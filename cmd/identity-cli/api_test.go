package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTokenResponse(t *testing.T) {
	access, refresh, ttl, err := tokenResponse(map[string]any{"access_token": "at", "refresh_token": "rt", "expires_in": float64(300)})
	if err != nil || access != "at" || refresh != "rt" || ttl != 5*time.Minute {
		t.Fatalf("valid response: %q %q %v %v", access, refresh, ttl, err)
	}
	for _, m := range []map[string]any{
		nil,
		{},
		{"access_token": 7, "expires_in": float64(300)},
		{"access_token": "at"},
		{"access_token": "at", "expires_in": "300"},
		{"access_token": "at", "expires_in": float64(-1)},
		{"access_token": "", "expires_in": float64(300)},
	} {
		if _, _, _, err := tokenResponse(m); !errors.Is(err, errTokenResponse) {
			t.Errorf("%v: %v, want errTokenResponse", m, err)
		}
	}
}

func useTempConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("AppData", dir)
}

// TestRefreshUnexpectedTokenShape: a token endpoint that answers 200 with an
// unexpected body yields an error instead of a panic, and the stored
// credentials are left alone.
func TestRefreshUnexpectedTokenShape(t *testing.T) {
	useTempConfigDir(t)
	var body any = map[string]any{"access_token": 42}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()
	if err := saveCreds(&credentials{URL: srv.URL, Realm: "main", Audience: "admin", AccessToken: "old", RefreshToken: "rt",
		Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	c, err := client("main", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Token(context.Background()); !errors.Is(err, errTokenResponse) {
		t.Fatalf("refresh with a malformed response: %v", err)
	}
	body = map[string]any{"access_token": "new", "expires_in": float64(60)}
	if tok, err := c.Token(context.Background()); err != nil || tok != "new" {
		t.Fatalf("refresh: %q %v", tok, err)
	}
	cr, err := loadCreds("main", "admin")
	if err != nil || cr.AccessToken != "new" || cr.RefreshToken != "rt" {
		t.Fatalf("stored credentials: %+v %v", cr, err)
	}
}

// TestRefreshSaveFailureWarns: when the refreshed credentials cannot be
// stored, the command still gets its token but a warning says so (the stored
// refresh token may already be spent).
func TestRefreshSaveFailureWarns(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions that apply to the current user")
	}
	useTempConfigDir(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at-fresh-7f3a", "refresh_token": "rt-fresh-9c1d", "expires_in": float64(60)})
	}))
	defer srv.Close()
	if err := saveCreds(&credentials{URL: srv.URL, Realm: "main", Audience: "admin", AccessToken: "old", RefreshToken: "rt",
		Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(credPath("main", "admin"))
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var buf bytes.Buffer
	prev := warnings
	warnings = &buf
	t.Cleanup(func() { warnings = prev })
	c, err := client("main", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := c.Token(context.Background()); err != nil || tok != "at-fresh-7f3a" {
		t.Fatalf("refresh: %q %v", tok, err)
	}
	if !strings.Contains(buf.String(), "could not be saved") || !strings.Contains(buf.String(), credPath("main", "admin")) {
		t.Fatalf("no warning about the unsaved credentials: %q", buf.String())
	}
	if strings.Contains(buf.String(), "fresh-") {
		t.Fatalf("warning contains token material: %q", buf.String())
	}
	if cr, err := loadCreds("main", "admin"); err != nil || cr.RefreshToken != "rt" {
		t.Fatalf("stored credentials changed: %+v %v", cr, err)
	}
}

// TestHeadlessUnexpectedStart: a malformed transaction response is an error,
// not a panic.
func TestHeadlessUnexpectedStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"transaction_id":"tx_1"}`))
	}))
	defer srv.Close()
	if _, err := headless(srv.URL, "main", "res", "proudauth:admin"); err == nil {
		t.Fatal("headless accepted a response without a continuation token or state")
	}
}

func TestWritePrivateFileTightensExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	p := filepath.Join(t.TempDir(), "secrets.json")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(p, []byte(`{"web":"secret"}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(p); string(b) != `{"web":"secret"}` {
		t.Fatalf("content %q", b)
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	if err := writePrivateFile(filepath.Join(t.TempDir(), "missing", "x.json"), nil); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
}
