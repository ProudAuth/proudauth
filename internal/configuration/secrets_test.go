package configuration

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultResolver(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "tok-1" || r.URL.Path != "/v1/secret/data/proudauth" {
			w.WriteHeader(403)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"root_key":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}}`))
	}))
	defer srv.Close()
	t.Setenv("VAULT_ADDR", srv.URL) // httptest listens on 127.0.0.1, so plain http is allowed
	t.Setenv("VAULT_TOKEN", "tok-1")
	v, err := ResolveSecret("vault:secret/data/proudauth#root_key")
	if err != nil || len(v) != 64 {
		t.Fatalf("vault resolve: %q %v", v, err)
	}
	if !IsSecretRef("vault:secret/data/proudauth#root_key") {
		t.Fatal("vault: is a secret reference")
	}
	if _, err := ResolveSecret("vault:secret/data/proudauth#missing"); err == nil {
		t.Fatal("missing field resolved")
	}
	t.Setenv("VAULT_ADDR", "http://vault.example.test:8200")
	if _, err := ResolveSecret("vault:secret/data/proudauth#root_key"); err == nil {
		t.Fatal("plain-http Vault address accepted for a non-loopback host")
	}
}

func TestCredentialResolver(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root_key"), []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if v, err := ResolveSecret("cred:root_key"); err != nil || v != "secret-value" {
		t.Fatalf("cred resolve: %q %v", v, err)
	}
	if _, err := ResolveSecret("cred:../etc/passwd"); err == nil {
		t.Fatal("path traversal accepted")
	}
}
