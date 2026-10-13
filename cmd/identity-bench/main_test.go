package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCheckArgs: an empty --url value must not let the next flag become the
// URL and the remaining flags be dropped silently.
func TestCheckArgs(t *testing.T) {
	parse := func(args ...string) (*flag.FlagSet, string) {
		fs := flag.NewFlagSet("seed", flag.ContinueOnError)
		base := fs.String("url", "", "")
		fs.String("realm", "bench", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return fs, *base
	}
	if err := checkArgs(parse("--url", "https://id.example.test", "--realm", "bench")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--url", "--realm", "bench"},
		{"--realm", "bench"},
		{"--url", "https://id.example.test", "stray"},
		{"--url", "id.example.test"},
	} {
		if err := checkArgs(parse(args...)); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
}

func TestSeedFileIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	p := filepath.Join(t.TempDir(), "bench-seed.json")
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(p, []byte(`{"web_client":{"client_secret":"x"}}`)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
}
