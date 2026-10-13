package credential

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/proudbase/proudauth/internal/configuration"
)

// TestOfflineBreachedPasswordScreening covers SEC-013: breached passwords are
// screened against the embedded list plus an operator-supplied local file,
// case-insensitively, with no network lookup involved; a missing file is a
// configuration error, never a silent pass.
func TestOfflineBreachedPasswordScreening(t *testing.T) {
	d := configuration.Defaults().Security.Password
	const leaked = "Correct Horse Battery Staple 2026"
	base, err := NewPolicy(d.MinLength, d.MaxLength, d.MaxBytes, "")
	if err != nil {
		t.Fatal(err)
	}
	if v := base.Check(leaked, 0); v != nil {
		t.Fatalf("baseline rejected the candidate: %s", v.Code)
	}
	if v := base.Check("passwordpassword", 0); v == nil || v.Code != "compromised" {
		t.Fatal("embedded breached-password list not applied")
	}

	file := filepath.Join(t.TempDir(), "breached.txt")
	if err := os.WriteFile(file, []byte("correct horse battery staple 2026\n\nanother leaked passphrase\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	screened, err := NewPolicy(d.MinLength, d.MaxLength, d.MaxBytes, file)
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{leaked, "ANOTHER LEAKED PASSPHRASE", "passwordpassword"} {
		if v := screened.Check(pw, 0); v == nil || v.Code != "compromised" {
			t.Errorf("breached password %q accepted by the offline screen", pw)
		}
	}
	if v := screened.Check("a perfectly fine passphrase", 0); v != nil {
		t.Fatalf("unlisted password rejected: %s", v.Code)
	}
	if _, err := NewPolicy(d.MinLength, d.MaxLength, d.MaxBytes, filepath.Join(t.TempDir(), "missing.txt")); err == nil {
		t.Fatal("a missing screening file must fail configuration")
	}
}
