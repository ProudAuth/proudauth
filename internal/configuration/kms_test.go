package configuration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKMSUnwrap covers DEP-016: kms: references are unwrapped by the
// operator's command (here a stand-in that reverses its input), the wrapped
// file is never treated as the key, and without a command the reference
// fails instead of being used literally.
func TestKMSUnwrap(t *testing.T) {
	dir := t.TempDir()
	wrapped := filepath.Join(dir, "root.wrapped")
	if err := os.WriteFile(wrapped, []byte("WRAPPED:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"), 0o600); err != nil {
		t.Fatal(err)
	}
	ConfigureKMS(KMSConfig{})
	if _, err := ResolveSecret("kms:" + wrapped); err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("kms without a command: %v", err)
	}
	ConfigureKMS(KMSConfig{Command: []string{"sed", "s/^WRAPPED://"}})
	defer ConfigureKMS(KMSConfig{})
	got, err := ResolveSecret("kms:" + wrapped)
	if err != nil || got != "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" {
		t.Fatalf("unwrap: %q %v", got, err)
	}
	if _, err := DecodeKey(got); err != nil {
		t.Fatal(err)
	}
	if !IsSecretRef("kms:" + wrapped) {
		t.Fatal("kms: is a secret reference")
	}
	ConfigureKMS(KMSConfig{Command: []string{"false"}})
	if _, err := ResolveSecret("kms:" + wrapped); err == nil {
		t.Fatal("a failing provider must fail")
	}
	// A provider whose child keeps the output open cannot outlast the
	// timeout by much: the child holds stdout for 20 s, the timeout is 200 ms.
	ConfigureKMS(KMSConfig{Command: []string{"sh", "-c", "sleep 20 & sleep 20"}, Timeout: 200 * time.Millisecond})
	start := time.Now()
	if _, err := ResolveSecret("kms:" + wrapped); err == nil {
		t.Fatal("a stuck provider must fail")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("a child holding the output kept the resolution waiting %s", d)
	}
}
