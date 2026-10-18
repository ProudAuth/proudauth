package credential

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestValidateImportedHash(t *testing.T) {
	h := &Hasher{Params: Params{Memory: 19456, Time: 2, Threads: 1}, MaxBytes: 1024}
	good, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	for v, ok := range map[string]bool{
		"":   true,
		good: true,
		"$argon2id$v=19$m=4194304,t=3,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g":   false, // memory above ceiling
		"$argon2id$v=19$m=65536,t=99,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g":    false, // time above ceiling
		"$argon2id$v=19$m=65536,t=3,p=300$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g":   false, // threads overflow
		"$argon2id$v=19$m=65536,t=3,p=1,k=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g": false, // local pepper reference
		"$2a$10$bcrypt": false,
		"$legacy-sha256$c2FsdHNhbHRzYWx0$" + "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU": true,
		"$legacy-sha256$c2FsdA$AAAA": false,
	} {
		if err := ValidateImportedHash(v); (err == nil) != ok {
			t.Errorf("%q: err=%v, want ok=%v", v, err, ok)
		}
	}
}

// TestLegacyHashDeadline covers CRED-004: legacy verifiers verify only until
// the configured end of the migration.
func TestLegacyHashDeadline(t *testing.T) {
	salt := []byte("saltsaltsalt")
	sum := sha256.Sum256(append(append([]byte{}, salt...), []byte("old password 1")...))
	legacy := "$legacy-sha256$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(sum[:])
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	h := &Hasher{Params: Params{Time: 1, Memory: 1024, Threads: 1}, MaxBytes: 1024, Now: func() time.Time { return now }}
	if _, err := h.Verify(legacy, "old password 1"); err != nil {
		t.Fatalf("legacy verifier without a deadline: %v", err)
	}
	h.LegacyUntil = now.Add(time.Hour)
	if _, err := h.Verify(legacy, "old password 1"); err != nil {
		t.Fatalf("legacy verifier before the deadline: %v", err)
	}
	h.LegacyUntil = now
	if _, err := h.Verify(legacy, "old password 1"); !errors.Is(err, ErrLegacyRetired) {
		t.Fatalf("legacy verifier after the deadline: %v", err)
	}
}

// TestLegacySHA256TypedPassword covers MIG-006 and CRED-003 for imported
// salted SHA-256 verifiers: the source hashed the password as typed, so a
// password that NFKC normalization changes (full-width letters and a
// ligature, a decomposed accent) verifies against sha256(salt || typed) and
// is rehashed, as the other imported formats are; a verifier computed over
// the NFKC form keeps verifying.
func TestLegacySHA256TypedPassword(t *testing.T) {
	h := &Hasher{Params: Params{Time: 1, Memory: 1024, Threads: 1}, MaxBytes: 1024}
	legacy := func(pw string) string {
		salt := []byte("saltsaltsalt")
		sum := sha256.Sum256(append(append([]byte{}, salt...), []byte(pw)...))
		return "$legacy-sha256$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	for name, typed := range map[string]string{
		"full-width letters and a ligature": "ｆｕｌｌｗｉｄｔｈ ﬁle passphrase 2026",
		"decomposed accent (NFD)":           "café au lait passphrase 2026",
	} {
		n, err := h.Normalize(typed)
		if err != nil || n == typed {
			t.Fatalf("%s: the test password must change under NFKC (%v)", name, err)
		}
		if rehash, err := h.Verify(legacy(typed), typed); err != nil || !rehash {
			t.Fatalf("%s: verifier over the typed password: %v rehash=%v", name, err, rehash)
		}
		if rehash, err := h.Verify(legacy(n), typed); err != nil || !rehash {
			t.Fatalf("%s: verifier over the NFKC form: %v rehash=%v", name, err, rehash)
		}
		if _, err := h.Verify(legacy(typed), n); !errors.Is(err, ErrMismatch) {
			t.Fatalf("%s: the NFKC form matched a verifier over the typed password: %v", name, err)
		}
		if _, err := h.Verify(legacy(typed), typed+"!"); !errors.Is(err, ErrMismatch) {
			t.Fatalf("%s: a wrong password verified: %v", name, err)
		}
	}
}
