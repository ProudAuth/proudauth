package keys

import (
	"bytes"
	"testing"

	"github.com/proudbase/proudauth/internal/platform/secret"
)

// TestEncryptRoundTripAndBinding covers SEC-010: recoverable secrets are
// sealed with authenticated encryption bound to their owning row, carry their
// key version, are rejected when tampered with, and the keys for data
// encryption, signing-key wrapping, webhook secrets, OTP verifiers and the
// password pepper are separate.
func TestEncryptRoundTripAndBinding(t *testing.T) {
	k := NewRandom()
	ct, v, err := k.Encrypt(PurposeData, []byte("totp-seed"), []byte("totp:usr_1"))
	if err != nil || v != 1 {
		t.Fatal(err)
	}
	pt, err := k.Decrypt(PurposeData, ct, []byte("totp:usr_1"))
	if err != nil || !bytes.Equal(pt, []byte("totp-seed")) {
		t.Fatalf("roundtrip: %v", err)
	}
	if _, err := k.Decrypt(PurposeData, ct, []byte("totp:usr_2")); err == nil {
		t.Fatal("ciphertext must be bound to its associated data")
	}
	if _, err := k.Decrypt(PurposeWebhook, ct, []byte("totp:usr_1")); err == nil {
		t.Fatal("purpose keys must be separated")
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 1
	if _, err := k.Decrypt(PurposeData, tampered, []byte("totp:usr_1")); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
	purposes := []Purpose{PurposeData, PurposeSigningWrap, PurposeWebhook, PurposeOTP, PurposePepper}
	for _, p := range purposes {
		sealed, _, err := k.Encrypt(p, []byte("secret"), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range purposes {
			if _, err := k.Decrypt(other, sealed, nil); (err == nil) != (other == p) {
				t.Fatalf("%s ciphertext opened with the %s key: %v", p, other, err)
			}
		}
		mac, ver := k.MAC(p, "x")
		for _, other := range purposes {
			if other != p && k.VerifyMAC(other, ver, mac, "x") {
				t.Fatalf("%s verifier accepted by the %s key", p, other)
			}
		}
	}
}

// TestRotationKeepsOldVersionsReadable covers SEC-010's key-versioned
// envelopes: rotation keeps older ciphertext readable and new encryptions use
// the active version.
func TestRotationKeepsOldVersionsReadable(t *testing.T) {
	r1, r2 := secret.Random(32), secret.Random(32)
	old, _ := New(map[uint32][]byte{1: r1}, 1)
	ct, _, _ := old.Encrypt(PurposeData, []byte("x"), nil)
	rotated, _ := New(map[uint32][]byte{1: r1, 2: r2}, 2)
	if pt, err := rotated.Decrypt(PurposeData, ct, nil); err != nil || string(pt) != "x" {
		t.Fatal("old ciphertext must stay readable after rotation")
	}
	_, v, _ := rotated.Encrypt(PurposeData, []byte("y"), nil)
	if v != 2 {
		t.Fatalf("new encryptions use active version, got %d", v)
	}
}

func TestMACIsKeyedAndVersioned(t *testing.T) {
	k := NewRandom()
	m, v := k.MAC(PurposeOTP, "chl_1", "123456")
	if !k.VerifyMAC(PurposeOTP, v, m, "chl_1", "123456") {
		t.Fatal("verify")
	}
	if k.VerifyMAC(PurposeOTP, v, m, "chl_1", "123457") {
		t.Fatal("wrong code accepted")
	}
	if k.VerifyMAC(PurposeOTP, v, m, "chl_2", "123456") {
		t.Fatal("verifier must bind challenge id")
	}
	other := NewRandom()
	if other.VerifyMAC(PurposeOTP, v, m, "chl_1", "123456") {
		t.Fatal("a different key must not verify")
	}
}
