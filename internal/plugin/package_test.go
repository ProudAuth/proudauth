package plugin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

func signed(t *testing.T, priv ed25519.PrivateKey, keyID string, manifest map[string]any, payload []byte) Package {
	t.Helper()
	sum := sha256.Sum256(payload)
	if _, ok := manifest["payload_sha256"]; !ok {
		manifest["payload_sha256"] = hex.EncodeToString(sum[:])
	}
	mb, _ := json.Marshal(manifest)
	sig := ed25519.Sign(priv, append([]byte(SigningContext), mb...))
	return Package{Manifest: base64.StdEncoding.EncodeToString(mb), Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: Signature{KeyID: keyID, Algorithm: "Ed25519", Value: base64.StdEncoding.EncodeToString(sig)}}
}

// TestVerify covers plugin package signatures and strict decoding. A payload
// member that would carry code ("scripts") is refused: a plugin configures
// only what the administration API can and never runs logic inside the
// server (EXT-013; no embedded execution to sandbox, ADR 0021).
func TestVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	trusted := []configuration.PluginPublisherKey{{KeyID: "k1", Publisher: "acme", PublicKey: base64.StdEncoding.EncodeToString(pub)}}
	now := time.Now()
	payload := []byte(`{"hooks":[{"name":"h","kind":"profile.validation","url":"https://hooks.example.com/p"}]}`)
	manifest := func() map[string]any {
		return map[string]any{"manifest_version": 1, "name": "acme-hooks", "version": "1.0.0", "publisher": "acme", "permissions": []string{"realm.hooks.write"}}
	}
	v, err := Verify(signed(t, priv, "k1", manifest(), payload), trusted, now)
	if err != nil {
		t.Fatalf("valid package: %v", err)
	}
	if v.Manifest.Name != "acme-hooks" || len(v.Payload.Hooks) != 1 || len(v.Digest) != 64 {
		t.Fatalf("verified: %+v", v)
	}
	forbidden := func(name string, pkg Package, trusted []configuration.PluginPublisherKey) {
		t.Helper()
		if _, err := Verify(pkg, trusted, now); err == nil || !problem.Is(err, problem.ErrForbidden) {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := func(name string, pkg Package) {
		t.Helper()
		if _, err := Verify(pkg, trusted, now); err == nil || !problem.Is(err, problem.ErrValidation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	forbidden("untrusted key", signed(t, otherPriv, "k1", manifest(), payload), trusted)
	forbidden("unknown key id", signed(t, priv, "k2", manifest(), payload), trusted)
	tampered := signed(t, priv, "k1", manifest(), payload)
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte(`{"hooks":[]}`))
	forbidden("payload swapped", tampered, trusted)
	m := manifest()
	m["publisher"] = "mallory"
	forbidden("publisher mismatch", signed(t, priv, "k1", m, payload), trusted)
	expired := []configuration.PluginPublisherKey{trusted[0]}
	expired[0].NotAfter = now.Add(-time.Hour).Format(time.RFC3339)
	forbidden("expired key", signed(t, priv, "k1", manifest(), payload), expired)
	// A signature over a different context never verifies.
	mb, _ := json.Marshal(func() map[string]any { x := manifest(); x["payload_sha256"] = hexSum(payload); return x }())
	raw := signed(t, priv, "k1", manifest(), payload)
	raw.Signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, mb))
	forbidden("no domain separation", raw, trusted)

	m = manifest()
	m["manifest_version"] = 2
	invalid("future manifest", signed(t, priv, "k1", m, payload))
	m = manifest()
	m["version"] = "1.0"
	invalid("bad semver", signed(t, priv, "k1", m, payload))
	m = manifest()
	m["requires"] = map[string]any{"hook_contract": []int{9}}
	invalid("unsupported contract", signed(t, priv, "k1", m, payload))
	m = manifest()
	m["requires"] = map[string]any{"teleport": []int{1}}
	invalid("unknown contract", signed(t, priv, "k1", m, payload))
	m = manifest()
	m["permissions"] = []string{"realm.godmode"}
	invalid("unknown permission", signed(t, priv, "k1", m, payload))
	m = manifest()
	m["surprise"] = true
	invalid("unknown manifest member", signed(t, priv, "k1", m, payload))
	invalid("empty payload", signed(t, priv, "k1", manifest(), []byte(`{}`)))
	invalid("unknown payload member", signed(t, priv, "k1", manifest(), []byte(`{"scripts":["rm -rf /"]}`)))
	m = manifest()
	m["dependencies"] = []any{map[string]any{"name": "acme-hooks", "min_version": "1.0.0"}}
	invalid("self dependency", signed(t, priv, "k1", m, payload))
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestSemver(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"1.0.0", "1.0.1", true}, {"1.9.0", "1.10.0", true}, {"2.0.0", "1.99.99", false}, {"1.0.0", "1.0.0", false}} {
		a, ok1 := ParseSemver(c.a)
		b, ok2 := ParseSemver(c.b)
		if !ok1 || !ok2 || a.Less(b) != c.less {
			t.Errorf("%s < %s: %v", c.a, c.b, a.Less(b))
		}
	}
	for _, bad := range []string{"1.0", "01.0.0", "1.0.0-rc1", "v1.0.0", ""} {
		if _, ok := ParseSemver(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
