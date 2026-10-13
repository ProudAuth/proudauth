package configuration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// TestPluginPublisherKeys covers extensions.plugin_publishers validation
// (EXT-014): keys must decode to Ed25519 public keys, IDs are unique.
func TestPluginPublisherKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := PluginPublisherKey{KeyID: "acme-2026", Publisher: "acme", PublicKey: base64.StdEncoding.EncodeToString(pub)}
	c := validDev()
	c.Extensions.PluginPublishers = []PluginPublisherKey{good}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	for name, k := range map[string]PluginPublisherKey{
		"short key":     {KeyID: "k", Publisher: "acme", PublicKey: base64.StdEncoding.EncodeToString(pub[:16])},
		"not base64":    {KeyID: "k", Publisher: "acme", PublicKey: "%%%"},
		"bad key id":    {KeyID: "Key ID", Publisher: "acme", PublicKey: good.PublicKey},
		"bad publisher": {KeyID: "k", Publisher: "", PublicKey: good.PublicKey},
		"bad not_after": {KeyID: "k", Publisher: "acme", PublicKey: good.PublicKey, NotAfter: "tomorrow"},
	} {
		c := validDev()
		c.Extensions.PluginPublishers = []PluginPublisherKey{k}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "extensions.plugin_publishers") {
			t.Errorf("%s: %v", name, err)
		}
	}
	c = validDev()
	c.Extensions.PluginPublishers = []PluginPublisherKey{good, good}
	if err := c.Validate(); err == nil {
		t.Error("duplicate key IDs accepted")
	}
}
