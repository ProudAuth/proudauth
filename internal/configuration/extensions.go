package configuration

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"regexp"
	"time"
)

// ExtensionsConfig is the operator's extension trust configuration (EXT-014).
type ExtensionsConfig struct {
	// PluginPublishers are the publisher keys whose signatures make a plugin
	// package installable. A package signed by any other key is refused;
	// there is no unsigned mode.
	PluginPublishers []PluginPublisherKey `yaml:"plugin_publishers"`
}

// PluginPublisherKey is one trusted Ed25519 publisher key.
type PluginPublisherKey struct {
	// KeyID is the key identifier packages name in signature.key_id.
	KeyID string `yaml:"key_id"`
	// Publisher is the publisher name a manifest must declare for this key.
	Publisher string `yaml:"publisher"`
	// PublicKey is the raw 32-byte Ed25519 public key, base64 (standard
	// alphabet). Public keys are not secrets.
	PublicKey string `yaml:"public_key"`
	// NotAfter optionally ends the key's validity (RFC 3339); packages are
	// verified against the time of upload and of installation.
	NotAfter string `yaml:"not_after"`
}

var publisherName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,62}$`)

// Ed25519 decodes the public key.
func (k PluginPublisherKey) Ed25519() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func (e ExtensionsConfig) validate() []string {
	var errs []string
	seen := map[string]bool{}
	for i, k := range e.PluginPublishers {
		if !publisherName.MatchString(k.KeyID) || seen[k.KeyID] {
			errs = append(errs, fmt.Sprintf("extensions.plugin_publishers[%d].key_id must be unique, lower-case and at most 63 characters", i))
		}
		seen[k.KeyID] = true
		if !publisherName.MatchString(k.Publisher) {
			errs = append(errs, fmt.Sprintf("extensions.plugin_publishers[%d].publisher must be lower-case and at most 63 characters", i))
		}
		if _, err := k.Ed25519(); err != nil {
			errs = append(errs, fmt.Sprintf("extensions.plugin_publishers[%d].public_key: %v", i, err))
		}
		if k.NotAfter != "" {
			if _, err := time.Parse(time.RFC3339, k.NotAfter); err != nil {
				errs = append(errs, fmt.Sprintf("extensions.plugin_publishers[%d].not_after must be an RFC 3339 time", i))
			}
		}
	}
	return errs
}
