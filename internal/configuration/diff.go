package configuration

import (
	"encoding/json"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Change is one configuration difference (DEP-020). Values are shown redacted:
// secrets appear only as references, never as literals.
type Change struct {
	Key string `json:"key"`
	Old string `json:"old"`
	New string `json:"new"`
	// Effect says when the change applies. Every file setting is read at
	// process start, so file changes take effect on restart; realm policy,
	// clients and other realm configuration change dynamically through the
	// administration API instead and are versioned and audited there.
	Effect string `json:"effect"`
	// SecurityBoundary marks changes that alter a trust or exposure boundary
	// and need a second reviewer before rollout.
	SecurityBoundary bool `json:"security_boundary"`
}

// securityPrefixes are configuration keys whose change moves a security
// boundary: keys and secrets, token and session lifetimes, network exposure,
// egress and trusted roots, impersonation, the SAML profiles (switching them
// on, message and clock-skew bounds, signing-key publication), the directory
// module (switching it on, its egress and trusted roots) and the deployment
// mode.
var securityPrefixes = []string{
	"mode", "keys.", "sessions.", "tokens.", "security.", "impersonation.", "server.trusted_proxies", "server.public_origin",
	"server.internal_listen", "server.metrics_token", "server.host_policy", "server.public_listen", "server.tls_cert_file", "server.tls_key_file",
	// Mutual TLS (TOK-019, MCH-014): where client certificates are accepted
	// and from which header a proxy may assert one.
	"server.mtls_listen", "server.mtls_origin", "server.client_cert_header",
	"federation.allow_private_network", "federation.ca_file", "saml.",
	"directory.enabled", "directory.allow_private_network", "directory.egress_allowlist", "directory.ca_file",
	"federation.egress_allowlist", "delivery.allow_private_webhooks", "delivery.egress_allowlist", "delivery.email.allowed_sender_domains",
	"delivery.email.events_secret", "delivery.sms.webhook_secret", "storage.database_url", "storage.migration_database_url",
	"storage.runtime_role", "observability.metrics_enabled", "observability.otlp_endpoint", "workers.metrics_listen",
	"privacy.", "limits.", "webauthn.",
}

// Diff compares two configurations key by key.
func Diff(oldCfg, newCfg Config) ([]Change, error) {
	a, err := flatten(oldCfg.Redacted())
	if err != nil {
		return nil, err
	}
	b, err := flatten(newCfg.Redacted())
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []Change
	for k := range keys {
		if a[k] == b[k] {
			continue
		}
		c := Change{Key: k, Old: a[k], New: b[k], Effect: "restart"}
		for _, p := range securityPrefixes {
			if k == strings.TrimSuffix(p, ".") || strings.HasPrefix(k, p) {
				c.SecurityBoundary = true
			}
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(x, y Change) int { return strings.Compare(x.Key, y.Key) })
	return out, nil
}

func flatten(c Config) (map[string]string, error) {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				key := k
				if prefix != "" {
					key = prefix + "." + k
				}
				walk(key, child)
			}
		case string:
			out[prefix] = t
		default:
			b, _ := json.Marshal(t)
			out[prefix] = string(b)
		}
	}
	walk("", tree)
	return out, nil
}
