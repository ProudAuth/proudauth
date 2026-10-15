package application

import (
	"fmt"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"strings"
)

// Claim mappings (APP-011). A client's id_token_claims and access_token_claims
// hold static values or attribute mappings of the form
//
//	{"$attr": "profile.department", "transform": "lower", "default": "none"}
//
// A mapping reads one approved attribute: the user's given_name, family_name,
// display_name, locale or zoneinfo ("user.*"), or a custom profile attribute
// the realm marked claimable ("profile.*"). transform is "", "lower" or
// "upper". Expressions cannot compute, concatenate or reach other data, and
// mapped values never replace reserved or standard user claims.

// ClaimSource supplies attribute values to claim mappings.
type ClaimSource struct {
	User      map[string]string
	Profile   map[string]any
	Claimable map[string]bool
}

var userAttrs = map[string]bool{"given_name": true, "family_name": true, "display_name": true, "locale": true, "zoneinfo": true}

// validateClaimMap checks the shape of a client's claim map at registration.
func validateClaimMap(field string, m map[string]any) error {
	if len(m) > 20 {
		return fmt.Errorf("%s: at most 20 claims", field)
	}
	for k, v := range m {
		if len(k) > 64 {
			return fmt.Errorf("%s: claim names are at most 64 characters", field)
		}
		if IsStandardUserClaim(k) {
			return fmt.Errorf("%s.%s: standard user claims come from the account, not from mappings", field, k)
		}
		spec, ok := v.(map[string]any)
		if !ok {
			continue
		}
		path, _ := spec["$attr"].(string)
		if path == "" {
			return fmt.Errorf("%s.%s: objects must be attribute mappings with $attr", field, k)
		}
		for key := range spec {
			if key != "$attr" && key != "transform" && key != "default" {
				return fmt.Errorf("%s.%s: unsupported mapping member %s", field, k, key)
			}
		}
		if t, _ := spec["transform"].(string); t != "" && t != "lower" && t != "upper" {
			return fmt.Errorf("%s.%s: transform must be lower or upper", field, k)
		}
		if d, ok := spec["default"]; ok {
			if _, isStr := d.(string); !isStr {
				return fmt.Errorf("%s.%s: default must be a string", field, k)
			}
		}
		kind, name, _ := strings.Cut(path, ".")
		switch {
		case kind == "user" && userAttrs[name]:
		case kind == "profile" && name != "" && !strings.Contains(name, "."):
		default:
			return fmt.Errorf("%s.%s: $attr must be user.<given_name|family_name|display_name|locale|zoneinfo> or profile.<attribute>", field, k)
		}
	}
	return nil
}

// ResolveClaims renders a claim map for a subject: static values pass
// through, mappings read their attribute (omitted when absent and without a
// default, or when the profile attribute is not claimable).
func ResolveClaims(m map[string]any, src ClaimSource) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		spec, ok := v.(map[string]any)
		if !ok {
			out[k] = v
			continue
		}
		path, _ := spec["$attr"].(string)
		kind, name, _ := strings.Cut(path, ".")
		var val any
		switch kind {
		case "user":
			if s := src.User[name]; s != "" {
				val = s
			}
		case "profile":
			if src.Claimable[name] {
				if pv, ok := src.Profile[name]; ok {
					switch pv.(type) {
					case string, bool, float64, int, int64:
						val = pv
					}
				}
			}
		}
		if s, ok := val.(string); ok {
			if len(s) > 256 {
				s = canonical.Truncate(s, 256)
			}
			switch spec["transform"] {
			case "lower":
				s = strings.ToLower(s)
			case "upper":
				s = strings.ToUpper(s)
			}
			val = s
		}
		if val == nil {
			if d, ok := spec["default"].(string); ok {
				val = d
			}
		}
		if val != nil {
			out[k] = val
		}
	}
	return out
}

// HasMappings reports whether a claim map needs subject attributes.
func HasMappings(m map[string]any) bool {
	for _, v := range m {
		if _, ok := v.(map[string]any); ok {
			return true
		}
	}
	return false
}
