package oauth

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/proudbase/proudauth/internal/session"
)

// Claims parameter profile (OIDC-008). The parameter is accepted and validated,
// but it never widens release: individual claims are released only when a
// granted scope already authorizes them (ID token and UserInfo alike), so a
// request cannot override protected or unconsented claims. The one effect beyond
// scope-driven release is assurance: an "acr" request (essential or not) adds
// its values to the transaction's assurance requirement, and an essential acr
// request that cannot be met fails instead of inventing evidence (OIDC-009).

var claimsParameterNames = map[string]bool{
	"sub": true, "name": true, "given_name": true, "family_name": true, "middle_name": true, "nickname": true, "preferred_username": true,
	"profile": true, "picture": true, "website": true, "email": true, "email_verified": true, "gender": true, "birthdate": true,
	"zoneinfo": true, "locale": true, "phone_number": true, "phone_number_verified": true, "address": true, "updated_at": true,
	"acr": true, "auth_time": true, "amr": true,
}

type claimRequest struct {
	Essential bool     `json:"essential"`
	Value     any      `json:"value"`
	Values    []string `json:"values"`
}

// parseClaimsParameter validates the claims request and returns any acr values
// it asks for.
func parseClaimsParameter(raw string) ([]string, *Error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 4096 {
		return nil, ErrInvalidRequest("claims parameter too large")
	}
	var doc map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	if err := dec.Decode(&doc); err != nil {
		return nil, ErrInvalidRequest("claims must be a JSON object")
	}
	var acr []string
	for member, body := range doc {
		if member != "userinfo" && member != "id_token" {
			return nil, ErrInvalidRequest("claims members are userinfo and id_token")
		}
		var reqs map[string]json.RawMessage
		if err := json.Unmarshal(body, &reqs); err != nil {
			return nil, ErrInvalidRequest("claims." + member + " must be an object")
		}
		for name, spec := range reqs {
			if !claimsParameterNames[name] {
				return nil, ErrInvalidRequest("unsupported claim " + name)
			}
			if string(spec) == "null" {
				continue
			}
			var cr claimRequest
			sd := json.NewDecoder(bytes.NewReader(spec))
			sd.DisallowUnknownFields()
			if err := sd.Decode(&cr); err != nil {
				return nil, ErrInvalidRequest("invalid request for claim " + name)
			}
			if name != "acr" {
				continue
			}
			vals := cr.Values
			if s, ok := cr.Value.(string); ok {
				vals = append(vals, s)
			}
			for _, v := range vals {
				if session.ACRRank(v) == 0 {
					if cr.Essential {
						return nil, &Error{Status: 400, Code: "unmet_authentication_requirements", Description: "essential acr " + v + " is not supported"}
					}
					continue
				}
				if !slices.Contains(acr, v) {
					acr = append(acr, v)
				}
			}
		}
	}
	return acr, nil
}

// requestedClaims returns the claim names a validated claims request asks for
// in one member ("id_token" or "userinfo"), and whether that member was
// present. Release stays bounded by scope: this only narrows (OIDC-008).
func requestedClaims(raw, member string) (map[string]bool, bool) {
	if raw == "" {
		return nil, false
	}
	var doc map[string]map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return nil, false
	}
	reqs, ok := doc[member]
	if !ok {
		return nil, false
	}
	out := map[string]bool{}
	for name := range reqs {
		out[name] = true
	}
	return out, true
}

// releaseFor narrows scope-authorized user claims to a claims request member
// when one was given. Protected claims (sub, verification flags with their
// values) always come from the user record, never from the request.
func releaseFor(claims map[string]any, raw, member string) map[string]any {
	want, present := requestedClaims(raw, member)
	if !present {
		return claims
	}
	out := map[string]any{}
	for k, v := range claims {
		if want[k] || (k == "email_verified" && want["email"]) || (k == "phone_number_verified" && want["phone_number"]) {
			out[k] = v
		}
	}
	return out
}
