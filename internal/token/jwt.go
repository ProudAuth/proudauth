package token

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// JOSE "typ" values. Each artifact has its own type so one can never be accepted as
// another (§14.1, JWT-BCP). JWT-secured authorization responses (JARM) and
// signed UserInfo responses are signed with the realm key like ID tokens, so
// they carry their own types too: neither can pass as an ID token hint at
// logout (decision 15).
const (
	TypeAccess   = "at+jwt"
	TypeID       = "JWT"
	TypeLogout   = "logout+jwt"
	TypeAudit    = "audit-batch+jwt"
	TypeJARM     = "oauth-authz-resp+jwt"
	TypeUserInfo = "userinfo+jwt"
)

// AuthorizationResponseMembers are the members of an authorization response
// (RFC 6749 §4.1.2, §4.1.2.1) that a JARM response carries. An ID token never
// carries them: IDClaims leaves them out even when a client's claim mapping
// names them, and an ID token hint that has one is refused.
var AuthorizationResponseMembers = []string{"code", "error", "state"}

// Token kinds (product-defined token_kind claim).
const (
	KindUserAccess          = "user_access"
	KindServiceAccess       = "service_access"
	KindImpersonationAccess = "impersonation_access"
	KindExchangeAccess      = "exchange_access"
)

// Actor is the RFC 8693 "act" claim.
type Actor struct {
	Issuer  string `json:"iss,omitempty"`
	Subject string `json:"sub"`
	// Agent marks an autonomous agent acting as a delegate (MCH-017).
	Agent bool   `json:"agent,omitempty"`
	Act   *Actor `json:"act,omitempty"`
}

// Depth returns the delegation chain depth.
func (a *Actor) Depth() int {
	n := 0
	for x := a; x != nil; x = x.Act {
		n++
	}
	return n
}

// MaxAuditChain bounds the delegation chain recorded in one audit event.
const MaxAuditChain = 16

// AuditChain returns the delegation chain as audit metadata, outermost
// (current) actor first, so the real actors behind an exchanged or agent
// token are preserved next to its effective subject (AUD-005). Each entry
// names the actor's subject and issuer and marks agents (MCH-017). At most
// MaxAuditChain entries are returned; truncated reports a longer chain.
func (a *Actor) AuditChain() (chain []map[string]any, truncated bool) {
	for x := a; x != nil; x = x.Act {
		if len(chain) == MaxAuditChain {
			return chain, true
		}
		e := map[string]any{"sub": x.Subject}
		if x.Issuer != "" {
			e["iss"] = x.Issuer
		}
		if x.Agent {
			e["agent"] = true
		}
		chain = append(chain, e)
	}
	return chain, false
}

// ActorFrom reads an "act" claim as introspection returns it: an *Actor
// for a JWT, a decoded JSON object for an opaque token. Anything else is nil.
func ActorFrom(v any) *Actor {
	switch x := v.(type) {
	case *Actor:
		return x
	case Actor:
		return &x
	case map[string]any:
		b, err := json.Marshal(x)
		if err != nil {
			return nil
		}
		var a Actor
		if json.Unmarshal(b, &a) != nil || a.Subject == "" {
			return nil
		}
		return &a
	}
	return nil
}

// Confirmation is the RFC 7800/9449 "cnf" claim.
type Confirmation struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// AccessClaims is the JWT access-token profile (RFC 9068 + product claims, §14.3).
type AccessClaims struct {
	Issuer       string        `json:"iss"`
	Subject      string        `json:"sub"`
	Audience     jwt.Audience  `json:"aud"`
	ClientID     string        `json:"client_id"`
	IssuedAt     int64         `json:"iat"`
	NotBefore    int64         `json:"nbf,omitempty"`
	Expiry       int64         `json:"exp"`
	JTI          string        `json:"jti"`
	SessionID    string        `json:"sid,omitempty"`
	Scope        string        `json:"scope,omitempty"`
	OrgID        string        `json:"org_id,omitempty"`
	ProjectID    string        `json:"project_id,omitempty"`
	TokenKind    string        `json:"token_kind"`
	AuthzVersion int64         `json:"authz_version,omitempty"`
	AuthTime     int64         `json:"auth_time,omitempty"`
	ACR          string        `json:"acr,omitempty"`
	AMR          []string      `json:"amr,omitempty"`
	Act          *Actor        `json:"act,omitempty"`
	Cnf          *Confirmation `json:"cnf,omitempty"`
	// Agent marks a token whose subject is an autonomous agent's service
	// principal (MCH-017), so resource servers can apply their own rules.
	Agent   bool           `json:"agent,omitempty"`
	GrantID string         `json:"grant_id,omitempty"`
	Extra   map[string]any `json:"-"`
}

// MarshalJSON flattens Extra claims without allowing them to override reserved claims (TOK-015).
func (c AccessClaims) MarshalJSON() ([]byte, error) {
	type plain AccessClaims
	b, err := json.Marshal(plain(c))
	if err != nil || len(c.Extra) == 0 {
		return b, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	for k, v := range c.Extra {
		if ReservedClaims[k] {
			continue
		}
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

// Scopes splits the scope claim.
func (c *AccessClaims) Scopes() []string { return strings.Fields(c.Scope) }

// HasScope reports whether the token carries s.
func (c *AccessClaims) HasScope(s string) bool {
	for _, x := range c.Scopes() {
		if x == s {
			return true
		}
	}
	return false
}

// IDClaims is the OIDC ID-token profile (OIDC-003).
type IDClaims struct {
	Issuer    string         `json:"iss"`
	Subject   string         `json:"sub"`
	Audience  jwt.Audience   `json:"aud"`
	Expiry    int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	AuthTime  int64          `json:"auth_time,omitempty"`
	Nonce     string         `json:"nonce,omitempty"`
	ACR       string         `json:"acr,omitempty"`
	AMR       []string       `json:"amr,omitempty"`
	AZP       string         `json:"azp,omitempty"`
	SessionID string         `json:"sid,omitempty"`
	AtHash    string         `json:"at_hash,omitempty"`
	CHash     string         `json:"c_hash,omitempty"`
	OrgID     string         `json:"org_id,omitempty"`
	Claims    map[string]any `json:"-"`
}

// MarshalJSON merges released user claims without overriding reserved claims.
func (c IDClaims) MarshalJSON() ([]byte, error) {
	type plain IDClaims
	b, err := json.Marshal(plain(c))
	if err != nil || len(c.Claims) == 0 {
		return b, err
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for k, v := range c.Claims {
		if ReservedClaims[k] || slices.Contains(AuthorizationResponseMembers, k) {
			continue
		}
		m[k] = v
	}
	return json.Marshal(m)
}

// ReservedClaims cannot be set by tenant claim mappings or hooks (TOK-015, EXT-011).
var ReservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	"client_id": true, "scope": true, "token_kind": true, "act": true, "may_act": true, "cnf": true,
	"sid": true, "grant_id": true, "org_id": true, "auth_time": true, "acr": true, "amr": true, "azp": true,
	"nonce": true, "at_hash": true, "c_hash": true, "authz_version": true, "events": true,
	"impersonation_grant_id": true, "support_mode": true, "project_id": true, "typ": true, "agent": true,
}

// Signer mints signed JWTs with the realm's active key.
type Signer struct {
	Keys *KeyManager
	// OnFailure, when set, observes key-provider and signing failures
	// (OPS-002); reason is a bounded label.
	OnFailure func(reason string)
}

func (s *Signer) fail(reason string, err error) error {
	if s.OnFailure != nil {
		s.OnFailure(reason)
	}
	return err
}

// Sign signs claims with the active key and the given JOSE typ.
func (s *Signer) Sign(ctx context.Context, realmID, typ string, claims any) (string, error) {
	key, err := s.Keys.Active(ctx, realmID)
	if err != nil {
		if errors.Is(err, ErrNoActiveKey) && !errors.Is(err, ErrKeyUnavailable) {
			return "", s.fail("no_active_key", err)
		}
		return "", s.fail("key_unavailable", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.SignatureAlgorithm(key.Algorithm),
		Key:       jose.JSONWebKey{Key: key.Private, KeyID: key.KID, Algorithm: key.Algorithm},
	}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", s.fail("signer_error", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", s.fail("sign_error", err)
	}
	return out, nil
}

// ActiveAlgorithm returns the active key algorithm (for at_hash computation).
func (s *Signer) ActiveAlgorithm(ctx context.Context, realmID string) (string, error) {
	k, err := s.Keys.Active(ctx, realmID)
	if err != nil {
		return "", err
	}
	return k.Algorithm, nil
}

// HalfHash computes at_hash / c_hash for the signing algorithm (OIDC Core §3.1.3.6).
func HalfHash(alg, value string) string {
	var h hash.Hash
	switch alg {
	case "RS384", "ES384", "PS384":
		h = sha512.New384()
	case "RS512", "ES512", "PS512", "EdDSA":
		h = sha512.New()
	default:
		h = sha256.New()
	}
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// Verification errors are deliberately coarse for callers; details go to logs.
var (
	ErrMalformed      = errors.New("token: malformed")
	ErrWrongType      = errors.New("token: wrong token type")
	ErrAlgorithm      = errors.New("token: algorithm not allowed")
	ErrUnknownKey     = errors.New("token: unknown signing key")
	ErrSignature      = errors.New("token: signature invalid")
	ErrIssuer         = errors.New("token: issuer mismatch")
	ErrAudience       = errors.New("token: audience mismatch")
	ErrExpired        = errors.New("token: expired")
	ErrNotYetValid    = errors.New("token: not yet valid")
	ErrIssuedInFuture = errors.New("token: issued in the future")
	ErrTooLarge       = errors.New("token: too large")
	ErrDuplicateClaim = errors.New("token: duplicate JSON member")
)

// Verifier validates access tokens presented to the identity provider's own APIs
// using the §14.4 algorithm. Keys are resolved only from the realm's trusted set; no
// URL in a token is ever fetched.
type Verifier struct {
	Keys       *KeyManager
	Algorithms []jose.SignatureAlgorithm
	ClockSkew  time.Duration
	MaxBytes   int
	Now        func() time.Time
}

// VerifyAccess verifies a JWT access token for (issuer, audience) of realmID.
func (v *Verifier) VerifyAccess(ctx context.Context, realmID, issuer, audience, raw string) (*AccessClaims, error) {
	var c AccessClaims
	if err := v.verify(ctx, realmID, raw, TypeAccess, &c); err != nil {
		return nil, err
	}
	if c.Issuer != issuer {
		return nil, ErrIssuer
	}
	if len(c.Audience) != 1 || c.Audience[0] != audience {
		return nil, ErrAudience
	}
	if c.TokenKind == "" || c.Subject == "" || c.ClientID == "" || c.JTI == "" {
		return nil, ErrMalformed
	}
	if err := v.checkTimes(c.IssuedAt, c.NotBefore, c.Expiry); err != nil {
		return nil, err
	}
	return &c, nil
}

// VerifyIDTokenHint validates an ID token used as id_token_hint at logout: signature,
// issuer and type must be valid and the claims must have the shape of an ID token
// (IDTokenShaped); expiry is not enforced (OIDC RP-initiated logout).
func (v *Verifier) VerifyIDTokenHint(ctx context.Context, realmID, issuer, raw string) (*IDClaims, error) {
	var c IDClaims
	var members map[string]json.RawMessage
	if err := v.verify(ctx, realmID, raw, TypeID, &c, &members); err != nil {
		return nil, err
	}
	if c.Issuer != issuer {
		return nil, ErrIssuer
	}
	if !IDTokenShaped(&c, members) {
		return nil, ErrWrongType
	}
	return &c, nil
}

// IDTokenShaped reports whether verified claims have the shape of an ID token
// (OIDC Core §2): a subject, an audience, exp and iat, and none of the
// AuthorizationResponseMembers. The realm key signs other JWTs too; tokens
// issued before JARM and signed UserInfo had their own typ (JWT, like ID
// tokens) fail here: a JARM response has no sub and no iat and carries code
// or error, a signed UserInfo response has no exp or iat.
func IDTokenShaped(c *IDClaims, members map[string]json.RawMessage) bool {
	if c.Subject == "" || len(c.Audience) == 0 || c.Audience[0] == "" || c.Expiry == 0 || c.IssuedAt == 0 {
		return false
	}
	for _, m := range AuthorizationResponseMembers {
		if _, ok := members[m]; ok {
			return false
		}
	}
	return true
}

func (v *Verifier) checkTimes(iat, nbf, exp int64) error {
	now := v.Now()
	skew := v.ClockSkew
	if exp == 0 || now.After(time.Unix(exp, 0).Add(skew)) {
		return ErrExpired
	}
	if nbf != 0 && now.Add(skew).Before(time.Unix(nbf, 0)) {
		return ErrNotYetValid
	}
	if iat != 0 && time.Unix(iat, 0).After(now.Add(skew)) {
		return ErrIssuedInFuture
	}
	return nil
}

func (v *Verifier) verify(ctx context.Context, realmID, raw, expectedTyp string, out ...any) error {
	max := v.MaxBytes
	if max == 0 {
		max = 8192
	}
	if len(raw) > max {
		return ErrTooLarge
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ErrMalformed
	}
	for _, p := range parts[:2] {
		seg, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return ErrMalformed
		}
		if err := RejectDuplicateKeys(seg); err != nil {
			return err
		}
	}
	tok, err := jwt.ParseSigned(raw, v.Algorithms)
	if err != nil {
		if strings.Contains(err.Error(), "algorithm") {
			return ErrAlgorithm
		}
		return ErrMalformed
	}
	if len(tok.Headers) != 1 {
		return ErrMalformed
	}
	h := tok.Headers[0]
	typ, _ := h.ExtraHeaders[jose.HeaderType].(string)
	if !typeMatches(typ, expectedTyp) {
		return ErrWrongType
	}
	if h.KeyID == "" {
		return ErrUnknownKey
	}
	pk, ok, err := v.Keys.Lookup(ctx, realmID, h.KeyID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrUnknownKey
	}
	if pk.Algorithm != h.Algorithm {
		// The header algorithm must match the key's registered algorithm (no confusion).
		return ErrAlgorithm
	}
	if err := tok.Claims(pk.JWK.Key, out...); err != nil {
		return ErrSignature
	}
	return nil
}

// typeMatches compares a JOSE typ case-insensitively, with or without the
// "application/" prefix (RFC 7515 §4.1.9). An absent typ never matches: every
// token this server signs names its type.
func typeMatches(got, want string) bool {
	got = strings.ToLower(got)
	want = strings.ToLower(want)
	return got == want || got == "application/"+want
}

// RejectDuplicateKeys returns an error if a JSON object has duplicate member names
// at any depth (§14.4 step 2). Go's decoder otherwise keeps the last duplicate.
func RejectDuplicateKeys(b []byte) error { return RejectDuplicateKeysDepth(b, 32) }

// RejectDuplicateKeysDepth is RejectDuplicateKeys with an explicit nesting limit
// (NFR-001 limits.max_json_depth).
func RejectDuplicateKeysDepth(b []byte, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = 32
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > maxDepth {
			return ErrMalformed
		}
		t, err := dec.Token()
		if err != nil {
			return ErrMalformed
		}
		switch d := t.(type) {
		case json.Delim:
			switch d {
			case '{':
				seen := map[string]bool{}
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return ErrMalformed
					}
					k, ok := kt.(string)
					if !ok {
						return ErrMalformed
					}
					if seen[k] {
						return ErrDuplicateClaim
					}
					seen[k] = true
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				if _, err := dec.Token(); err != nil {
					return ErrMalformed
				}
			case '[':
				for dec.More() {
					if err := walk(depth + 1); err != nil {
						return err
					}
				}
				if _, err := dec.Token(); err != nil {
					return ErrMalformed
				}
			}
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	// Exactly one JSON value: any trailing data (even a stray delimiter) is malformed.
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}

// Describe returns a stable, non-secret reason string for an error.
func Describe(err error) string {
	switch {
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrAudience):
		return "audience"
	case errors.Is(err, ErrIssuer):
		return "issuer"
	case errors.Is(err, ErrWrongType):
		return "type"
	case errors.Is(err, ErrAlgorithm):
		return "algorithm"
	case errors.Is(err, ErrUnknownKey):
		return "unknown_key"
	case errors.Is(err, ErrSignature):
		return "signature"
	default:
		return "invalid"
	}
}
