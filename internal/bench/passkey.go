package bench

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// softwarePasskey measures server verification, not authenticator/browser
// latency (NFR-003). Keys remain in memory; they are never result metadata.
// Each worker owns one non-synced ES256 credential and monotonic counter.
type softwarePasskey struct {
	key                   *ecdsa.PrivateKey
	id, handle            []byte
	rpID, origin, subject string
	counter               uint32
}

func newSoftwarePasskey(rpID, origin string) (*softwarePasskey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &softwarePasskey{key: key, id: id, rpID: rpID, origin: origin}, nil
}

func object(v any) map[string]any                   { m, _ := v.(map[string]any); return m }
func stringValue(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func (k *softwarePasskey) authData(attested bool) ([]byte, error) {
	rp := sha256.Sum256([]byte(k.rpID))
	data := append([]byte{}, rp[:]...)
	flags := byte(0x05) // user presence + verification; no backup flags
	if attested {
		flags |= 0x40
	}
	data = append(data, flags)
	data = binary.BigEndian.AppendUint32(data, k.counter)
	if attested {
		data = append(data, make([]byte, 16)...)
		data = binary.BigEndian.AppendUint16(data, uint16(len(k.id)))
		data = append(data, k.id...)
		key, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
			-2: k.key.X.FillBytes(make([]byte, 32)), -3: k.key.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			return nil, err
		}
		data = append(data, key...)
	}
	return data, nil
}

func (k *softwarePasskey) credential(opts map[string]any, register bool) (map[string]any, error) {
	challenge := stringValue(opts, "challenge")
	if challenge == "" {
		return nil, fmt.Errorf("passkey options have no challenge")
	}
	typ := "webauthn.get"
	if register {
		typ = "webauthn.create"
		var err error
		k.handle, err = base64.RawURLEncoding.DecodeString(stringValue(object(opts["user"]), "id"))
		if err != nil || len(k.handle) == 0 {
			return nil, fmt.Errorf("passkey options have no user handle")
		}
	} else {
		if rp := stringValue(opts, "rpId"); rp != "" && rp != k.rpID {
			return nil, fmt.Errorf("passkey RP changed")
		}
		if k.counter == ^uint32(0) {
			return nil, fmt.Errorf("passkey counter exhausted")
		}
		k.counter++
	}
	clientData, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": k.origin, "crossOrigin": false})
	if err != nil {
		return nil, err
	}
	data, err := k.authData(register)
	if err != nil {
		return nil, err
	}
	response := map[string]any{"clientDataJSON": base64.RawURLEncoding.EncodeToString(clientData)}
	if register {
		att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": data})
		if err != nil {
			return nil, err
		}
		response["attestationObject"] = base64.RawURLEncoding.EncodeToString(att)
		response["transports"] = []string{"internal"}
	} else {
		hash := sha256.Sum256(clientData)
		digest := sha256.Sum256(append(data, hash[:]...))
		sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
		if err != nil {
			return nil, err
		}
		response["authenticatorData"] = base64.RawURLEncoding.EncodeToString(data)
		response["signature"] = base64.RawURLEncoding.EncodeToString(sig)
		response["userHandle"] = base64.RawURLEncoding.EncodeToString(k.handle)
	}
	id := base64.RawURLEncoding.EncodeToString(k.id)
	extensions := map[string]any{}
	if register && object(opts["extensions"])["credProps"] == true {
		extensions["credProps"] = map[string]any{"rk": true}
	}
	return map[string]any{"id": id, "rawId": id, "type": "public-key", "authenticatorAttachment": "platform",
		"clientExtensionResults": extensions, "response": response}, nil
}

func jwtData(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var data map[string]any
	if json.Unmarshal(b, &data) != nil {
		return nil
	}
	return data
}

func runPrefix(seed *SeedData, purpose string) (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return seed.Prefix + purpose + "-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b)), nil
}

type passkeyAssertion struct{ keys []*softwarePasskey }

func (*passkeyAssertion) Name() string { return "passkey-assertion" }
func (s *passkeyAssertion) Notes() []string {
	return []string{fmt.Sprintf("software ES256 discoverable passkeys: %d additional isolated users/credentials, registered before warm-up; per-worker counters; none attestation; UP/UV asserted by software", len(s.keys)),
		"one operation: headless transaction, discoverable assertion options, signed assertion verification, authorization-code/PKCE exchange; excludes browser/device latency"}
}

func (s *passkeyAssertion) Prepare(ctx context.Context, e *Env) error {
	if e.Concurrency < 1 || e.Seed.AccountAudience == "" {
		return fmt.Errorf("passkey-assertion needs a freshly generated seed with an account-resource grant")
	}
	settings, err := e.Client.API(ctx, "GET", "/settings", e.adminToken(ctx), nil)
	if _, err := Must(settings, err, 200, "realm passkey policy"); err != nil {
		return err
	}
	policy := object(settings.Body["policy"])
	if object(policy["login"])["passkeys"] != true {
		return fmt.Errorf("enable passkeys in the dedicated benchmark realm before running passkey-assertion")
	}
	origin := e.Client.BaseURL
	if origins, _ := object(policy["webauthn"])["origins"].([]any); len(origins) > 0 {
		origin, _ = origins[0].(string)
	}
	if u, err := url.Parse(origin); err != nil || u.Hostname() == "" {
		return fmt.Errorf("invalid benchmark passkey origin")
	}
	prefix, err := runPrefix(e.Seed, "pk")
	if err != nil {
		return err
	}
	// New accounts keep factor enrollment out of the password workload and
	// avoid relaxing per-identifier budgets. Import is unmeasured preparation.
	users := make([]map[string]any, e.Concurrency)
	for i := range users {
		users[i] = map[string]any{"source_id": fmt.Sprint(i), "email": fmt.Sprintf("%s-%d@bench.test", prefix, i), "email_verified": true,
			"password_hash": legacyHash(e.Seed.UserPassword(i), i)}
	}
	for start := 0; start < len(users); start += 500 {
		job, err := e.Client.API(ctx, "POST", "/user-imports", e.adminToken(ctx), map[string]any{"source_system": prefix, "users": users[start:min(start+500, len(users))],
			"trust_email_verification": true, "verification_reason": "synthetic passkey benchmark accounts"})
		if _, err := Must(job, err, 202, "passkey user import"); err != nil {
			return err
		}
		id := job.Str("job_id")
		if id == "" {
			return fmt.Errorf("passkey user import has no job_id")
		}
		if err := waitJob(ctx, e.Client, e.Admin, id); err != nil {
			return err
		}
	}
	s.keys = nil
	for i := range users {
		token, outcome := e.loginPassword(ctx, users[i]["email"].(string), e.Seed.UserPassword(i), e.Seed.AccountAudience, "proudauth:account")
		if outcome != "ok" {
			return fmt.Errorf("passkey enrollment sign-in: %s", outcome)
		}
		access := token.Str("access_token")
		options, err := e.Client.API(ctx, "POST", "/me/webauthn/registration-options", access, map[string]any{})
		if _, err := Must(options, err, 200, "passkey registration options"); err != nil {
			return err
		}
		public := object(options.Body["public_key"])
		key, err := newSoftwarePasskey(stringValue(object(public["rp"]), "id"), origin)
		if err != nil {
			return err
		}
		key.subject = stringValue(jwtData(access), "sub")
		if key.subject == "" || key.rpID == "" {
			return fmt.Errorf("passkey registration lacks subject or RP ID")
		}
		credential, err := key.credential(public, true)
		if err != nil {
			return err
		}
		result, err := e.Client.API(ctx, "POST", "/me/webauthn/registration-complete", access,
			map[string]any{"ceremony_id": options.Str("ceremony_id"), "credential": credential, "name": "benchmark software authenticator"})
		if _, err := Must(result, err, 201, "passkey registration"); err != nil {
			return err
		}
		s.keys = append(s.keys, key)
	}
	return nil
}

func (s *passkeyAssertion) Op(ctx context.Context, e *Env, worker int, _ *mrand.Rand) string {
	if worker < 0 || worker >= len(s.keys) {
		return "setup_missing_credential"
	}
	d := e.Seed
	verifier, challenge := PKCE()
	start, err := e.Client.API(ctx, "POST", "/auth/transactions", "", map[string]any{"client_id": d.Web.ClientID, "redirect_uri": d.RedirectURI,
		"scope": "bench:read", "state": "bench", "code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{d.Audience}})
	if err != nil || start.Status != 201 {
		return lifecycleOutcome(start, err, "passkey_start")
	}
	step := func(name string, body any) (*Response, error) {
		return e.Client.Do(ctx, Request{Method: "POST", Path: "/api/v1/realms/" + e.Client.Realm + "/auth/transactions/" + start.Str("transaction_id") + "/" + name,
			JSON: body, Headers: map[string]string{"X-Transaction-Token": start.Str("continuation_token")}})
	}
	options, err := step("webauthn/options", map[string]any{})
	if err != nil || options.Status != 200 {
		return lifecycleOutcome(options, err, "passkey_options")
	}
	credential, err := s.keys[worker].credential(object(object(options.Body["webauthn"])["public_key"]), false)
	if err != nil {
		return "setup_invalid_assertion_options"
	}
	done, err := step("webauthn/verify", map[string]any{"credential": credential})
	if err != nil || done.Status != 200 {
		return lifecycleOutcome(done, err, "passkey_verify")
	}
	u, err := url.Parse(done.Str("redirect_to"))
	if err != nil || u.Query().Get("code") == "" {
		return "unexpected_next_action"
	}
	token, err := e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Basic: [2]string{d.Web.ClientID, d.Web.Secret},
		Form: url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {d.RedirectURI}, "resource": {d.Audience}}})
	if err != nil || token.Status != 200 {
		return lifecycleOutcome(token, err, "passkey_token")
	}
	claims := jwtData(token.Str("access_token"))
	if claims["sub"] != s.keys[worker].subject || claims["acr"] != "urn:proudauth:acr:phishing_resistant" {
		return "invariant_violation_subject_or_assurance"
	}
	return "ok"
}
