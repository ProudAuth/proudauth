package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/proudauth/proudauth/internal/realm"
)

// softKey is a software WebAuthn authenticator for tests. It produces "none"
// attestation registration responses and ES256 assertions exactly as a browser
// would serialize them (PublicKeyCredential JSON).
type softKey struct {
	priv       *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	counter    uint32
	rpID       string
	origin     string
	backup     bool // backup eligible + backed up (synced passkey)
	uv         bool
	// aaguid names the authenticator model (zero when nil); att, when set,
	// signs a packed attestation; credProtect, when non-zero, is reported
	// as the credProtect extension output (PASS-009, PASS-010).
	aaguid      []byte
	att         *attester
	credProtect int
}

func newSoftKey(rpID, origin string, backup bool) *softKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &softKey{priv: k, credID: id, rpID: rpID, origin: origin, backup: backup, uv: true}
}

var b64 = base64.RawURLEncoding

func (k *softKey) flags(attested bool) byte {
	f := byte(0x01) // UP
	if k.uv {
		f |= 0x04
	}
	if k.backup {
		f |= 0x08 | 0x10
	}
	if attested {
		f |= 0x40
		if k.credProtect != 0 {
			f |= 0x80 // extension data
		}
	}
	return f
}

func (k *softKey) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(k.rpID))
	out := append([]byte{}, rp[:]...)
	out = append(out, k.flags(attested))
	out = binary.BigEndian.AppendUint32(out, k.counter)
	if attested {
		aaguid := k.aaguid
		if aaguid == nil {
			aaguid = make([]byte, 16)
		}
		out = append(out, aaguid...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.credID)))
		out = append(out, k.credID...)
		point, err := k.priv.PublicKey.Bytes()
		if err != nil {
			panic(err)
		}
		x, y := point[1:33], point[33:65]
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
		out = append(out, cose...)
		if k.credProtect != 0 {
			ext, _ := cbor.Marshal(map[string]any{"credProtect": k.credProtect})
			out = append(out, ext...)
		}
	}
	return out
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// create answers navigator.credentials.create() options.
func (k *softKey) create(t testing.TB, opts any) map[string]any {
	t.Helper()
	o, ok := opts.(map[string]any)
	if !ok {
		t.Fatalf("no creation options: %v", opts)
	}
	user := o["user"].(map[string]any)
	h, err := b64.DecodeString(user["id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	k.userHandle = h
	cd := clientData("webauthn.create", o["challenge"].(string), k.origin)
	ad := k.authData(true)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if k.att != nil {
		att = k.att.packed(t, ad, cd)
	}
	return map[string]any{"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}},
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "attestationObject": b64.EncodeToString(att), "transports": []string{"internal"}}}
}

// get answers navigator.credentials.get() options.
func (k *softKey) get(t testing.TB, opts any) map[string]any {
	t.Helper()
	o, ok := opts.(map[string]any)
	if !ok {
		t.Fatalf("no request options: %v", opts)
	}
	k.counter++
	ad := k.authData(false)
	cd := clientData("webauthn.get", o["challenge"].(string), k.origin)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"id": b64.EncodeToString(k.credID), "rawId": b64.EncodeToString(k.credID), "type": "public-key",
		"authenticatorAttachment": "platform", "clientExtensionResults": map[string]any{},
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(k.userHandle)}}
}

func actionTypes(st *Resp) []string {
	out := []string{}
	actions, _ := st.Get("next_actions").([]any)
	if actions == nil {
		actions, _ = st.Get("state.next_actions").([]any)
	}
	for _, a := range actions {
		out = append(out, a.(map[string]any)["type"].(string))
	}
	return out
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// exchange redeems the code from a completed transaction state for tokens.
func (f *Fixture) exchange(st *Resp, verifier, clientID string, resources ...string) *Resp {
	f.H.t.Helper()
	u, _ := url.Parse(st.Str("redirect_to"))
	code := u.Query().Get("code")
	if code == "" {
		f.H.t.Fatalf("transaction did not complete: %d %s", st.Status, st.Raw)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1/callback"},
		"client_id": {clientID}}
	for _, r := range resources {
		form.Add("resource", r)
	}
	return f.H.TokenRequest(form, "", "")
}

func passkeyPolicy(p *realm.Policy) {
	p.Login.Passkeys = true
	p.WebAuthn = realm.WebAuthnPolicy{RPID: "login.test", RPName: "Example", Origins: []string{"https://login.test"}, AllowSynced: true, UserVerification: "preferred"}
}

// TestPasskeyEnrollmentHonoursMFAFloor covers MFA-003: self-service passkey
// enrollment requires user verification when the operator floor demands
// phishing-resistant MFA, as sign-in does, even under a realm policy that
// predates the floor.
func TestPasskeyEnrollmentHonoursMFAFloor(t *testing.T) {
	f := NewFixture(t, passkeyPolicy)
	h := f.H
	tok := f.AccountToken("carol").Tokens.Str("access_token") // no factor yet
	uv := func() string {
		t.Helper()
		opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		mustStatus(t, opts, 200, "registration options")
		return opts.Str("public_key.authenticatorSelection.userVerification")
	}
	if got := uv(); got == "required" {
		t.Fatalf("user verification required without policy or floor: %q", got)
	}
	h.App.D.Cfg.Security.MFAFloor.AdminPhishingResistant = true
	defer func() { h.App.D.Cfg.Security.MFAFloor.AdminPhishingResistant = false }()
	if got := uv(); got != "required" {
		t.Fatalf("operator floor ignored at enrollment: userVerification %q", got)
	}
}

// TestPasskeys covers PASS-001..PASS-007, MFA-007, SEC-012 and TEST-025.
func TestPasskeys(t *testing.T) {
	f := NewFixture(t, passkeyPolicy)
	h := f.H
	account := h.Realm.Issuer + "/account"
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{account}}

	enroll := func(user string, key *softKey, name string) {
		t.Helper()
		tok := f.AccountToken(user).Tokens.Str("access_token")
		opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		mustStatus(t, opts, 200, "registration options")
		if opts.Str("public_key.rp.id") != "login.test" {
			t.Fatalf("rp id: %s", opts.Raw)
		}
		res := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": key.create(t, opts.Get("public_key")), "name": name})
		mustStatus(t, res, 201, "registration complete")
		// The ceremony is single-use.
		again := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": key.create(t, opts.Get("public_key")), "name": name})
		if again.Status != 400 {
			t.Fatalf("replayed registration ceremony: %d %s", again.Status, again.Raw)
		}
	}

	alice := newSoftKey("login.test", "https://login.test", false)
	bob := newSoftKey("login.test", "https://login.test", true)
	enroll("alice", alice, "Laptop")
	tok := f.AccountToken("alice").Tokens.Str("access_token")
	list := h.API("GET", "/me/webauthn", tok, nil)
	mustStatus(t, list, 200, "list passkeys")
	items := list.Get("items").([]any)
	if len(items) != 1 || items[0].(map[string]any)["name"] != "Laptop" || items[0].(map[string]any)["backup_eligible"] != false {
		t.Fatalf("passkey list: %s", list.Raw)
	}
	if strings.Contains(string(list.Raw), "public_key") || strings.Contains(string(list.Raw), b64.EncodeToString(alice.credID)) {
		t.Fatal("passkey list exposes key material or raw credential IDs")
	}
	mustStatus(t, h.API("PATCH", "/me/webauthn/"+items[0].(map[string]any)["id"].(string), tok, map[string]any{"name": "Work laptop"}), 204, "rename")

	t.Run("adding a factor needs an existing one", func(t *testing.T) {
		// alice's password-only session cannot add a second authenticator (MFA-006).
		r := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		if r.Status != 403 || r.Str("code") != "step_up_required" {
			t.Fatalf("factor added without proving the existing one: %d %s", r.Status, r.Raw)
		}
		mustStatus(t, h.API("POST", "/me/totp/enroll", tok, nil), 403, "totp without the existing factor")
	})

	t.Run("registration bound to origin", func(t *testing.T) {
		evil := newSoftKey("login.test", "https://evil.test", false)
		tok := f.AccountToken("carol").Tokens.Str("access_token") // no factor yet
		opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		res := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": evil.create(t, opts.Get("public_key"))})
		if res.Status != 400 || res.Str("code") != "invalid_proof" {
			t.Fatalf("wrong-origin registration: %d %s", res.Status, res.Raw)
		}
		wrongRP := newSoftKey("evil.test", "https://login.test", false)
		opts = h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
		if res := h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
			"credential": wrongRP.create(t, opts.Get("public_key"))}); res.Status != 400 {
			t.Fatalf("wrong RP ID hash accepted: %d", res.Status)
		}
		f.ReloginAdmin()
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=mfa.webauthn.enrollment_failed", nil), 200, "audit")
		if len(ev.Get("items").([]any)) < 2 {
			t.Fatalf("failed enrollment not audited: %s", ev.Raw)
		}
	})

	t.Run("username-less sign-in", func(t *testing.T) {
		start, verifier, cont := h.StartTx(cli)
		txID := start.Str("transaction_id")
		if !has(actionTypes(start), "webauthn") {
			t.Fatalf("webauthn not offered: %s", start.Raw)
		}
		opts := h.Step(txID, cont, "webauthn/options", nil)
		mustStatus(t, opts, 200, "options")
		if allow, _ := opts.Get("webauthn.public_key.allowCredentials").([]any); len(allow) != 0 {
			t.Fatalf("discoverable ceremony lists credentials: %s", opts.Raw)
		}
		assertion := alice.get(t, opts.Get("webauthn.public_key"))
		done := h.Step(txID, cont, "webauthn/verify", map[string]any{"credential": assertion})
		mustStatus(t, done, 200, "verify")
		toks := f.exchange(done, verifier, "proudauth-cli", account)
		mustStatus(t, toks, 200, "token")
		if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:phishing_resistant" {
			t.Fatalf("passkey assurance not reflected: acr=%v", acr)
		}
		// The session records the factor as a hardware-bound, user-verified key.
		sessions := h.API("GET", "/me/sessions", toks.Str("access_token"), nil)
		if s := jsonString(sessions.Body); !strings.Contains(s, "hwk") {
			t.Fatalf("session factors: %s", s)
		}
		// Replaying the same assertion against a new ceremony fails (challenge binding).
		start2, _, cont2 := h.StartTx(cli)
		tx2 := start2.Str("transaction_id")
		h.Step(tx2, cont2, "webauthn/options", nil)
		if r := h.Step(tx2, cont2, "webauthn/verify", map[string]any{"credential": assertion}); r.Status != 400 {
			t.Fatalf("replayed assertion accepted: %d %s", r.Status, r.Raw)
		}
		// Without an open ceremony, verify fails.
		if r := h.Step(tx2, cont2, "webauthn/verify", map[string]any{"credential": assertion}); r.Status != 400 {
			t.Fatalf("verify without ceremony: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("identified accounts and enumeration resistance", func(t *testing.T) {
		start, _, cont := h.StartTx(cli)
		txID := start.Str("transaction_id")
		h.Step(txID, cont, "identify", map[string]any{"identifier": "alice@example.test"})
		known := h.Step(txID, cont, "webauthn/options", nil)
		start2, _, cont2 := h.StartTx(cli)
		tx2 := start2.Str("transaction_id")
		h.Step(tx2, cont2, "identify", map[string]any{"identifier": "nobody@example.test"})
		unknown := h.Step(tx2, cont2, "webauthn/options", nil)
		ka, _ := known.Get("webauthn.public_key.allowCredentials").([]any)
		ua, _ := unknown.Get("webauthn.public_key.allowCredentials").([]any)
		if len(ka) != 1 || len(ua) != 1 {
			t.Fatalf("allow lists differ in shape: known=%d unknown=%d", len(ka), len(ua))
		}
		if ka[0].(map[string]any)["id"] != b64.EncodeToString(alice.credID) {
			t.Fatalf("known account allow list: %v", ka)
		}
		// Another account's identified ceremony cannot be satisfied with alice's key.
		start3, _, cont3 := h.StartTx(cli)
		tx3 := start3.Str("transaction_id")
		h.Step(tx3, cont3, "identify", map[string]any{"identifier": "bob@example.test"})
		bobOpts := h.Step(tx3, cont3, "webauthn/options", nil)
		if r := h.Step(tx3, cont3, "webauthn/verify", map[string]any{"credential": alice.get(t, bobOpts.Get("webauthn.public_key"))}); r.Status != 400 {
			t.Fatalf("alice's passkey signed bob in: %d %s", r.Status, r.Raw)
		}
		// The identified flow works for the owner.
		start4, verifier4, cont4 := h.StartTx(cli)
		tx4 := start4.Str("transaction_id")
		h.Step(tx4, cont4, "identify", map[string]any{"identifier": "alice@example.test"})
		o4 := h.Step(tx4, cont4, "webauthn/options", nil)
		done := h.Step(tx4, cont4, "webauthn/verify", map[string]any{"credential": alice.get(t, o4.Get("webauthn.public_key"))})
		mustStatus(t, f.exchange(done, verifier4, "proudauth-cli", account), 200, "identified passkey login")
	})

	t.Run("TEST-024 assertions with wrong challenge, origin, RP ID or flags are rejected", func(t *testing.T) {
		try := func(mutate func(k *softKey, opts map[string]any)) int {
			start, _, cont := h.StartTx(cli)
			tx := start.Str("transaction_id")
			o := h.Step(tx, cont, "webauthn/options", nil)
			opts := o.Get("webauthn.public_key").(map[string]any)
			k := *alice
			mutate(&k, opts)
			r := h.Step(tx, cont, "webauthn/verify", map[string]any{"credential": k.get(t, opts)})
			alice.counter = k.counter
			return r.Status
		}
		cases := map[string]func(k *softKey, opts map[string]any){
			"wrong challenge": func(k *softKey, opts map[string]any) {
				opts["challenge"] = b64.EncodeToString([]byte("not-the-issued-challenge-value"))
			},
			"wrong origin": func(k *softKey, opts map[string]any) { k.origin = "https://evil.test" },
			"wrong RP ID":  func(k *softKey, opts map[string]any) { k.rpID = "evil.test" },
		}
		for name, m := range cases {
			if st := try(m); st != 400 {
				t.Fatalf("%s accepted: %d", name, st)
			}
		}
		// Phishing-resistant requests require user verification; a UP-only
		// assertion is refused even though the signature is valid.
		strict := cli
		strict.ACR = "urn:proudauth:acr:phishing_resistant"
		start, _, cont := h.StartTx(strict)
		tx := start.Str("transaction_id")
		o := h.Step(tx, cont, "webauthn/options", nil)
		k := *alice
		k.uv = false
		if r := h.Step(tx, cont, "webauthn/verify", map[string]any{"credential": k.get(t, o.Get("webauthn.public_key"))}); r.Status != 400 {
			t.Fatalf("assertion without required user verification accepted: %d", r.Status)
		}
		alice.counter = k.counter
	})

	t.Run("counter semantics", func(t *testing.T) {
		// Device-bound authenticator whose counter goes backwards: possible clone.
		login := func(key *softKey) *Resp {
			start, _, cont := h.StartTx(cli)
			txID := start.Str("transaction_id")
			o := h.Step(txID, cont, "webauthn/options", nil)
			return h.Step(txID, cont, "webauthn/verify", map[string]any{"credential": key.get(t, o.Get("webauthn.public_key"))})
		}
		alice.counter = 0
		if r := login(alice); r.Status != 400 {
			t.Fatalf("device-bound counter regression accepted: %d %s", r.Status, r.Raw)
		}
		// Synced passkey (TEST-025): a counter change is a risk signal, not a lockout.
		enroll("bob", bob, "Phone")
		bob.counter = 10
		if r := login(bob); r.Status != 200 {
			t.Fatalf("synced login: %d %s", r.Status, r.Raw)
		}
		bob.counter = 3
		if r := login(bob); r.Status != 200 {
			t.Fatalf("synced passkey with counter change rejected: %d %s", r.Status, r.Raw)
		}
		f.ReloginAdmin()
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=mfa.webauthn.counter_anomaly", nil), 200, "audit")
		handlings := jsonString(ev.Get("items"))
		if !strings.Contains(handlings, "rejected_device_bound") || !strings.Contains(handlings, "accepted_synced") {
			t.Fatalf("counter anomalies not recorded with handling: %s", handlings)
		}
	})

	t.Run("phishing-resistant administrators", func(t *testing.T) {
		// root-admin enrolled TOTP (and got recovery codes) at bootstrap. The
		// profile must not let the password alone register a passkey and
		// take over the account (MFA-006): the existing TOTP is proved first,
		// as an upgrade proof that unlocks registration and nothing else.
		f.ReloginAdmin()
		admin := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:admin", Resources: []string{h.Realm.Issuer + "/admin"}, Identifier: "root-admin"}
		signIn := func() (string, string, string, *Resp) {
			t.Helper()
			start, verifier, cont := h.StartTx(admin)
			txID := start.Str("transaction_id")
			h.Step(txID, cont, "identify", map[string]any{"identifier": "root-admin"})
			return txID, verifier, cont, h.Step(txID, cont, "password", map[string]any{"password": h.passwords["root-admin"]})
		}
		activeTOTP := func() int {
			t.Helper()
			var n int
			if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`,
				f.Users["admin"]).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}

		// A TOTP enrollment begun before the profile applied cannot be
		// activated after it does: activation would replace the account's
		// TOTP and recovery codes.
		mustStatus(t, h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/users/" + f.Users["admin"] + "/required-actions", Token: f.AdminToken,
			JSON: map[string]any{"actions": []string{"configure_totp"}}}), 204, "require a factor enrollment")
		pendTx, _, pendCont, _ := signIn()
		st := h.Step(pendTx, pendCont, "totp", map[string]any{"code": h.TOTPNow("root-admin")})
		if !has(actionTypes(st), "enroll_totp") {
			t.Fatalf("required enrollment not offered: %s", st.Raw)
		}
		en := h.Step(pendTx, pendCont, "totp/enroll", nil)
		mustStatus(t, en, 200, "totp enroll before the profile")
		h.seeds["root-admin (pending)"] = en.Str("one_time.totp.secret")

		cur := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
		var pol realm.Policy
		_ = json.Unmarshal([]byte(jsonString(cur.Get("policy"))), &pol)
		pol.MFA.AdminPhishingResistant = true
		pol.WebAuthn.AllowSynced = false
		upd := h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/settings", Token: f.AdminToken, JSON: map[string]any{"policy": pol, "reason": "SEC-012"},
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
		mustStatus(t, upd, 200, "policy update")

		if r := h.Step(pendTx, pendCont, "totp/activate", map[string]any{"code": h.TOTPNow("root-admin (pending)")}); r.Status != 409 {
			t.Fatalf("TOTP activated under the phishing-resistant profile: %d %s", r.Status, r.Raw)
		}
		if n := activeTOTP(); n != 1 {
			t.Fatalf("active TOTP credentials after the refused activation: %d", n)
		}

		// Password alone: the existing factors are offered as an upgrade
		// proof, and nothing can be enrolled yet.
		txID, verifier, cont, st := signIn()
		acts := actionTypes(st)
		if has(acts, "enroll_webauthn") || has(acts, "enroll_totp") || !has(acts, "totp") || !has(acts, "recovery_code") {
			t.Fatalf("password-only actions under the profile: %v", acts)
		}
		for _, a := range st.Get("next_actions").([]any) {
			if opts, _ := a.(map[string]any)["options"].(map[string]any); opts["upgrade_proof"] != true {
				t.Fatalf("action not marked as an upgrade proof: %v", a)
			}
		}
		for step, body := range map[string]any{
			"webauthn/registration-options": nil,
			"totp/enroll":                   nil,
			"totp/activate":                 map[string]any{"code": "000000"},
		} {
			if r := h.Step(txID, cont, step, body); r.Status != 409 {
				t.Fatalf("%s accepted with the password alone: %d %s", step, r.Status, r.Raw)
			}
		}

		// The TOTP proof unlocks passkey registration only: no factor is
		// completed and TOTP is not offered again.
		st = h.Step(txID, cont, "totp", map[string]any{"code": h.TOTPNow("root-admin")})
		mustStatus(t, st, 200, "totp upgrade proof")
		acts = actionTypes(st)
		if st.Str("status") != "pending" || has(toStrings(st.Get("completed_factors")), "totp") {
			t.Fatalf("upgrade proof counted as a factor: %s", st.Raw)
		}
		if !has(acts, "enroll_webauthn") || has(acts, "enroll_totp") || has(acts, "totp") || has(acts, "recovery_code") {
			t.Fatalf("actions after the upgrade proof: %v", acts)
		}
		if r := h.Step(txID, cont, "totp", map[string]any{"code": h.TOTPNow("root-admin")}); r.Status != 409 {
			t.Fatalf("TOTP accepted again after the upgrade proof: %d %s", r.Status, r.Raw)
		}
		if r := h.Step(txID, cont, "totp/enroll", nil); r.Status != 409 {
			t.Fatalf("TOTP enrollment under the profile: %d %s", r.Status, r.Raw)
		}
		if n := activeTOTP(); n != 1 {
			t.Fatalf("active TOTP credentials: %d", n)
		}
		// Synced passkeys are refused by policy; a device-bound one is accepted.
		synced := newSoftKey("login.test", "https://login.test", true)
		ro := h.Step(txID, cont, "webauthn/registration-options", nil)
		mustStatus(t, ro, 200, "tx registration options")
		if ro.Str("webauthn.public_key.authenticatorSelection.userVerification") != "required" {
			t.Fatalf("user verification not required: %s", ro.Raw)
		}
		if r := h.Step(txID, cont, "webauthn/register", map[string]any{"credential": synced.create(t, ro.Get("webauthn.public_key"))}); r.Status != 422 {
			t.Fatalf("synced passkey accepted with allow_synced=false: %d %s", r.Status, r.Raw)
		}
		key := newSoftKey("login.test", "https://login.test", false)
		ro = h.Step(txID, cont, "webauthn/registration-options", nil)
		done := h.Step(txID, cont, "webauthn/register", map[string]any{"credential": key.create(t, ro.Get("webauthn.public_key")), "name": "YubiKey"})
		mustStatus(t, done, 200, "tx register")
		toks := f.exchange(done, verifier, "proudauth-cli", h.Realm.Issuer+"/admin")
		mustStatus(t, toks, 200, "admin token")
		if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:phishing_resistant" {
			t.Fatalf("admin acr %v", acr)
		}
		var proof string
		_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT metadata->>'factor' FROM audit_events WHERE type='mfa.upgrade_proof.recorded'
			AND subject_id=$1`, f.Users["admin"]).Scan(&proof)
		if proof != "totp" {
			t.Fatalf("upgrade proof not audited: %q", proof)
		}
		// Next admin login: only the passkey is offered as second factor.
		txID, verifier, cont, st = signIn()
		if acts := actionTypes(st); !has(acts, "webauthn") || has(acts, "totp") || has(acts, "recovery_code") || has(acts, "enroll_webauthn") {
			t.Fatalf("second admin login actions: %v", acts)
		}
		if r := h.Step(txID, cont, "totp", map[string]any{"code": h.TOTPNow("root-admin")}); r.Status != 409 {
			t.Fatalf("TOTP accepted with a user-verified passkey enrolled: %d %s", r.Status, r.Raw)
		}
		o := h.Step(txID, cont, "webauthn/options", nil)
		done = h.Step(txID, cont, "webauthn/verify", map[string]any{"credential": key.get(t, o.Get("webauthn.public_key"))})
		toks = f.exchange(done, verifier, "proudauth-cli", h.Realm.Issuer+"/admin")
		mustStatus(t, toks, 200, "admin passkey login")
		// Bob's synced passkey is now refused at sign-in by policy.
		start, _, cont := h.StartTx(cli)
		txID = start.Str("transaction_id")
		o = h.Step(txID, cont, "webauthn/options", nil)
		if r := h.Step(txID, cont, "webauthn/verify", map[string]any{"credential": bob.get(t, o.Get("webauthn.public_key"))}); r.Status != 400 {
			t.Fatalf("synced passkey accepted after allow_synced=false: %d %s", r.Status, r.Raw)
		}
	})
}

// TestPhishingResistantUpgradeFromUnverifiedPasskey covers MFA-006 and
// SEC-012: under the phishing-resistant profile an account whose only
// passkey never performed user verification proves that passkey first; the
// proof unlocks registering a user-verified passkey but is not MFA itself.
func TestPhishingResistantUpgradeFromUnverifiedPasskey(t *testing.T) {
	f := NewFixture(t, passkeyPolicy)
	h := f.H
	weak := newSoftKey("login.test", "https://login.test", false)
	weak.uv = false
	tok := f.AccountToken("carol").Tokens.Str("access_token")
	opts := h.API("POST", "/me/webauthn/registration-options", tok, map[string]any{})
	mustStatus(t, opts, 200, "registration options")
	mustStatus(t, h.API("POST", "/me/webauthn/registration-complete", tok, map[string]any{"ceremony_id": opts.Str("ceremony_id"),
		"credential": weak.create(t, opts.Get("public_key")), "name": "Old key"}), 201, "register unverified passkey")

	strict := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		ACR: "urn:proudauth:acr:phishing_resistant"}
	start, verifier, cont := h.StartTx(strict)
	txID := start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": "carol@example.test"})
	st := h.Step(txID, cont, "password", map[string]any{"password": h.passwords["carol@example.test"]})
	if acts := actionTypes(st); !has(acts, "webauthn") || has(acts, "enroll_webauthn") {
		t.Fatalf("password-only actions: %v", acts)
	}
	if r := h.Step(txID, cont, "webauthn/registration-options", nil); r.Status != 409 {
		t.Fatalf("passkey registration with the password alone: %d %s", r.Status, r.Raw)
	}
	o := h.Step(txID, cont, "webauthn/options", nil)
	mustStatus(t, o, 200, "upgrade ceremony")
	if uv := o.Str("webauthn.public_key.userVerification"); uv == "required" {
		t.Fatalf("upgrade ceremony requires user verification the passkey never gave: %s", o.Raw)
	}
	st = h.Step(txID, cont, "webauthn/verify", map[string]any{"credential": weak.get(t, o.Get("webauthn.public_key"))})
	mustStatus(t, st, 200, "upgrade proof")
	if st.Str("status") != "pending" || len(toStrings(st.Get("completed_factors"))) != 1 || !has(actionTypes(st), "enroll_webauthn") {
		t.Fatalf("after the upgrade proof: %s", st.Raw)
	}
	strong := newSoftKey("login.test", "https://login.test", false)
	ro := h.Step(txID, cont, "webauthn/registration-options", nil)
	mustStatus(t, ro, 200, "registration options")
	done := h.Step(txID, cont, "webauthn/register", map[string]any{"credential": strong.create(t, ro.Get("webauthn.public_key")), "name": "New key"})
	mustStatus(t, done, 200, "register")
	toks := f.exchange(done, verifier, "proudauth-cli", h.Realm.Issuer+"/account")
	mustStatus(t, toks, 200, "token")
	if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:phishing_resistant" {
		t.Fatalf("acr %v", acr)
	}
}
