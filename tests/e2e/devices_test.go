package e2e

import (
	"net/url"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestRememberedDevices covers AUT-013.
func TestRememberedDevices(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Login.RememberDevices = true })
	h := f.H
	f.EnrollTOTP("bob")
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	step := func(tx, cont, path string, body any, device string) *Resp {
		if body == nil {
			body = map[string]any{}
		}
		hdr := map[string]string{"X-Transaction-Token": cont}
		if device != "" {
			hdr["X-Remembered-Device"] = device
		}
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/" + path, JSON: body, Headers: hdr})
	}
	login := func(user, device string, opts LoginOpts) (*Resp, string, string, string) {
		start, verifier, cont := h.StartTx(opts)
		tx := start.Str("transaction_id")
		step(tx, cont, "identify", map[string]any{"identifier": user + "@example.test"}, device)
		st := step(tx, cont, "password", map[string]any{"password": h.passwords[user+"@example.test"]}, device)
		return st, tx, cont, verifier
	}
	// First sign-in: TOTP is required; the user opts in to remember the device.
	st, tx, cont, _ := login("bob", "", cli)
	if !has(actionTypes(st), "totp") || !has(actionTypes(st), "remember_device") {
		t.Fatalf("expected totp and remember_device actions: %s", st.Raw)
	}
	mustStatus(t, step(tx, cont, "remember-device", map[string]any{"remember": true}, ""), 200, "opt in")
	done := step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("bob@example.test")}, "")
	device := done.Str("one_time.remembered_device_token")
	if done.Str("redirect_to") == "" || device == "" {
		t.Fatalf("no remembered device issued: %s", done.Raw)
	}

	t.Run("remembered device skips the prompt without adding assurance", func(t *testing.T) {
		st, _, _, verifier := login("bob", device, cli)
		if st.Str("redirect_to") == "" {
			t.Fatalf("remembered device did not skip MFA: %s", st.Raw)
		}
		u, _ := url.Parse(st.Str("redirect_to"))
		toks := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
		mustStatus(t, toks, 200, "token")
		if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:single_factor" {
			t.Fatalf("remembered device inflated assurance: %v", acr)
		}
	})

	t.Run("not honored for explicit re-authentication or another user", func(t *testing.T) {
		withPrompt := cli
		withPrompt.Prompt = "login"
		if st, _, _, _ := login("bob", device, withPrompt); !has(actionTypes(st), "totp") {
			t.Fatalf("prompt=login short-circuited: %s", st.Raw)
		}
		withACR := cli
		withACR.ACR = "urn:proudauth:acr:mfa"
		if st, _, _, _ := login("bob", device, withACR); !has(actionTypes(st), "totp") {
			t.Fatalf("acr_values mfa short-circuited: %s", st.Raw)
		}
		f.EnrollTOTP("alice")
		if st, _, _, _ := login("alice", device, cli); !has(actionTypes(st), "totp") {
			t.Fatalf("bob's device skipped alice's MFA: %s", st.Raw)
		}
	})

	t.Run("listing and revocation", func(t *testing.T) {
		tok := f.AccountToken("bob").Tokens.Str("access_token")
		list := h.API("GET", "/me/remembered-devices", tok, nil)
		items, _ := list.Get("items").([]any)
		if len(items) != 1 {
			t.Fatalf("devices: %s", list.Raw)
		}
		mustStatus(t, h.API("DELETE", "/me/remembered-devices/"+items[0].(map[string]any)["id"].(string), tok, nil), 204, "revoke device")
		if st, _, _, _ := login("bob", device, cli); !has(actionTypes(st), "totp") {
			t.Fatalf("revoked device still honored: %s", st.Raw)
		}
	})
}
