package migrate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
)

// TestPasskeysAreNotCopied covers MIG-008: a passkey is bound to the source's
// relying-party ID and its private key never leaves the authenticator, so no
// adapter copies a WebAuthn credential record. Every credential is reported
// unsupported with re-registration as the remedy, no credential data reaches
// the import documents, the import record has no member that could carry one,
// and a source relying-party ID is reported for review instead of being
// carried over silently.
func TestPasskeysAreNotCopied(t *testing.T) {
	// Keycloak: judy has a real passwordless WebAuthn credential.
	res := convert(t, Keycloak, Options{ImportTOTP: true, Mapping: kcMapping()}, kcFixture)
	entity(t, res.Report, "webauthn_credentials", 1, 0, 0, 1, 0)
	if s := itemReasons(res.Report, "webauthn_credentials", kcJudy); !strings.Contains(s, "unsupported") ||
		!strings.Contains(s, "relying party") || !strings.Contains(s, "registers again") {
		t.Fatalf("judy's passkey not reported as unsupported with re-registration: %s", s)
	}
	if s := itemReasons(res.Report, "users", kcJudy); !strings.Contains(s, "WebAuthn credential(s) not migrated; re-registration required") {
		t.Fatalf("judy's account report does not name the lost passkey: %s", s)
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	// The credential ID and public key of judy's passkey (from the fixture).
	for _, v := range []string{"0YqnudO7p94WMNkGnO4DdBFrQYWvQ-X3tnaGRnCeFNs", "pQECAyYgASFYIJ4mrABhupQArTOxD0AR2U9Ah5HEaCuVTU7ZB5JB0Vl0"} {
		if strings.Contains(string(out), v) {
			t.Fatalf("passkey credential data reached the conversion output: %s", v)
		}
	}
	// The import format has no member for WebAuthn credentials: a passkey
	// can only be enrolled again, never imported.
	rt := reflect.TypeOf(identity.ImportRecord{})
	for i := 0; i < rt.NumField(); i++ {
		tag := strings.ToLower(rt.Field(i).Tag.Get("json"))
		if strings.Contains(tag, "webauthn") || strings.Contains(tag, "passkey") || strings.Contains(tag, "credential_id") {
			t.Fatalf("import records carry a passkey member: %s", tag)
		}
	}

	// A source relying-party ID is a reviewed decision, not carried over:
	// changing the identity hostname means new enrollment.
	var realm map[string]any
	if err := json.Unmarshal(load(t, kcFixture), &realm); err != nil {
		t.Fatal(err)
	}
	realm["webAuthnPolicyRpId"] = "login.acme.example"
	doc, err := json.Marshal(realm)
	if err != nil {
		t.Fatal(err)
	}
	withRP, err := Convert(Keycloak, [][]byte{doc}, Options{Now: fixedNow, Mapping: kcMapping()})
	if err != nil {
		t.Fatal(err)
	}
	if s := itemReasons(withRP.Report, "realm_policies", "webAuthnPolicy"); !strings.Contains(s, "unsupported") ||
		!strings.Contains(s, "login.acme.example") || !strings.Contains(s, "existing passkeys do not carry over") {
		t.Fatalf("source relying-party ID not reported for review: %s", s)
	}

	// SuperTokens: WebAuthn login methods are reported per credential and
	// the account keeps its other sign-in methods.
	var st map[string]any
	if err := json.Unmarshal(load(t, stFixture), &st); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range st["users"].([]any) {
		um := u.(map[string]any)
		if um["externalUserId"] != stChen {
			continue
		}
		found = true
		um["loginMethods"] = append(um["loginMethods"].([]any), map[string]any{"recipeId": "webauthn", "tenantIds": []any{"public"},
			"email": "chen@northwind.example", "webauthnCredentialIds": []any{"cred-a", "cred-b"}, "timeJoinedInMSSinceEpoch": 1767225600000})
	}
	if !found {
		t.Fatal("fixture user chen not found")
	}
	if doc, err = json.Marshal(st); err != nil {
		t.Fatal(err)
	}
	stRes, err := Convert(SuperTokens, [][]byte{doc}, Options{Now: fixedNow, Mapping: stMapping()})
	if err != nil {
		t.Fatal(err)
	}
	entity(t, stRes.Report, "webauthn_credentials", 2, 0, 0, 2, 0)
	if s := itemReasons(stRes.Report, "webauthn_credentials", stChen); !strings.Contains(s, "registers again") {
		t.Fatalf("chen's passkeys not reported: %s", s)
	}
	if rec := record(t, stRes, stChen); rec.PasswordHash == "" {
		t.Fatalf("chen lost the password sign-in method with the passkeys: %+v", rec)
	}

	// ZITADEL's export carries no passkeys at all: the report says so.
	zt := convert(t, Zitadel, Options{SourceVersion: "v4.16.3", Mapping: ztMapping()}, ztFixture)
	if notes := strings.Join(zt.Report.Notes, " "); !strings.Contains(notes, "passkeys") || !strings.Contains(notes, "enroll again") {
		t.Fatalf("ZITADEL report does not say passkeys are enrolled again: %v", zt.Report.Notes)
	}
}

// TestSessionsAreNotPortable covers MIG-010: no adapter carries sessions,
// refresh or offline tokens across issuers. Every conversion reports them as
// unsupported with the cutover impact (users sign in again), and the import
// format has no member that could carry a session or token.
func TestSessionsAreNotPortable(t *testing.T) {
	for _, c := range []struct {
		source string
		opts   Options
		file   string
		extra  string // what the reason must also name
	}{
		{Keycloak, Options{Mapping: kcMapping()}, kcFixture, "offline tokens and consents"},
		{Zitadel, Options{SourceVersion: "v4.16.3", Mapping: ztMapping()}, ztFixture, "tokens"},
		{SuperTokens, Options{Mapping: stMapping()}, stFixture, "sessions"},
		{SuperTokens, Options{SourceVersion: "12.0.7"}, stCoreAPI, "sessions"},
	} {
		res := convert(t, c.source, c.opts, c.file)
		e := res.Report.Entity("sessions")
		if e.Total != 1 || e.Unsupported != 1 || e.Converted+e.ConvertedWithLoss != 0 {
			t.Errorf("%s: sessions reported as %+v, want one unsupported item", c.file, e)
			continue
		}
		var reason string
		for _, it := range res.Report.Items {
			if it.Entity == "sessions" {
				reason = strings.Join(it.Reasons, "; ")
			}
		}
		if !strings.Contains(reason, "never portable across issuers") || !strings.Contains(reason, "sign in again") || !strings.Contains(reason, c.extra) {
			t.Errorf("%s: session reason does not state the cutover impact: %q", c.file, reason)
		}
	}
	rt := reflect.TypeOf(identity.ImportRecord{})
	for i := 0; i < rt.NumField(); i++ {
		tag := strings.ToLower(rt.Field(i).Tag.Get("json"))
		for _, w := range []string{"session", "refresh", "offline", "access_token", "consent"} {
			if strings.Contains(tag, w) {
				t.Fatalf("import records carry a session or token member: %s", tag)
			}
		}
	}
}
