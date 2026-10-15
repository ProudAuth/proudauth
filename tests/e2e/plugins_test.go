package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/plugin"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// publisher signs plugin packages like a plugin vendor would.
type publisher struct {
	keyID, name string
	priv        ed25519.PrivateKey
	pub         ed25519.PublicKey
}

func newPublisher(t testing.TB, keyID, name string) *publisher {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &publisher{keyID: keyID, name: name, priv: priv, pub: pub}
}

func (p *publisher) trusted() configuration.PluginPublisherKey {
	return configuration.PluginPublisherKey{KeyID: p.keyID, Publisher: p.name, PublicKey: base64.StdEncoding.EncodeToString(p.pub)}
}

// pack builds a signed package; mutate may tamper with it after signing.
func (p *publisher) pack(manifest, payload map[string]any) map[string]any {
	pl, _ := json.Marshal(payload)
	sum := sha256.Sum256(pl)
	m := map[string]any{"manifest_version": 1, "publisher": p.name}
	for k, v := range manifest {
		m[k] = v
	}
	if _, ok := m["payload_sha256"]; !ok {
		m["payload_sha256"] = hex.EncodeToString(sum[:])
	}
	mb, _ := json.Marshal(m)
	sig := ed25519.Sign(p.priv, append([]byte(plugin.SigningContext), mb...))
	return map[string]any{"manifest": base64.StdEncoding.EncodeToString(mb), "payload": base64.StdEncoding.EncodeToString(pl),
		"signature": map[string]any{"key_id": p.keyID, "algorithm": "Ed25519", "value": base64.StdEncoding.EncodeToString(sig)}}
}

type pluginEnv struct {
	*Fixture
	acme, rogue *publisher
	hookEP      *endpoint
	carol       string
	w           *worker.Worker
}

func newPluginEnv(t *testing.T, mutate ...func(*realm.Policy)) *pluginEnv {
	t.Helper()
	acme, rogue := newPublisher(t, "acme-2026", "acme"), newPublisher(t, "rogue-1", "rogue")
	h := NewHarness(t, allowPrivate, func(c *configuration.Config) {
		c.Extensions.PluginPublishers = []configuration.PluginPublisherKey{acme.trusted()}
	})
	f := fixtureOn(t, h, mutate...)
	e := &pluginEnv{Fixture: f, acme: acme, rogue: rogue, hookEP: newEndpoint(t), w: worker.New(h.App, "plugin-test")}
	e.hookEP.setAnswer(func(r *http.Request, body []byte) (int, http.Header, []byte) {
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		if p, _ := in["profile"].(map[string]any); p != nil && strings.Contains(strings.ToLower(p["display_name"].(string)), "admin") {
			return 200, nil, []byte(`{"allow":false,"errors":{"display_name":"reserved"}}`)
		}
		return 200, nil, []byte(`{"allow":true}`)
	})
	// Carol is a second realm administrator: reviews need one.
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["realm-admin"], "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}),
		201, "carol admin")
	f.EnrollTOTP("carol")
	e.carol = f.AdminTokenFor("carol").Tokens.Str("access_token")
	if _, err := e.w.DispatchOutbox(e.ctx()); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *pluginEnv) ctx() context.Context { return bg() }

func (e *pluginEnv) payload(hookTimeout int, withWebhook bool, roleID string) map[string]any {
	p := map[string]any{
		"hooks": []any{map[string]any{"name": "hr profile rules", "kind": "profile.validation", "url": e.hookEP.srv.URL + "/profile",
			"allow_private_network": true, "timeout_ms": hookTimeout}},
		"workflows": []any{map[string]any{"name": "hr grant", "definition": map[string]any{"schema_version": 1,
			"triggers": []any{map[string]any{"type": "manual"}},
			"steps":    []any{map[string]any{"id": "grant", "type": "assign_role", "role_id": roleID, "scope": "organization"}}}}},
	}
	if withWebhook {
		p["webhooks"] = []any{map[string]any{"name": "hr feed", "destination_url": e.hookEP.srv.URL + "/feed", "event_types": []string{"user.created"},
			"allow_private_network": true}}
	}
	return p
}

var hrPermissions = []string{"realm.hooks.write", "realm.webhooks.write", "realm.workflows.write", "realm.workflows.publish", "org.roles.assign"}

func (e *pluginEnv) upload(t *testing.T, token string, pkg map[string]any, want int, what string) *Resp {
	t.Helper()
	r := e.H.API("POST", "/plugins", token, pkg)
	mustStatus(t, r, want, what)
	return r
}

// TestPluginLifecycle covers EXT-014: signed packages, declared permissions,
// second-administrator review, installation through the APIs' own
// validation, upgrade and rollback that keep part identities and secrets,
// atomic disable/enable, and uninstall.
func TestPluginLifecycle(t *testing.T) {
	e := newPluginEnv(t)
	h := e.H
	schemas := apiSchemas(t)
	manifest := map[string]any{"name": "hr-onboarding", "version": "1.0.0", "description": "HR integration", "permissions": hrPermissions,
		"requires": map[string]any{"hook_contract": []int{1}, "workflow_definition": []int{1}}}
	v1 := e.acme.pack(manifest, e.payload(1500, true, e.Roles["orders-viewer"]))
	var mdoc map[string]any
	raw, _ := base64.StdEncoding.DecodeString(v1["manifest"].(string))
	_ = json.Unmarshal(raw, &mdoc)
	if err := schemas.Validate("manifest.v1.json", mdoc); err != nil {
		t.Fatalf("manifest does not match the published schema: %v", err)
	}
	if err := schemas.Validate("package.v1.json", v1); err != nil {
		t.Fatalf("package does not match the published schema: %v", err)
	}

	t.Run("signature, digest and manifest checks", func(t *testing.T) {
		e.upload(t, e.AdminToken, e.rogue.pack(map[string]any{"name": "rogue", "version": "1.0.0", "permissions": hrPermissions},
			e.payload(1500, false, e.Roles["orders-viewer"])), 403, "untrusted publisher key")
		tampered := e.acme.pack(manifest, e.payload(1500, true, e.Roles["orders-viewer"]))
		tampered["payload"] = base64.StdEncoding.EncodeToString(asJSON(e.payload(5000, true, e.Roles["orders-viewer"])))
		e.upload(t, e.AdminToken, tampered, 403, "payload changed after signing")
		forged := e.acme.pack(manifest, e.payload(1500, true, e.Roles["orders-viewer"]))
		other := e.acme.pack(map[string]any{"name": "hr-onboarding", "version": "9.9.9", "permissions": hrPermissions}, e.payload(1500, true, e.Roles["orders-viewer"]))
		forged["manifest"] = other["manifest"]
		e.upload(t, e.AdminToken, forged, 403, "manifest changed after signing")
		e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"name": "hr-onboarding", "version": "1.0.0", "publisher": "someone-else", "permissions": hrPermissions},
			e.payload(1500, true, e.Roles["orders-viewer"])), 403, "publisher mismatch")
		e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"manifest_version": 2, "name": "hr-onboarding", "version": "1.0.0", "permissions": hrPermissions},
			e.payload(1500, true, e.Roles["orders-viewer"])), 422, "unsupported manifest version")
		incompatible := e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"name": "hr-onboarding", "version": "1.0.0", "permissions": hrPermissions,
			"requires": map[string]any{"hook_contract": []int{2}}}, e.payload(1500, true, e.Roles["orders-viewer"])), 422, "unsupported hook contract")
		if incompatible.Get("incompatible") != true {
			t.Fatalf("incompatibility not flagged: %s", incompatible.Raw)
		}
		e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"name": "hr-onboarding", "version": "1.0.0", "permissions": []string{"realm.hooks.write"}},
			e.payload(1500, true, e.Roles["orders-viewer"])), 422, "undeclared permissions")
		e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"name": "hr-onboarding", "version": "1.0.0", "permissions": append(hrPermissions, "realm.everything")},
			e.payload(1500, true, e.Roles["orders-viewer"])), 422, "unknown permission")
		bad := e.payload(1500, true, e.Roles["orders-viewer"])
		bad["hooks"].([]any)[0].(map[string]any)["kind"] = "shell.exec"
		r := e.upload(t, e.AdminToken, e.acme.pack(manifest, bad), 422, "invalid part")
		if !strings.Contains(string(r.Raw), "payload.hooks[0].kind") {
			t.Fatalf("part error not located: %s", r.Raw)
		}
		bad = e.payload(1500, true, e.Roles["orders-viewer"])
		bad["workflows"].([]any)[0].(map[string]any)["definition"].(map[string]any)["steps"] = []any{map[string]any{"id": "x", "type": "exec"}}
		e.upload(t, e.AdminToken, e.acme.pack(manifest, bad), 422, "invalid workflow part")
		// Bob holds none of the declared permissions.
		e.EnrollTOTP("bob")
		mgr := e.must(e.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "plugin-manager",
			"permissions": []string{"realm.plugins.manage", "realm.plugins.read"}}), 201, "role").Str("id")
		e.must(e.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": mgr, "subject": map[string]any{"type": "user", "id": e.Users["bob"]}}), 201, "assign")
		bob := e.AdminTokenFor("bob").Tokens.Str("access_token")
		e.upload(t, bob, v1, 403, "uploader lacks declared permissions")
	})

	var pluginID string
	var hookID, hookSecret, webhookID string
	t.Run("review and install", func(t *testing.T) {
		up := e.upload(t, e.AdminToken, v1, 201, "upload")
		pluginID = up.Str("plugin.id")
		if up.Str("version.status") != "pending_review" || up.Str("version.signing_key_id") != "acme-2026" || up.Str("plugin.state") != "inactive" {
			t.Fatalf("uploaded: %s", up.Raw)
		}
		e.upload(t, e.AdminToken, v1, 409, "same version twice")
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/1.0.0/install", nil), 403, "install before review")
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/1.0.0/approve", nil), 403, "self-approval")
		rev := h.API("GET", "/plugins/"+pluginID+"/versions/1.0.0", e.carol, nil)
		if rev.Status != 200 || rev.Get("payload.hooks") == nil {
			t.Fatalf("review view: %s", rev.Raw)
		}
		mustStatus(t, h.API("POST", "/plugins/"+pluginID+"/versions/1.0.0/approve", e.carol, map[string]any{"note": "reviewed"}), 200, "second administrator approves")
		inst := e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/1.0.0/install", nil), 200, "install")
		if inst.Str("plugin.state") != "enabled" || inst.Str("plugin.installed_version") != "1.0.0" {
			t.Fatalf("installed: %s", inst.Raw)
		}
		for _, s := range inst.Get("signing_secrets").([]any) {
			m := s.(map[string]any)
			switch m["kind"] {
			case "hook":
				hookID, hookSecret = m["part_id"].(string), m["secret"].(string)
			case "webhook":
				webhookID = m["part_id"].(string)
			}
		}
		if hookID == "" || webhookID == "" || !strings.HasPrefix(hookSecret, "hksec_") {
			t.Fatalf("installation secrets: %s", inst.Raw)
		}
		parts := e.must(e.AdminAPI("GET", "/plugins/"+pluginID, nil), 200, "plugin").Get("parts").(map[string]any)
		if len(parts["hooks"].([]any)) != 1 || len(parts["webhooks"].([]any)) != 1 || len(parts["workflows"].([]any)) != 1 {
			t.Fatalf("parts: %v", parts)
		}
		// The installed hook acts: a reserved display name is refused.
		bob := e.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Admin Bob"}), 422, "plugin hook refuses")
		calls := e.hookEP.received("/profile")
		if len(calls) == 0 || calls[len(calls)-1].Header.Get("ProudAuth-Hook-Version") != "1" {
			t.Fatal("plugin hook not called with the contract header")
		}
		// Parts change only with their plugin.
		hook := e.must(e.AdminAPI("GET", "/hooks/"+hookID, nil), 200, "hook")
		if hook.Str("plugin_id") != pluginID {
			t.Fatalf("hook not marked: %s", hook.Raw)
		}
		mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/hooks/" + hookID, Token: e.AdminToken, Headers: map[string]string{"If-Match": hook.Header.Get("ETag")},
			JSON: map[string]any{"name": "hr profile rules", "kind": "profile.validation", "url": e.hookEP.srv.URL + "/x", "allow_private_network": true}}), 409, "edit plugin hook")
		mustStatus(t, e.AdminAPI("DELETE", "/hooks/"+hookID, nil), 409, "delete plugin hook")
		mustStatus(t, e.AdminAPI("PATCH", "/webhooks/"+webhookID, map[string]any{"state": "paused"}), 409, "edit plugin webhook")
		wfID := parts["workflows"].([]any)[0].(map[string]any)["id"].(string)
		mustStatus(t, e.AdminAPI("POST", "/workflows/"+wfID+"/disable", nil), 409, "disable plugin workflow directly")
		wf := e.must(e.AdminAPI("GET", "/workflows/"+wfID, nil), 200, "plugin workflow")
		if wf.Str("state") != "active" || wf.Str("published_by_id") != e.Users["admin"] || wf.Str("plugin_id") != pluginID {
			t.Fatalf("plugin workflow: %s", wf.Raw)
		}
		if auditCount(t, h, "plugin.installed", pluginID) != 1 || auditCount(t, h, "plugin.version.approved", pluginID) != 1 {
			t.Fatal("installation not audited")
		}
	})

	t.Run("upgrade keeps parts and secrets, rollback restores", func(t *testing.T) {
		e.ReloginAdmin()
		e.carol = e.AdminTokenFor("carol").Tokens.Str("access_token")
		m2 := map[string]any{"name": "hr-onboarding", "version": "1.1.0", "permissions": hrPermissions}
		v2 := e.acme.pack(m2, e.payload(3000, false, e.Roles["orders-viewer"]))
		e.upload(t, e.AdminToken, v2, 201, "upload 1.1.0")
		mustStatus(t, h.API("POST", "/plugins/"+pluginID+"/versions/1.1.0/approve", e.carol, nil), 200, "approve 1.1.0")
		up := e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/1.1.0/install", nil), 200, "upgrade")
		if up.Str("plugin.installed_version") != "1.1.0" || up.Str("plugin.previous_version") != "1.0.0" || len(up.Get("signing_secrets").([]any)) != 0 {
			t.Fatalf("upgrade: %s", up.Raw)
		}
		parts := up.Get("plugin.parts").(map[string]any)
		hooks := parts["hooks"].([]any)
		if len(hooks) != 1 || hooks[0].(map[string]any)["id"] != hookID || len(parts["webhooks"].([]any)) != 0 {
			t.Fatalf("upgraded parts: %v", parts)
		}
		if hk := e.must(e.AdminAPI("GET", "/hooks/"+hookID, nil), 200, "hook"); hk.Get("timeout_ms").(float64) != 3000 {
			t.Fatalf("hook not upgraded: %s", hk.Raw)
		}
		// The hook still signs with its original secret.
		e.hookEP.reset()
		bob := e.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Bobby"}), 200, "profile with upgraded hook")
		c := e.hookEP.received("/profile")
		if len(c) != 1 || !validHookSignature(hookSecret, c[0]) {
			t.Fatal("upgraded hook does not sign with its original secret")
		}
		if auditCount(t, h, "plugin.upgraded", pluginID) != 1 {
			t.Fatal("upgrade not audited")
		}
		// Rollback: 1.0.0 again, without a new review; the webhook returns.
		rb := e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/rollback", nil), 200, "rollback")
		if rb.Str("plugin.installed_version") != "1.0.0" || rb.Str("plugin.previous_version") != "1.1.0" || len(rb.Get("plugin.parts.webhooks").([]any)) != 1 {
			t.Fatalf("rollback: %s", rb.Raw)
		}
		if rb.Get("plugin.parts.hooks").([]any)[0].(map[string]any)["id"] != hookID {
			t.Fatal("rollback replaced the hook")
		}
		if auditCount(t, h, "plugin.rolled_back", pluginID) != 1 {
			t.Fatal("rollback not audited")
		}
		versions := e.must(e.AdminAPI("GET", "/plugins/"+pluginID+"/versions", nil), 200, "versions")
		status := map[string]string{}
		for _, it := range versions.Get("items").([]any) {
			m := it.(map[string]any)
			status[m["version"].(string)] = m["status"].(string)
		}
		if status["1.0.0"] != "installed" || status["1.1.0"] != "superseded" {
			t.Fatalf("version statuses: %v", status)
		}
	})

	t.Run("disable stops every part at once", func(t *testing.T) {
		dis := e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/disable", map[string]any{"reason": "INCIDENT"}), 200, "disable")
		parts := dis.Get("parts").(map[string]any)
		for kind, list := range parts {
			for _, p := range list.([]any) {
				if p.(map[string]any)["state"] != "disabled" {
					t.Fatalf("%s part still %v", kind, p)
				}
			}
		}
		e.hookEP.reset()
		bob := e.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Admin Again"}), 200, "disabled hook not consulted")
		if len(e.hookEP.received("")) != 0 {
			t.Fatal("a disabled plugin's hook was called")
		}
		var category string
		_ = h.App.D.DB.Pool.QueryRow(bg(), `SELECT category FROM audit_events WHERE type='plugin.disabled' AND target_id=$1`, pluginID).Scan(&category)
		if category != "emergency" {
			t.Fatalf("disable category %q", category)
		}
		en := e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/enable", nil), 200, "enable")
		for _, list := range en.Get("parts").(map[string]any) {
			for _, p := range list.([]any) {
				if s := p.(map[string]any)["state"]; s != "active" {
					t.Fatalf("part after enable: %v", p)
				}
			}
		}
	})

	t.Run("dependencies", func(t *testing.T) {
		e.ReloginAdmin()
		e.carol = e.AdminTokenFor("carol").Tokens.Str("access_token")
		child := e.acme.pack(map[string]any{"name": "hr-reports", "version": "1.0.0", "permissions": []string{"realm.webhooks.write"},
			"dependencies": []any{map[string]any{"name": "hr-onboarding", "min_version": "1.1.0"}}},
			map[string]any{"webhooks": []any{map[string]any{"name": "hr reports", "destination_url": e.hookEP.srv.URL + "/reports",
				"event_types": []string{"user.deleted"}, "allow_private_network": true}}})
		cid := e.upload(t, e.AdminToken, child, 201, "upload child").Str("plugin.id")
		mustStatus(t, h.API("POST", "/plugins/"+cid+"/versions/1.0.0/approve", e.carol, nil), 200, "approve child")
		if r := e.AdminAPI("POST", "/plugins/"+cid+"/versions/1.0.0/install", nil); r.Status != 409 || r.Str("missing_dependency") != "hr-onboarding" {
			t.Fatalf("installed with an old dependency: %d %s", r.Status, r.Raw)
		}
		e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/1.1.0/install", nil), 200, "upgrade the dependency")
		e.must(e.AdminAPI("POST", "/plugins/"+cid+"/versions/1.0.0/install", nil), 200, "install child")
		if r := e.AdminAPI("POST", "/plugins/"+pluginID+"/rollback", nil); r.Status != 409 || r.Str("dependent") != "hr-reports" {
			t.Fatalf("rolled back below a dependent's minimum: %d %s", r.Status, r.Raw)
		}
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+pluginID+"/disable", nil), 409, "disable a dependency")
		mustStatus(t, e.AdminAPI("DELETE", "/plugins/"+pluginID, nil), 409, "uninstall a dependency")
		e.must(e.AdminAPI("POST", "/plugins/"+cid+"/disable", nil), 200, "disable child")
		un := e.must(e.AdminAPI("DELETE", "/plugins/"+pluginID, nil), 200, "uninstall")
		if un.Str("state") != "inactive" || len(un.Get("parts.hooks").([]any)) != 0 || len(un.Get("parts.webhooks").([]any)) != 0 {
			t.Fatalf("uninstalled: %s", un.Raw)
		}
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+cid+"/enable", nil), 409, "enable without its dependency")
	})

	t.Run("trust is re-checked at installation", func(t *testing.T) {
		m3 := map[string]any{"name": "hr-onboarding", "version": "2.0.0", "permissions": hrPermissions}
		e.upload(t, e.AdminToken, e.acme.pack(m3, e.payload(1500, false, e.Roles["orders-viewer"])), 201, "upload 2.0.0")
		mustStatus(t, h.API("POST", "/plugins/"+pluginID+"/versions/2.0.0/approve", e.carol, nil), 200, "approve 2.0.0")
		saved := h.Cfg.Extensions.PluginPublishers
		h.Cfg.Extensions.PluginPublishers = nil
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/2.0.0/install", nil), 403, "publisher key withdrawn")
		h.Cfg.Extensions.PluginPublishers = []configuration.PluginPublisherKey{{KeyID: saved[0].KeyID, Publisher: saved[0].Publisher,
			PublicKey: saved[0].PublicKey, NotAfter: h.Clock.Now().Add(-time.Minute).Format(time.RFC3339)}}
		mustStatus(t, e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/2.0.0/install", nil), 403, "publisher key expired")
		h.Cfg.Extensions.PluginPublishers = saved
		e.must(e.AdminAPI("POST", "/plugins/"+pluginID+"/versions/2.0.0/install", nil), 200, "install with the key restored")
	})
}

// TestPluginSingleAdminReview: a realm that explicitly allows it installs
// without a second review, and records the policy with the installation.
func TestPluginSingleAdminReview(t *testing.T) {
	e := newPluginEnv(t, func(p *realm.Policy) { p.Extensions.PluginReview = realm.PluginReviewSingleAdmin })
	up := e.upload(t, e.AdminToken, e.acme.pack(map[string]any{"name": "solo", "version": "0.1.0", "permissions": []string{"realm.hooks.write"}},
		map[string]any{"hooks": []any{map[string]any{"name": "solo rules", "kind": "profile.validation", "url": e.hookEP.srv.URL + "/solo",
			"allow_private_network": true}}}), 201, "upload")
	if up.Str("version.status") != "approved" || up.Str("version.reviewed_by_id") != e.Users["admin"] {
		t.Fatalf("single-admin upload: %s", up.Raw)
	}
	e.must(e.AdminAPI("POST", "/plugins/"+up.Str("plugin.id")+"/versions/0.1.0/install", nil), 200, "install")
	var review string
	_ = e.H.App.D.DB.Pool.QueryRow(bg(), `SELECT metadata->>'review' FROM audit_events WHERE type='plugin.installed'`).Scan(&review)
	if review != realm.PluginReviewSingleAdmin {
		t.Fatalf("review mode not recorded: %q", review)
	}
	// Another publisher cannot ship versions of this plugin name.
	other := newPublisher(t, "acme-2027", "acme-labs")
	e.H.Cfg.Extensions.PluginPublishers = append(e.H.Cfg.Extensions.PluginPublishers, other.trusted())
	e.upload(t, e.AdminToken, other.pack(map[string]any{"name": "solo", "version": "0.2.0", "permissions": []string{"realm.hooks.write"}},
		map[string]any{"hooks": []any{map[string]any{"name": "solo rules", "kind": "profile.validation", "url": e.hookEP.srv.URL + "/solo",
			"allow_private_network": true}}}), 409, "name taken by another publisher")
	r := e.SetPolicy(func(p *realm.Policy) { p.Extensions.PluginReview = "nobody" })
	mustStatus(t, r, 422, "unknown review mode")
}

// TestPluginPartStates covers part states across plugin upgrades and
// enable: a workflow a new version drops stays retired (disabled) after the
// upgrade and after the plugin is enabled again; a hook an administrator
// switched off in an emergency stays off until they turn it back on; and
// enabling re-checks the publisher key like an installation.
func TestPluginPartStates(t *testing.T) {
	e := newPluginEnv(t)
	h := e.H
	ctx := e.ctx()
	release := func(version string, payload map[string]any) string {
		t.Helper()
		pkg := e.acme.pack(map[string]any{"name": "hr-parts", "version": version, "permissions": hrPermissions,
			"requires": map[string]any{"hook_contract": []int{1}, "workflow_definition": []int{1}}}, payload)
		id := e.upload(t, e.AdminToken, pkg, 201, "upload "+version).Str("plugin.id")
		mustStatus(t, h.API("POST", "/plugins/"+id+"/versions/"+version+"/approve", e.carol, nil), 200, "approve "+version)
		e.must(e.AdminAPI("POST", "/plugins/"+id+"/versions/"+version+"/install", nil), 200, "install "+version)
		return id
	}
	id := release("1.0.0", e.payload(1500, false, e.Roles["orders-viewer"]))
	var wfID, hookID string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM workflows WHERE plugin_id=$1`, id).Scan(&wfID)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM hooks WHERE plugin_id=$1`, id).Scan(&hookID)
	// The workflow runs once, so a later version keeps it as evidence.
	e.must(e.AdminAPI("POST", "/workflows/"+wfID+"/runs", map[string]any{"subject_id": e.Users["bob"], "organization_id": e.Acme}), 202, "run")
	e.must(e.AdminAPI("POST", "/emergency/controls", map[string]any{"target_type": "hook", "target_id": hookID, "action": "disable",
		"reason": "INCIDENT"}), 200, "switch the hook off")
	state := func(table, id string) string {
		var s string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM `+table+` WHERE id=$1`, id).Scan(&s)
		return s
	}
	v2 := e.payload(1500, false, e.Roles["orders-viewer"])
	delete(v2, "workflows")
	release("1.1.0", v2)
	if state("workflows", wfID) != "disabled" || state("hooks", hookID) != "disabled" {
		t.Fatalf("after upgrade: workflow %s, hook %s", state("workflows", wfID), state("hooks", hookID))
	}
	e.must(e.AdminAPI("POST", "/plugins/"+id+"/disable", nil), 200, "disable plugin")
	e.must(e.AdminAPI("POST", "/plugins/"+id+"/enable", nil), 200, "enable plugin")
	if state("workflows", wfID) != "disabled" || state("hooks", hookID) != "disabled" {
		t.Fatalf("after enable: workflow %s, hook %s", state("workflows", wfID), state("hooks", hookID))
	}
	if n := auditCount(t, h, "workflow.disabled", wfID); n != 1 {
		t.Fatalf("retired workflow disabled %d times", n)
	}
	e.must(e.AdminAPI("POST", "/emergency/controls", map[string]any{"target_type": "hook", "target_id": hookID, "action": "enable",
		"reason": "RESOLVED"}), 200, "switch the hook back on")
	if state("hooks", hookID) != "active" {
		t.Fatalf("hook after the emergency control was lifted: %s", state("hooks", hookID))
	}
	// A plugin whose publisher key was removed cannot be enabled again.
	e.must(e.AdminAPI("POST", "/plugins/"+id+"/disable", nil), 200, "disable plugin")
	saved := h.App.D.Cfg.Extensions.PluginPublishers
	h.App.D.Cfg.Extensions.PluginPublishers = nil
	defer func() { h.App.D.Cfg.Extensions.PluginPublishers = saved }()
	if r := e.AdminAPI("POST", "/plugins/"+id+"/enable", nil); r.Status != 403 {
		t.Fatalf("enabled with its publisher key removed: %d %s", r.Status, r.Raw)
	}
}
