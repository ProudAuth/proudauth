package e2e

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/worker"
)

// TestMembershipMetadata covers USR-009's organization membership metadata:
// an organization administrator (org.members.write) sets it through the
// member endpoints with merge semantics (null removes a key), bounded by
// limits.metadata_bytes; it is returned by the member GET, list and PATCH to
// those who manage members, never to a reader holding only
// org.members.read, never in the member's own views or tokens, and never
// across organization boundaries; the change is audited with key names
// only; the realm data export carries it; and it is erased with the
// membership and with the account.
func TestMembershipMetadata(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	carol := f.AccountToken("carol").Tokens.Str("access_token") // globex organization admin
	alice := f.AccountToken("alice").Tokens.Str("access_token") // acme owner
	bobG, bobA := f.MemberGlobex["bob"], f.MemberAcme["bob"]
	member := func(org, id string) string { return "/organizations/" + org + "/members/" + id }
	metaOf := func(r *Resp) map[string]any {
		t.Helper()
		m, _ := r.Get("metadata").(map[string]any)
		if m == nil {
			m, _ = r.Get("membership.metadata").(map[string]any)
		}
		return m
	}

	// Set by the organization's administrator; the PATCH answers with it.
	set := f.must(h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{"metadata": map[string]any{
		"cost_center": "CC-4242", "badge": 7, "desk": "B-12"}}), 200, "set membership metadata")
	if m := metaOf(set); m["cost_center"] != "CC-4242" || m["badge"] != float64(7) || set.Str("state") != "active" {
		t.Fatalf("PATCH response: %s", set.Raw)
	}
	// Merge: null removes a key, other keys stay; state can change in the same call.
	set = f.must(h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{"metadata": map[string]any{"desk": nil, "badge": 8}}), 200, "merge")
	if m := metaOf(set); m["desk"] != nil || m["badge"] != float64(8) || m["cost_center"] != "CC-4242" {
		t.Fatalf("merge semantics: %s", set.Raw)
	}
	// Read back through GET and list.
	if m := metaOf(f.must(h.API("GET", member(f.Globex, bobG), carol, nil), 200, "get member")); m["cost_center"] != "CC-4242" {
		t.Fatal("GET member does not return the metadata")
	}
	list := f.must(h.API("GET", "/organizations/"+f.Globex+"/members", carol, nil), 200, "list members")
	found := false
	for _, it := range list.Get("items").([]any) {
		if m := it.(map[string]any); m["id"] == bobG {
			md, _ := m["metadata"].(map[string]any)
			found = md["cost_center"] == "CC-4242"
		}
	}
	if !found {
		t.Fatalf("list does not return the metadata: %s", list.Raw)
	}
	// Validation: a JSON object within limits.metadata_bytes.
	mustStatus(t, h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{"metadata": map[string]any{"blob": strings.Repeat("x", 17000)}}),
		422, "metadata above limits.metadata_bytes")
	if r := h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{"metadata": "not an object"}); r.Status < 400 || r.Status >= 500 {
		t.Fatalf("non-object metadata: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{}), 422, "nothing to change")

	// Organization boundaries: acme's owner cannot read or write globex's
	// metadata, through either organization's path, and carol cannot reach
	// bob's acme membership.
	for _, c := range []struct {
		name, method, path, token string
	}{
		{"acme owner reads globex member", "GET", member(f.Globex, bobG), alice},
		{"acme owner writes globex member", "PATCH", member(f.Globex, bobG), alice},
		{"acme owner writes globex member through acme", "PATCH", member(f.Acme, bobG), alice},
		{"acme owner reads globex member through acme", "GET", member(f.Acme, bobG), alice},
		{"globex admin writes acme member", "PATCH", member(f.Acme, bobA), carol},
		{"globex admin writes acme member through globex", "PATCH", member(f.Globex, bobA), carol},
		{"globex admin reads acme member through globex", "GET", member(f.Globex, bobA), carol},
	} {
		var body any
		if c.method == "PATCH" {
			body = map[string]any{"metadata": map[string]any{"cost_center": "STOLEN"}}
		}
		r := h.API(c.method, c.path, c.token, body)
		if r.Status != 403 && r.Status != 404 {
			t.Fatalf("%s: %d %s", c.name, r.Status, r.Raw)
		}
		if bytes.Contains(r.Raw, []byte("CC-4242")) {
			t.Fatalf("%s disclosed the metadata: %s", c.name, r.Raw)
		}
	}
	var acmeMeta, globexMeta string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT (SELECT metadata::text FROM memberships WHERE id=$1), (SELECT metadata::text FROM memberships WHERE id=$2)`,
		bobA, bobG).Scan(&acmeMeta, &globexMeta); err != nil {
		t.Fatal(err)
	}
	if acmeMeta != "{}" || strings.Contains(globexMeta, "STOLEN") {
		t.Fatalf("cross-organization write: acme=%s globex=%s", acmeMeta, globexMeta)
	}

	// A reader who can list members but not manage them does not see it.
	roster := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "roster-viewer",
		"permissions": []string{"org.read", "org.members.read"}}), 201, "roster role").Str("id")
	f.CreateUser("rita")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/members", map[string]any{"user_id": f.Users["rita"], "role_ids": []string{roster}}), 201, "rita joins")
	rita := f.AccountToken("rita").Tokens.Str("access_token")
	for _, r := range []*Resp{
		f.must(h.API("GET", "/organizations/"+f.Globex+"/members", rita, nil), 200, "reader lists"),
		f.must(h.API("GET", member(f.Globex, bobG), rita, nil), 200, "reader gets"),
	} {
		if bytes.Contains(r.Raw, []byte(`"metadata"`)) || bytes.Contains(r.Raw, []byte("CC-4242")) {
			t.Fatalf("membership metadata shown to a reader without org.members.write: %s", r.Raw)
		}
	}
	mustStatus(t, h.API("PATCH", member(f.Globex, bobG), rita, map[string]any{"metadata": map[string]any{"x": 1}}), 403, "reader writes")

	// Separate from the member's own data: not in bob's profile, his
	// organization list, or his tokens.
	bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
	for _, p := range []string{"/me", "/organizations"} {
		if r := f.must(h.API("GET", p, bobAcct, nil), 200, "bob reads "+p); bytes.Contains(r.Raw, []byte("CC-4242")) {
			t.Fatalf("membership metadata in the member's own view %s: %s", p, r.Raw)
		}
	}
	web := f.LoginWeb("bob", f.Globex, f.OrdersAud, "openid orders:read").Tokens
	if bytes.Contains(web.Raw, []byte("CC-4242")) || strings.Contains(jsonString(jwtPayload(web.Str("access_token"))), "CC-4242") ||
		strings.Contains(jsonString(jwtPayload(web.Str("id_token"))), "CC-4242") {
		t.Fatalf("membership metadata in tokens: %s", web.Raw)
	}
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, web.Str("access_token")); bytes.Contains(in.Raw, []byte("CC-4242")) {
		t.Fatalf("membership metadata at introspection: %s", in.Raw)
	}

	// Audited with key names only.
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=organization.membership.metadata_updated", nil), 200, "audit")
	if items, _ := ev.Get("items").([]any); len(items) != 2 || !bytes.Contains(ev.Raw, []byte("cost_center")) ||
		bytes.Contains(ev.Raw, []byte("CC-4242")) || bytes.Contains(ev.Raw, []byte("STOLEN")) {
		t.Fatalf("metadata audit (keys, never values; refused writes not recorded): %s", ev.Raw)
	}

	// The realm data export carries it with the membership.
	w := worker.New(h.App, "test")
	job := f.must(f.AdminAPI("POST", "/data-exports", map[string]any{}), 202, "realm export")
	if data := gapDownload(t, f, w, job.Str("job_id")); !bytes.Contains(data.Raw, []byte("CC-4242")) {
		t.Fatal("realm export lacks the membership metadata")
	}

	// Erased with the membership...
	mustStatus(t, h.API("DELETE", member(f.Globex, bobG), carol, nil), 204, "remove bob from globex")
	var after string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text FROM memberships WHERE id=$1`, bobG).Scan(&after); err != nil || after != "{}" {
		t.Fatalf("metadata kept after removal: %q %v", after, err)
	}
	mustStatus(t, h.API("PATCH", member(f.Globex, bobG), carol, map[string]any{"metadata": map[string]any{"x": 1}}), 409, "metadata on a removed membership")
	// ...and with the account.
	ritaMembership := ""
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM memberships WHERE user_id=$1 AND organization_id=$2 AND state='active'`, f.Users["rita"], f.Globex).Scan(&ritaMembership)
	f.must(h.API("PATCH", member(f.Globex, ritaMembership), carol, map[string]any{"metadata": map[string]any{"contractor_agency": "Initech"}}), 200, "rita's metadata")
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["rita"], nil), 204, "delete rita")
	var kept int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE user_id=$1 AND metadata <> '{}'::jsonb`, f.Users["rita"]).Scan(&kept)
	if kept != 0 {
		t.Fatalf("membership metadata survived the account's deletion: %d", kept)
	}
}
