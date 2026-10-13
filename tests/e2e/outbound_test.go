package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/worker"
)

// fakeSCIM is a downstream SCIM 2.0 service recording what it receives.
type fakeSCIM struct {
	mu       sync.Mutex
	srv      *httptest.Server
	token    string
	seq      int
	users    map[string]map[string]any
	groups   map[string]map[string]any
	requests []string
	failNext int // answer the next N writes with 503
	auths    []string
	accepts  []string
}

func newFakeSCIM(t *testing.T, token string) *fakeSCIM {
	f := &fakeSCIM{token: token, users: map[string]map[string]any{}, groups: map[string]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSCIM) write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (f *fakeSCIM) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.accepts = append(f.accepts, r.Header.Get("Accept"))
	// Like ZITADEL v4, refuse an Accept header listing several media types
	// (docs/integrations/outbound-provisioning.md, "Tested downstream services").
	if strings.Contains(r.Header.Get("Accept"), ",") {
		f.write(w, 400, map[string]any{"status": "400", "scimType": "invalidValue", "detail": "Invalid accept header"})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.write(w, 401, map[string]any{"status": "401"})
		return
	}
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	if r.Method != http.MethodGet && f.failNext > 0 {
		f.failNext--
		f.write(w, 503, map[string]any{"status": "503"})
		return
	}
	var doc map[string]any
	if b, _ := io.ReadAll(r.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &doc)
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	coll := map[string]map[string]map[string]any{"Users": f.users, "Groups": f.groups}[parts[0]]
	if parts[0] == "ServiceProviderConfig" {
		f.write(w, 200, map[string]any{"patch": map[string]any{"supported": true}})
		return
	}
	if coll == nil {
		f.write(w, 404, nil)
		return
	}
	id := ""
	if len(parts) > 1 {
		id = parts[1]
	}
	switch {
	case r.Method == http.MethodGet && id == "":
		var list []any
		filter := r.URL.Query().Get("filter")
		for _, d := range coll {
			if filter != "" && !strings.Contains(filter, `"`+str(d["externalId"])+`"`) {
				continue
			}
			list = append(list, d)
		}
		f.write(w, 200, map[string]any{"totalResults": len(list), "Resources": list, "startIndex": 1, "itemsPerPage": len(list)})
	case r.Method == http.MethodPost:
		key := "userName"
		if parts[0] == "Groups" {
			key = "displayName"
		}
		for _, d := range coll {
			if strings.EqualFold(str(d[key]), str(doc[key])) {
				f.write(w, 409, map[string]any{"status": "409", "scimType": "uniqueness"})
				return
			}
		}
		f.seq++
		doc["id"] = "r" + strconv.Itoa(f.seq)
		coll[doc["id"].(string)] = doc
		f.write(w, 201, doc)
	case coll[id] == nil:
		f.write(w, 404, map[string]any{"status": "404"})
	case r.Method == http.MethodGet:
		f.write(w, 200, coll[id])
	case r.Method == http.MethodPut:
		doc["id"] = id
		coll[id] = doc
		f.write(w, 200, doc)
	case r.Method == http.MethodPatch:
		ops, _ := doc["Operations"].([]any)
		for _, o := range ops {
			op := o.(map[string]any)
			if op["path"] == "active" {
				coll[id]["active"] = op["value"]
			}
		}
		f.write(w, 200, coll[id])
	case r.Method == http.MethodDelete:
		delete(coll, id)
		w.WriteHeader(204)
	}
}

func str(v any) string { s, _ := v.(string); return s }

func (f *fakeSCIM) byExternal(ext string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, d := range f.users {
		if d["externalId"] == ext {
			return d
		}
	}
	return nil
}

func (f *fakeSCIM) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// TestOutboundProvisioning covers PROV-010, PROV-017 and PROV-018: an
// organization's outbound connector pushes its eligible members' lifecycle
// (create, update, deactivate) from the outbox and a change scan, with the
// encrypted bearer token, retries with backoff, dead-lettering and replay,
// idempotent adoption of its own earlier resources, group pushes,
// reconciliation reports that never delete foreign resources, tenant
// isolation, and operational evidence without the credential.
func TestOutboundProvisioning(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "out-worker")
	down := newFakeSCIM(t, "downstream token")
	// A group whose members are pushed with it.
	grp := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "Engineering"}), 201, "group").Str("id")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups/"+grp+"/members", map[string]any{"membership_id": f.MemberAcme["alice"]}), 204, "group member")

	path := "/organizations/" + f.Acme + "/directory-connectors"
	// Destinations pass the egress policy: a private destination needs the
	// connector's opt-in on top of the operator policy (EXT-007).
	if r := f.AdminAPI("POST", path, map[string]any{"name": "Downstream", "kind": "scim_outbound", "credential": "downstream token",
		"config": map[string]any{"base_url": down.srv.URL}}); r.Status != 422 {
		t.Fatalf("private destination without opt-in: %d %s", r.Status, r.Raw)
	}
	if r := f.AdminAPI("POST", path, map[string]any{"name": "Downstream", "kind": "scim_outbound", "credential": "downstream token",
		"config": map[string]any{"base_url": down.srv.URL, "allow_private_network": true, "eligible_organization_ids": []string{f.Globex}}}); r.Status != 422 {
		t.Fatalf("organization connector reaching another organization: %d %s", r.Status, r.Raw)
	}
	created := f.must(f.AdminAPI("POST", path, map[string]any{"name": "Downstream", "kind": "scim_outbound", "credential": "downstream token",
		"config": map[string]any{"base_url": down.srv.URL, "allow_private_network": true, "max_attempts": 3, "push_group_ids": []string{grp}}}), 201, "outbound connector")
	connID := created.Str("id")
	cpath := path + "/" + connID
	if strings.Contains(string(created.Raw), "downstream token") {
		t.Fatal("token in the connector view")
	}

	// The first scheduler pass reconciles: every eligible member is created
	// downstream with externalId = the local account ID.
	runWorker(t, w)
	runWorker(t, w)
	alice, bob := down.byExternal(f.Users["alice"]), down.byExternal(f.Users["bob"])
	if alice == nil || bob == nil || alice["active"] != true || alice["userName"] != "alice" {
		t.Fatalf("initial push: %v", down.reqs())
	}
	if down.byExternal(f.Users["carol"]) != nil {
		t.Fatal("a Globex-only account was pushed by an Acme connector")
	}
	for _, a := range down.auths {
		if a != "Bearer downstream token" {
			t.Fatalf("authorization: %q", a)
		}
	}
	// One SCIM media type in Accept (RFC 7644 section 8.1); ZITADEL v4
	// answers a list with 400.
	for _, a := range down.accepts {
		if a != "application/scim+json" {
			t.Fatalf("Accept: %q", a)
		}
	}
	down.mu.Lock()
	ngroups := len(down.groups)
	var gmembers []any
	for _, g := range down.groups {
		gmembers, _ = g["members"].([]any)
	}
	down.mu.Unlock()
	if ngroups != 1 || len(gmembers) != 1 || gmembers[0].(map[string]any)["value"] != alice["id"] {
		t.Fatalf("group push: %d groups, members %v", ngroups, gmembers)
	}

	// A profile edit (no outbox event) reaches the downstream through the
	// change scan; an unchanged account is not written again.
	before := len(down.reqs())
	h.Clock.Advance(time.Second)
	f.must(f.AdminAPI("PATCH", "/users/"+f.Users["alice"], map[string]any{"given_name": "Alicia"}), 200, "edit")
	runWorker(t, w)
	if a := down.byExternal(f.Users["alice"]); a["name"].(map[string]any)["givenName"] != "Alicia" {
		t.Fatalf("update not pushed: %v", a)
	}
	puts := 0
	for _, r := range down.reqs()[before:] {
		if strings.HasPrefix(r, "PUT /Users/") {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("expected exactly one update, got %v", down.reqs()[before:])
	}
	// An email change (a new address, verified, made primary) edits no
	// profile field and publishes no outbox event; the change scan still
	// finds it, and only the verified primary address is pushed (found
	// missing by the ZITADEL interoperability run).
	primaryEmail := func() string {
		a := down.byExternal(f.Users["alice"])
		down.mu.Lock()
		defer down.mu.Unlock()
		emails, _ := a["emails"].([]any)
		if len(emails) != 1 {
			return ""
		}
		v, _ := emails[0].(map[string]any)["value"].(string)
		return v
	}
	const reason = "address change requested by the owner, ticket 7"
	h.Clock.Advance(time.Second)
	addr := f.must(f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/identifiers", map[string]any{"type": "email", "value": "alice.l@example.test",
		"reason": reason}), 201, "add address").Str("id")
	runWorker(t, w)
	if e := primaryEmail(); e != "alice@example.test" {
		t.Fatalf("after adding an unverified address, downstream email %q", e)
	}
	h.Clock.Advance(time.Second)
	f.must(f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/verification-overrides", map[string]any{"identifier_id": addr, "reason": reason}), 204, "verify")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/identifiers/"+addr+"/primary", map[string]any{"reason": reason}), 204, "make primary")
	runWorker(t, w)
	if e := primaryEmail(); e != "alice.l@example.test" {
		t.Fatalf("email change not pushed: downstream email %q", e)
	}

	// Removing bob from Acme deactivates him downstream (outbox event).
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+f.MemberAcme["bob"], nil), 204, "remove member")
	runWorker(t, w)
	if b := down.byExternal(f.Users["bob"]); b["active"] != false {
		t.Fatalf("deactivation not pushed: %v", b)
	}

	// Retries with backoff, then dead-letter; replay delivers.
	down.mu.Lock()
	down.failNext = 100
	down.mu.Unlock()
	h.Clock.Advance(time.Second)
	f.must(f.AdminAPI("PATCH", "/users/"+f.Users["alice"], map[string]any{"family_name": "Liddell"}), 200, "edit")
	runWorker(t, w)
	dl := f.must(f.AdminAPI("GET", cpath+"/deliveries?state=retrying", nil), 200, "deliveries")
	items := dl.Get("items").([]any)
	if len(items) != 1 || items[0].(map[string]any)["last_error_category"] != "server_error" {
		t.Fatalf("retrying delivery: %s", dl.Raw)
	}
	deliveryID := items[0].(map[string]any)["id"].(string)
	// Backoff doubles from 10s (with jitter); the third attempt is the last.
	for i := 0; i < 3; i++ {
		h.Clock.Advance(40 * time.Second)
		runWorker(t, w)
	}
	dl = f.must(f.AdminAPI("GET", cpath+"/deliveries?state=dead_letter", nil), 200, "dead letters")
	if items := dl.Get("items").([]any); len(items) != 1 || items[0].(map[string]any)["id"] != deliveryID {
		t.Fatalf("dead letter: %s", dl.Raw)
	}
	health := f.must(f.AdminAPI("GET", cpath+"/health", nil), 200, "health")
	if health.Str("status") != "degraded" || health.Get("deliveries.dead_letter") != float64(1) {
		t.Fatalf("health: %s", health.Raw)
	}
	down.mu.Lock()
	down.failNext = 0
	down.mu.Unlock()
	if r := f.AdminAPI("POST", cpath+"/deliveries/"+deliveryID+"/replay", nil); r.Status != 202 {
		t.Fatalf("replay: %d %s", r.Status, r.Raw)
	}
	if r := f.AdminAPI("POST", cpath+"/deliveries/"+deliveryID+"/replay", nil); r.Status != 409 {
		t.Fatalf("second replay: %d", r.Status)
	}
	runWorker(t, w)
	if a := down.byExternal(f.Users["alice"]); a["name"].(map[string]any)["familyName"] != "Liddell" {
		t.Fatalf("replayed delivery: %v", a)
	}

	// Idempotency: a resource created by an attempt whose response was lost
	// is adopted by its externalId, never duplicated.
	dana := f.CreateUser("dana")
	down.mu.Lock()
	down.seq++
	lost := "r" + strconv.Itoa(down.seq)
	down.users[lost] = map[string]any{"id": lost, "userName": "dana", "externalId": dana, "active": true}
	down.mu.Unlock()
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": dana, "role_ids": []string{}}), 201, "add dana")
	runWorker(t, w)
	down.mu.Lock()
	danas := 0
	for _, d := range down.users {
		if d["externalId"] == dana {
			danas++
		}
	}
	down.mu.Unlock()
	if danas != 1 {
		t.Fatalf("duplicate downstream resources: %d", danas)
	}
	var mapped string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT external_id FROM connector_external_ids WHERE connector_id=$1 AND local_id=$2`, connID, dana).Scan(&mapped)
	if mapped != lost {
		t.Fatalf("lost resource not adopted: %q", mapped)
	}
	// A downstream account with the same userName that this connector did
	// not create is never taken over.
	erin := f.CreateUser("erin")
	down.mu.Lock()
	down.users["foreign"] = map[string]any{"id": "foreign", "userName": "erin", "externalId": "someone-else", "active": true}
	down.mu.Unlock()
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": erin, "role_ids": []string{}}), 201, "add erin")
	runWorker(t, w)
	dl = f.must(f.AdminAPI("GET", cpath+"/deliveries?state=dead_letter", nil), 200, "dead letters")
	conflict := false
	for _, it := range dl.Get("items").([]any) {
		m := it.(map[string]any)
		if m["local_id"] == erin && m["last_error_category"] == "conflict" {
			conflict = true
		}
	}
	if !conflict {
		t.Fatalf("foreign resource conflict: %s", dl.Raw)
	}

	// Reconciliation reports drift and lost resources, repairs what it
	// manages and never deletes what it did not create (PROV-017).
	down.mu.Lock()
	delete(down.users, alice["id"].(string))
	down.users[mapped]["active"] = false // drift on dana
	down.mu.Unlock()
	dry := f.dirRun(t, w, cpath, map[string]any{"mode": "reconcile", "dry_run": true})
	if dry.Str("state") != "succeeded" || count(dry, "missing_remote") < 1 || count(dry, "drift") < 1 || count(dry, "unmanaged_remote") != 1 {
		t.Fatalf("reconciliation plan: %s", dry.Raw)
	}
	if down.byExternal(f.Users["alice"]) != nil {
		t.Fatal("dry run repaired the downstream")
	}
	run := f.dirRun(t, w, cpath, map[string]any{"mode": "reconcile"})
	runWorker(t, w)
	if run.Str("state") != "succeeded" || down.byExternal(f.Users["alice"]) == nil || down.byExternal(dana)["active"] != true {
		t.Fatalf("reconciliation: %s", run.Raw)
	}
	down.mu.Lock()
	_, foreignKept := down.users["foreign"]
	down.mu.Unlock()
	if !foreignKept {
		t.Fatal("reconciliation deleted a resource it did not create")
	}

	// Evidence: counts, last delivery and operator actions; never the token.
	health = f.must(f.AdminAPI("GET", cpath+"/health", nil), 200, "health")
	actions := health.Get("operator_actions").([]any)
	if health.Get("last_delivered_at") == nil || health.Get("deliveries.delivered") == float64(0) || len(actions) < 2 {
		t.Fatalf("evidence: %s", health.Raw)
	}
	for _, p := range []string{cpath, cpath + "/health", cpath + "/deliveries", cpath + "/runs"} {
		if r := f.AdminAPI("GET", p, nil); strings.Contains(string(r.Raw), "downstream token") {
			t.Fatalf("%s leaks the token", p)
		}
	}
	var leaked int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%downstream token%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("token in audit evidence")
	}
	// Rotating the credential: the old token stops being used.
	f.must(f.AdminAPI("PUT", cpath+"/credential", map[string]any{"credential": "rotated token"}), 200, "rotate")
	down.mu.Lock()
	down.token = "rotated token"
	down.mu.Unlock()
	if r := f.must(f.AdminAPI("POST", cpath+"/test", nil), 200, "test"); r.Get("ok") != true {
		t.Fatalf("test after rotation: %s", r.Raw)
	}
}
