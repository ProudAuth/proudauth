package bench

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"time"
)

// scimLifecycle measures a completed create/read/update/delete/read cycle
// (NFR-003). Each worker has a distinct organization-bound connector. Five
// requests per cycle and >=300ms between cycle starts stay below the unchanged
// 1200/minute connector budget; pacing is INCLUDED in operation latency.
type scimLifecycle struct {
	clients []scimWorker
	prefix  string
}
type scimWorker struct {
	token    string
	sequence uint64
	next     time.Time
}

func (*scimLifecycle) Name() string { return "scim" }
func (s *scimLifecycle) Notes() []string {
	return []string{fmt.Sprintf("%d additional isolated connectors in the large organization, one per worker; default 1200 requests/minute per connector unchanged", len(s.clients)),
		"one operation: SCIM user create, read, ETag-bound displayName patch, delete, and read expecting 404; no email or existing-user adoption",
		"cycle starts paced >=300ms apart per connector (<=1000 requests/minute); pacing is included in latency, so this measures a budgeted lifecycle workload rather than saturation throughput"}
}

func (s *scimLifecycle) Prepare(ctx context.Context, e *Env) error {
	if e.Concurrency < 1 || e.Seed.RoleID == "" {
		return fmt.Errorf("scim needs a freshly generated seed with the organization role ID")
	}
	var err error
	s.prefix, err = runPrefix(e.Seed, "scim")
	if err != nil {
		return err
	}
	s.clients = nil
	for i := 0; i < e.Concurrency; i++ {
		r, err := e.Client.API(ctx, "POST", "/organizations/"+e.Seed.LargeOrgID+"/provisioning-connectors", e.adminToken(ctx),
			map[string]any{"name": fmt.Sprintf("%s-%d", s.prefix, i), "role_ceiling_ids": []string{e.Seed.RoleID}, "default_role_id": e.Seed.RoleID})
		if _, err := Must(r, err, 201, "benchmark SCIM connector"); err != nil {
			return err
		}
		if r.Str("token") == "" {
			return fmt.Errorf("SCIM connector has no token")
		}
		s.clients = append(s.clients, scimWorker{token: r.Str("token")})
	}
	return nil
}

func (s *scimLifecycle) Op(ctx context.Context, e *Env, worker int, _ *mrand.Rand) string {
	if worker < 0 || worker >= len(s.clients) {
		return "setup_missing_connector"
	}
	c := &s.clients[worker] // Run invokes one operation at a time per worker.
	if wait := time.Until(c.next); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return "transport_error"
		case <-timer.C:
		}
	}
	c.next = time.Now().Add(300 * time.Millisecond)
	c.sequence++
	username := fmt.Sprintf("%s-%d-%d", s.prefix, worker, c.sequence)
	path := "/api/v1/realms/" + e.Client.Realm + "/scim/v2/Users"
	call := func(method, suffix string, body any, etag string) (*Response, error) {
		headers := map[string]string{}
		if etag != "" {
			headers["If-Match"] = etag
		}
		return e.Client.Do(ctx, Request{Method: method, Path: path + suffix, Token: c.token, JSON: body, Headers: headers})
	}
	created, err := call("POST", "", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": username,
		"externalId": username, "active": true}, "")
	if err != nil || created.Status != 201 {
		return lifecycleOutcome(created, err, "create")
	}
	id := created.Str("id")
	if id == "" || created.Str("userName") != username || created.Str("externalId") != username || created.Body["active"] != true {
		return "invariant_violation_created_user"
	}
	read, err := call("GET", "/"+id, nil, "")
	if err != nil || read.Status != 200 {
		return lifecycleOutcome(read, err, "read")
	}
	if read.Str("id") != id || read.Str("userName") != username || read.Header.Get("ETag") == "" {
		return "invariant_violation_read_user"
	}
	patched, err := call("PATCH", "/"+id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "benchmark updated"}}}, read.Header.Get("ETag"))
	if err != nil || patched.Status != 200 {
		return lifecycleOutcome(patched, err, "patch")
	}
	if patched.Str("id") != id || patched.Str("displayName") != "benchmark updated" {
		return "invariant_violation_patched_user"
	}
	deleted, err := call("DELETE", "/"+id, nil, "")
	if err != nil || deleted.Status != 204 {
		return lifecycleOutcome(deleted, err, "delete")
	}
	after, err := call("GET", "/"+id, nil, "")
	if err != nil {
		return outcomeOf(after, err)
	}
	if after.Status != 404 {
		return "invariant_violation_deleted_user"
	}
	return "ok"
}

func lifecycleOutcome(r *Response, err error, stage string) string {
	out := outcomeOf(r, err)
	if out == "ok" {
		return "invariant_violation_" + stage + "_status"
	}
	return out
}
