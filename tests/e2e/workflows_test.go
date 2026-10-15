package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/webhooks"
	"github.com/proudauth/proudauth/internal/worker"
	"github.com/proudauth/proudauth/internal/workflow"
)

// workflowEnv is a fixture with a realm-wide webhook subscription for
// call_webhook steps, a group in Acme and a worker.
type workflowEnv struct {
	*Fixture
	w       *worker.Worker
	ep      *endpoint
	subID   string
	secret  string
	groupID string
	ctx     context.Context
}

func newWorkflowEnv(t *testing.T, mutate ...func(*realm.Policy)) *workflowEnv {
	t.Helper()
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h, mutate...)
	e := &workflowEnv{Fixture: f, w: worker.New(h.App, "wf-test"), ep: newEndpoint(t), ctx: context.Background()}
	// The subscription receives no events (it listens to signing-key
	// rotations only); workflows use its destination and secret.
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "provisioning", "destination_url": e.ep.srv.URL + "/steps",
		"event_types": []string{"signing_key.rotated"}, "allow_private_network": true}), 201, "subscription")
	e.subID, e.secret = sub.Str("subscription.id"), sub.Str("signing_secret")
	e.groupID = f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/groups", map[string]any{"name": "engineering"}), 201, "group").Str("id")
	// Events the fixture caused are dispatched before any workflow exists.
	if _, err := e.w.DispatchOutbox(e.ctx); err != nil {
		t.Fatal(err)
	}
	return e
}

// createWorkflow creates and publishes a workflow; it returns its ID.
func (e *workflowEnv) createWorkflow(t *testing.T, name string, def map[string]any) string {
	t.Helper()
	r := e.must(e.AdminAPI("POST", "/workflows", map[string]any{"name": name, "definition": def}), 201, "create workflow "+name)
	id := r.Str("workflow.id")
	if r.Str("workflow.state") != "draft" || r.Get("revision.number").(float64) != 1 || r.Str("revision.status") != "draft" {
		t.Fatalf("new workflow: %s", r.Raw)
	}
	e.must(e.AdminAPI("POST", "/workflows/"+id+"/revisions/1/publish", nil), 200, "publish "+name)
	return id
}

func (e *workflowEnv) run(t *testing.T, id string) *Resp {
	t.Helper()
	return e.must(e.AdminAPI("GET", "/workflow-runs/"+id, nil), 200, "run")
}

// runsOf returns the runs of a workflow, newest first.
func (e *workflowEnv) runsOf(t *testing.T, workflowID string) []map[string]any {
	t.Helper()
	r := e.must(e.AdminAPI("GET", "/workflows/"+workflowID+"/runs", nil), 200, "runs")
	var out []map[string]any
	for _, it := range r.Get("items").([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func (e *workflowEnv) addMember(t *testing.T, org, user string) string {
	t.Helper()
	return e.must(e.AdminAPI("POST", "/organizations/"+org+"/members", map[string]any{"user_id": e.Users[user], "role_ids": []string{e.Roles["member"]}}),
		201, "member "+user).Str("id")
}

func (e *workflowEnv) assignments(t *testing.T, user, roleID string) []map[string]any {
	t.Helper()
	r := e.must(e.AdminAPI("GET", "/role-assignments?subject_id="+e.Users[user], nil), 200, "assignments")
	var out []map[string]any
	for _, it := range r.Get("items").([]any) {
		if m := it.(map[string]any); m["role_id"] == roleID {
			out = append(out, m)
		}
	}
	return out
}

func (e *workflowEnv) inGroup(t *testing.T, user string) bool {
	t.Helper()
	r := e.must(e.AdminAPI("GET", "/organizations/"+e.Acme+"/groups/"+e.groupID+"/members", nil), 200, "group members")
	for _, it := range r.Get("items").([]any) {
		if it.(map[string]any)["user_id"] == e.Users[user] {
			return true
		}
	}
	return false
}

func attemptsOf(run *Resp) []map[string]any {
	var out []map[string]any
	for _, it := range run.Get("attempts").([]any) {
		out = append(out, it.(map[string]any))
	}
	return out
}

func onboardingDefinition(e *workflowEnv, approver string, retry map[string]any) map[string]any {
	return map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "event", "event_types": []string{"organization.membership.added"}, "organization_id": e.Acme}},
		"steps": []any{
			map[string]any{"id": "approve", "type": "approval", "approvers": []string{e.Users[approver]}, "expires_in": "72h"},
			map[string]any{"id": "grant", "type": "assign_role", "role_id": e.Roles["orders-viewer"], "scope": "organization", "expires_in": "720h"},
			map[string]any{"id": "team", "type": "add_to_group", "group_id": e.groupID},
			map[string]any{"id": "tell", "type": "notify", "notice": "access_granted"},
			map[string]any{"id": "sync", "type": "call_webhook", "subscription_id": e.subID, "compensate": true, "retry": retry},
			map[string]any{"id": "done", "type": "end"},
		}}
}

// TestWorkflowOnboardingApprovalAndCompensation covers EXT-015 and EXT-016:
// an event-triggered onboarding run waits for a named approver, grants
// access within the publisher's authority, records every attempt with its
// idempotency key, retries a failing endpoint with bounded backoff and, when
// the retries are exhausted, compensates what it can undo in reverse order.
func TestWorkflowOnboardingApprovalAndCompensation(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	schemas := apiSchemas(t)
	for _, u := range []string{"dave", "erin", "frank"} {
		e.CreateUser(u)
	}
	def := onboardingDefinition(e, "carol", map[string]any{"max_attempts": 2, "backoff": "10s"})
	if err := schemas.Validate("definition.v1.json", def); err != nil {
		t.Fatalf("definition does not match the published schema: %v", err)
	}
	wf := e.createWorkflow(t, "acme onboarding", def)
	got := e.must(e.AdminAPI("GET", "/workflows/"+wf, nil), 200, "workflow")
	if got.Str("state") != "active" || got.Get("active_revision").(float64) != 1 || got.Str("published_by_id") != e.Users["admin"] {
		t.Fatalf("published workflow: %s", got.Raw)
	}
	carol := e.AccountToken("carol").Tokens.Str("access_token")

	// --- A run that fails at the endpoint and compensates. ---
	e.ep.status(500)
	e.addMember(t, e.Acme, "dave")
	pump(t, h, e.w)
	runs := e.runsOf(t, wf)
	if len(runs) != 1 || runs[0]["subject_id"] != e.Users["dave"] || runs[0]["state"] != "awaiting_approval" || runs[0]["trigger_type"] != "event" ||
		runs[0]["trigger_event_type"] != "organization.membership.added" || runs[0]["organization_id"] != e.Acme {
		t.Fatalf("run after the event: %v", runs)
	}
	runID := runs[0]["id"].(string)
	// The approver was notified with the workflow notice.
	if body := h.Mail("carol@example.test", "workflow_notice"); !strings.Contains(body, "needs your approval") || !strings.Contains(body, "acme onboarding") {
		t.Fatalf("approval notice: %q", body)
	}
	// The subject never sees, let alone decides, their own approval.
	dave := e.AccountToken("dave").Tokens.Str("access_token")
	if r := h.API("GET", "/me/workflow-approvals", dave, nil); r.Status != 200 || len(r.Get("items").([]any)) != 0 {
		t.Fatalf("subject sees the approval: %s", r.Raw)
	}
	list := h.API("GET", "/me/workflow-approvals", carol, nil)
	if list.Status != 200 || len(list.Get("items").([]any)) != 1 {
		t.Fatalf("approver's approvals: %s", list.Raw)
	}
	approval := list.Get("items").([]any)[0].(map[string]any)["id"].(string)
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+approval+"/decision", dave, map[string]any{"decision": "approve"}), 404, "subject decides")
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+approval+"/decision", carol, map[string]any{"decision": "maybe"}), 422, "bad decision")
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+approval+"/decision", carol, map[string]any{"decision": "approve", "comment": "ok"}), 200, "approve")
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+approval+"/decision", carol, map[string]any{"decision": "reject"}), 409, "decided twice")
	pump(t, h, e.w)
	run := e.run(t, runID)
	if run.Str("state") != "running" || run.Get("step_index").(float64) != 4 || run.Str("error_category") != "http_500" {
		t.Fatalf("run after the first endpoint failure: %s", run.Raw)
	}
	if len(e.assignments(t, "dave", e.Roles["orders-viewer"])) != 1 || !e.inGroup(t, "dave") {
		t.Fatal("access was not granted before the endpoint step")
	}
	// The retry waits for its backoff, then exhausts the bounded attempts.
	h.Clock.Advance(5 * time.Second)
	pump(t, h, e.w)
	if n := len(e.ep.received("/steps")); n != 1 {
		t.Fatalf("retried before the backoff elapsed: %d calls", n)
	}
	h.Clock.Advance(15 * time.Second)
	pump(t, h, e.w)
	run = e.run(t, runID)
	if run.Str("state") != "compensated" || run.Str("error_category") != "http_500" || run.Get("finished_at") == nil {
		t.Fatalf("run after exhausting retries: %s", run.Raw)
	}
	// Compensation removed what the run created, newest first.
	if len(e.assignments(t, "dave", e.Roles["orders-viewer"])) != 0 || e.inGroup(t, "dave") {
		t.Fatal("compensation left the run's grants in place")
	}
	// Every attempt is recorded with input version, result, retry policy
	// and compensation strategy (EXT-016).
	byStep := map[string][]map[string]any{}
	for _, a := range attemptsOf(run) {
		byStep[a["step_id"].(string)] = append(byStep[a["step_id"].(string)], a)
		if a["input_version"] == "" || a["max_attempts"] == nil || a["idempotency_key"] != runID+"."+a["step_id"].(string) {
			t.Fatalf("attempt record: %v", a)
		}
	}
	if c := byStep["grant"]; len(c) != 1 || c[0]["compensation"] != "undo" || c[0]["compensation_state"] != "done" {
		t.Fatalf("grant attempt: %v", c)
	}
	if c := byStep["team"]; len(c) != 1 || c[0]["compensation"] != "undo" || c[0]["compensation_state"] != "done" {
		t.Fatalf("group attempt: %v", c)
	}
	if c := byStep["tell"]; len(c) != 1 || c[0]["compensation"] != "impossible" || c[0]["compensation_state"] != "impossible" {
		t.Fatalf("notice attempt: %v", c)
	}
	if c := byStep["sync"]; len(c) != 2 || c[0]["state"] != "failed" || c[1]["state"] != "failed" || c[1]["error_category"] != "http_500" ||
		c[0]["max_attempts"].(float64) != 2 || c[0]["backoff_ms"].(float64) != 10000 {
		t.Fatalf("endpoint attempts: %v", c)
	}
	if c := byStep["approve"]; len(c) != 1 || c[0]["state"] != "succeeded" || c[0]["result"].(map[string]any)["decided_by"] != e.Users["carol"] {
		t.Fatalf("approval attempt: %v", c)
	}
	// Endpoint calls: signed with the subscription's secret, a stable
	// Idempotency-Key across attempts and a fresh message ID per attempt.
	calls := e.ep.received("/steps")
	if len(calls) != 2 {
		t.Fatalf("endpoint calls: %d", len(calls))
	}
	if calls[0].Header.Get("Idempotency-Key") != runID+".sync" || calls[1].Header.Get("Idempotency-Key") != calls[0].Header.Get("Idempotency-Key") ||
		calls[0].Header.Get("Webhook-Id") == calls[1].Header.Get("Webhook-Id") {
		t.Fatalf("idempotency headers: %v / %v", calls[0].Header, calls[1].Header)
	}
	for _, c := range calls {
		if err := webhooks.VerifySignature(e.secret, c.Header.Get("Webhook-Id"), c.Header.Get("Webhook-Timestamp"), c.Header.Get("Webhook-Signature"),
			c.Body, h.Clock.Now(), time.Hour); err != nil {
			t.Fatalf("step call signature: %v", err)
		}
		if err := schemas.ValidateBytes("step-call.v1.json", c.Body); err != nil {
			t.Fatalf("step call body: %v", err)
		}
	}
	// Audit: the publisher is the accountable actor of every step, and the
	// run's ID correlates its evidence (API-012).
	var actorID, reqID string
	if err := h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT actor_id, coalesce(request_id,'') FROM audit_events WHERE type='role.assigned' AND subject_id=$1
		AND metadata->>'source'='workflow'`,
		e.Users["dave"]).Scan(&actorID, &reqID); err != nil {
		t.Fatal(err)
	}
	if actorID != e.Users["admin"] || reqID != runID {
		t.Fatalf("role.assigned by %s (request %s), want the publisher and the run", actorID, reqID)
	}
	for _, typ := range []string{"workflow.run.started", "workflow.step.succeeded", "workflow.step.failed", "workflow.run.failed", "workflow.step.compensated",
		"workflow.run.compensated"} {
		if auditCount(t, h, typ, runID) == 0 {
			t.Errorf("no %s evidence", typ)
		}
	}
	if auditCount(t, h, "workflow.approval.approved", approval) != 1 {
		t.Error("approval decision not audited")
	}

	// --- A run that succeeds. ---
	e.ep.status(204)
	e.ep.reset()
	e.addMember(t, e.Acme, "erin")
	pump(t, h, e.w)
	erinRun := e.runsOf(t, wf)[0]
	ap := h.API("GET", "/me/workflow-approvals", carol, nil).Get("items").([]any)[0].(map[string]any)["id"].(string)
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+ap+"/decision", carol, map[string]any{"decision": "approve"}), 200, "approve erin")
	pump(t, h, e.w)
	run = e.run(t, erinRun["id"].(string))
	if run.Str("state") != "succeeded" {
		t.Fatalf("successful run: %s", run.Raw)
	}
	as := e.assignments(t, "erin", e.Roles["orders-viewer"])
	if len(as) != 1 || as[0]["expires_at"] == nil || as[0]["source"] != "workflow" {
		t.Fatalf("granted assignment: %v", as)
	}
	if exp, _ := time.Parse(time.RFC3339Nano, as[0]["expires_at"].(string)); exp.Sub(h.Clock.Now()) < 719*time.Hour {
		t.Fatalf("assignment expiry %v", exp)
	}
	if !e.inGroup(t, "erin") || len(e.ep.received("/steps")) != 1 {
		t.Fatal("successful run did not complete its steps")
	}
	if body := h.Mail("erin@example.test", "workflow_notice"); !strings.Contains(body, "Access was granted") {
		t.Fatalf("subject notice: %q", body)
	}

	// --- A rejected approval grants nothing. ---
	e.addMember(t, e.Acme, "frank")
	pump(t, h, e.w)
	frankRun := e.runsOf(t, wf)[0]["id"].(string)
	ap = h.API("GET", "/me/workflow-approvals", carol, nil).Get("items").([]any)[0].(map[string]any)["id"].(string)
	mustStatus(t, h.API("POST", "/me/workflow-approvals/"+ap+"/decision", carol, map[string]any{"decision": "reject"}), 200, "reject")
	pump(t, h, e.w)
	run = e.run(t, frankRun)
	if run.Str("state") != "failed" || run.Str("error_category") != "approval_rejected" || len(e.assignments(t, "frank", e.Roles["orders-viewer"])) != 0 {
		t.Fatalf("rejected run: %s", run.Raw)
	}

	// --- An unanswered approval expires. ---
	mustStatus(t, h.API("DELETE", "/organizations/"+e.Acme+"/members/"+e.MemberAcme["bob"], e.AdminToken, nil), 204, "remove bob")
	e.addMember(t, e.Acme, "bob")
	pump(t, h, e.w)
	bobRun := e.runsOf(t, wf)[0]["id"].(string)
	h.Clock.Advance(73 * time.Hour)
	pump(t, h, e.w)
	e.ReloginAdmin()
	run = e.run(t, bobRun)
	if run.Str("state") != "failed" || run.Str("error_category") != "approval_expired" {
		t.Fatalf("expired approval: %s", run.Raw)
	}
	if auditCount(t, h, "workflow.approval.expired", "") != 1 {
		t.Error("expiry not audited")
	}
	diag := e.must(e.AdminAPI("GET", "/workflows/"+wf+"/diagnostics", nil), 200, "diagnostics")
	if diag.Get("runs_by_state.compensated").(float64) != 1 || diag.Get("runs_by_state.succeeded").(float64) != 1 || diag.Str("health") == "" {
		t.Fatalf("diagnostics: %s", diag.Raw)
	}
	if strings.Contains(string(diag.Raw), e.Users["dave"]) {
		t.Fatal("diagnostics reveal subjects")
	}
}

// TestWorkflowDelegationCeiling covers the authority rules: a workflow never
// grants more than its publisher could, stops when the publisher loses the
// authority, and a manual run never does more than its starter could.
func TestWorkflowDelegationCeiling(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	// Carol may draft and publish workflows and assign organization roles,
	// but holds no billing permission.
	role := e.must(e.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "workflow-author",
		"permissions": []string{"realm.workflows.read", "realm.workflows.write", "realm.workflows.publish", "realm.workflows.run", "org.roles.assign",
			"orders.read"}}), 201, "role").Str("id")
	assignment := e.must(e.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": e.Users["carol"]}}),
		201, "assign").Str("id")
	e.EnrollTOTP("carol")
	carol := e.AdminTokenFor("carol").Tokens.Str("access_token")
	def := func(roleID string) map[string]any {
		return map[string]any{"schema_version": 1, "triggers": []any{map[string]any{"type": "manual"},
			map[string]any{"type": "event", "event_types": []string{"organization.membership.added"}}},
			"steps": []any{map[string]any{"id": "grant", "type": "assign_role", "role_id": roleID, "scope": "organization"}}}
	}
	// Drafting is allowed; publishing beyond the ceiling is not.
	r := h.API("POST", "/workflows", carol, map[string]any{"name": "billing grant", "definition": def(e.Roles["billing-viewer"])})
	mustStatus(t, r, 201, "draft")
	if p := h.API("POST", "/workflows/"+r.Str("workflow.id")+"/revisions/1/publish", carol, nil); p.Status != 403 || !strings.Contains(string(p.Raw), "steps[0]") {
		t.Fatalf("publish beyond the ceiling: %d %s", p.Status, p.Raw)
	}
	// Within the ceiling it publishes, and carol is the accountable actor.
	r = h.API("POST", "/workflows", carol, map[string]any{"name": "orders grant", "definition": def(e.Roles["orders-viewer"])})
	mustStatus(t, r, 201, "draft")
	wf := r.Str("workflow.id")
	mustStatus(t, h.API("POST", "/workflows/"+wf+"/revisions/1/publish", carol, nil), 200, "publish")

	// A manual run about yourself is refused, as is one by a starter
	// without the authority the steps need.
	mustStatus(t, h.API("POST", "/workflows/"+wf+"/runs", carol, map[string]any{"subject_id": e.Users["carol"], "organization_id": e.Acme}), 403, "self run")
	e.CreateUser("dave")
	e.addMember(t, e.Acme, "dave")
	pump(t, h, e.w)
	if a := e.assignments(t, "dave", e.Roles["orders-viewer"]); len(a) != 1 || a[0]["granted_by"] != e.Users["carol"] {
		t.Fatalf("event-triggered grant under carol's authority: %v", a)
	}

	// Carol loses her authority: the next run stops before granting.
	mustStatus(t, e.AdminAPI("DELETE", "/role-assignments/"+assignment, nil), 204, "revoke carol")
	e.CreateUser("erin")
	e.addMember(t, e.Acme, "erin")
	pump(t, h, e.w)
	runs := e.runsOf(t, wf)
	run := e.run(t, runs[0]["id"].(string))
	if run.Str("state") != "failed" || run.Str("error_category") != "publisher_lacks_authority" || len(e.assignments(t, "erin", e.Roles["orders-viewer"])) != 0 {
		t.Fatalf("run after the publisher lost authority: %s", run.Raw)
	}
	// Someone who can run workflows but not assign roles cannot start one.
	runner := e.must(e.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "workflow-runner",
		"permissions": []string{"realm.workflows.read", "realm.workflows.run"}}), 201, "runner role").Str("id")
	e.must(e.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": runner, "subject": map[string]any{"type": "user", "id": e.Users["bob"]}}), 201, "assign runner")
	e.EnrollTOTP("bob")
	bob := e.AdminTokenFor("bob").Tokens.Str("access_token")
	// Re-publish under the administrator so the workflow can run at all.
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/rollback", map[string]any{"revision": 1}), 409, "rollback to the active revision")
	stage := e.must(e.AdminAPI("POST", "/workflows/"+wf+"/revisions", map[string]any{"definition": def(e.Roles["orders-viewer"]), "note": "re-own"}), 201, "stage")
	e.must(e.AdminAPI("POST", fmt.Sprintf("/workflows/%s/revisions/%v/publish", wf, stage.Get("number")), nil), 200, "admin publishes")
	if s := h.API("POST", "/workflows/"+wf+"/runs", bob, map[string]any{"subject_id": e.Users["erin"], "organization_id": e.Acme}); s.Status != 403 {
		t.Fatalf("run beyond the starter's authority: %d %s", s.Status, s.Raw)
	}
	started := e.must(e.AdminAPI("POST", "/workflows/"+wf+"/runs", map[string]any{"subject_id": e.Users["erin"], "organization_id": e.Acme}), 202, "admin run")
	if started.Str("trigger_type") != "manual" || started.Str("accountable_id") != e.Users["admin"] || started.Str("started_by_id") != e.Users["admin"] {
		t.Fatalf("manual run: %s", started.Raw)
	}
	pump(t, h, e.w)
	if len(e.assignments(t, "erin", e.Roles["orders-viewer"])) != 1 {
		t.Fatal("manual run did not grant")
	}
	// Approvers must be accounts of this realm; another realm's role is
	// unknown here (tenant isolation).
	other, err := h.App.Provision.CreateRealm(e.ctx, "other", "Other", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var otherRole string
	if err := h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT id FROM roles WHERE realm_id=$1 LIMIT 1`, other.ID).Scan(&otherRole); err != nil {
		t.Fatal(err)
	}
	if r := e.AdminAPI("POST", "/workflows", map[string]any{"name": "foreign", "definition": def(otherRole)}); r.Status != 422 {
		t.Fatalf("another realm's role accepted: %d %s", r.Status, r.Raw)
	}
	foreign, _, err := h.App.Workflows.Create(e.ctx, other.ID, workflowCreate("theirs", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "manual"}}, "steps": []any{map[string]any{"id": "x", "type": "end"}}}), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	mustStatus(t, e.AdminAPI("GET", "/workflows/"+foreign.ID, nil), 404, "another realm's workflow")
	mustStatus(t, e.AdminAPI("GET", "/workflows/"+foreign.ID+"/runs", nil), 404, "another realm's runs")
}

// TestWorkflowIdempotency covers EXT-016 under crashes and concurrency: a
// redelivered event starts one run, concurrent workers never apply a step
// twice, a step whose advance was lost is not re-applied, and an endpoint
// call interrupted by a crash is retried with the same idempotency key.
// Requirements: DEP-011 (duplicate workers create no duplicate grants; an
// expired lease is taken over).
func TestWorkflowIdempotency(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	wf := e.createWorkflow(t, "grant on join", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "event", "event_types": []string{"organization.membership.added"}}},
		"steps": []any{
			map[string]any{"id": "grant", "type": "assign_role", "role_id": e.Roles["orders-viewer"], "scope": "organization"},
			map[string]any{"id": "sync", "type": "call_webhook", "subscription_id": e.subID},
		}})
	e.ep.status(204)
	names := []string{}
	for i := 0; i < 8; i++ {
		n := fmt.Sprintf("member%d", i)
		e.CreateUser(n)
		e.addMember(t, e.Acme, n)
		names = append(names, n)
	}
	if _, err := e.w.DispatchOutbox(e.ctx); err != nil {
		t.Fatal(err)
	}
	// Redelivering an event starts nothing new (unique trigger key).
	var evID, payload string
	if err := h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT id, payload::text FROM outbox_events WHERE event_type='organization.membership.added'
		ORDER BY seq DESC LIMIT 1`).Scan(&evID, &payload); err != nil {
		t.Fatal(err)
	}
	tx, _ := h.App.D.DB.Pool.Begin(e.ctx)
	if n, err := h.App.Workflows.OnEvent(e.ctx, tx, h.Realm.ID, e.Acme, evID, "organization.membership.added", []byte(payload)); err != nil || n != 0 {
		t.Fatalf("redelivered event started %d runs (%v)", n, err)
	}
	_ = tx.Commit(e.ctx)
	// Four workers race for the same runs.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := h.App.Workflows.RunDue(e.ctx, fmt.Sprintf("racer-%d", i), 3, time.Minute, 0); err != nil {
					t.Errorf("racer: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()
	pump(t, h, e.w)
	for _, n := range names {
		if a := e.assignments(t, n, e.Roles["orders-viewer"]); len(a) != 1 {
			t.Fatalf("%s holds %d assignments", n, len(a))
		}
	}
	var succeeded, duplicates int
	if err := h.App.D.DB.Pool.QueryRow(e.ctx, `SELECT count(*) FILTER (WHERE state='succeeded'),
		(SELECT count(*) FROM (SELECT run_id, step_index FROM workflow_step_attempts WHERE state='succeeded' GROUP BY 1,2 HAVING count(*) > 1) d)
		FROM workflow_step_attempts`).Scan(&succeeded, &duplicates); err != nil {
		t.Fatal(err)
	}
	if succeeded != 2*len(names) || duplicates != 0 || len(e.ep.received("/steps")) != len(names) {
		t.Fatalf("succeeded attempts %d, duplicated steps %d, endpoint calls %d", succeeded, duplicates, len(e.ep.received("/steps")))
	}
	if n := auditCount(t, h, "role.assigned", ""); n < len(names) {
		t.Fatalf("role.assigned events: %d", n)
	}

	// A lost advance: the step's success is on record but the run points
	// at it again (as after a crash between commits). It is not re-applied.
	e.CreateUser("late")
	e.ep.status(500)
	e.addMember(t, e.Acme, "late")
	pump(t, h, e.w)
	runID := e.runsOf(t, wf)[0]["id"].(string)
	before := auditCount(t, h, "role.assigned", "")
	if _, err := h.App.D.DB.Pool.Exec(e.ctx, `UPDATE workflow_runs SET step_index=0, next_run_at=$2 WHERE id=$1`, runID, h.Clock.Now()); err != nil {
		t.Fatal(err)
	}
	pump(t, h, e.w)
	if auditCount(t, h, "role.assigned", "") != before || len(e.assignments(t, "late", e.Roles["orders-viewer"])) != 1 {
		t.Fatal("a succeeded step was applied again")
	}

	// A crash after an endpoint call was started: the attempt stays
	// "started" and the lease expires. The next worker closes it as
	// interrupted and retries with the same Idempotency-Key.
	e.ep.status(204)
	e.ep.reset()
	if _, err := h.App.D.DB.Pool.Exec(e.ctx, `UPDATE workflow_step_attempts SET state='started', error_category=NULL, finished_at=NULL
		WHERE run_id=$1 AND step_id='sync' AND attempt=(SELECT max(attempt) FROM workflow_step_attempts WHERE run_id=$1 AND step_id='sync')`, runID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.D.DB.Pool.Exec(e.ctx, `UPDATE workflow_runs SET lease_owner='crashed', lease_expires_at=$2, next_run_at=$2 WHERE id=$1`, runID,
		h.Clock.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(time.Hour)
	pump(t, h, e.w) // closes the interrupted attempt; the retry waits for its backoff
	h.Clock.Advance(5 * time.Minute)
	pump(t, h, e.w)
	e.ReloginAdmin()
	run := e.run(t, runID)
	var interrupted bool
	for _, a := range attemptsOf(run) {
		interrupted = interrupted || a["error_category"] == "interrupted"
	}
	calls := e.ep.received("/steps")
	if run.Str("state") != "succeeded" || !interrupted || len(calls) != 1 || calls[0].Header.Get("Idempotency-Key") != runID+".sync" {
		t.Fatalf("recovery after a crash: %s (calls %d)", run.Raw, len(calls))
	}
}

func workflowCreate(name string, def map[string]any) workflow.CreateInput {
	return workflow.CreateInput{Name: name, Definition: asJSON(def)}
}

// TestWorkflowRevisionsRollbackAndDisable covers versioned definitions:
// approval by a second administrator when the realm requires it, runs
// pinned to their revision, rollback, and disabling (which stops triggers
// and pauses runs).
func TestWorkflowRevisionsRollbackAndDisable(t *testing.T) {
	e := newWorkflowEnv(t, func(p *realm.Policy) { p.Extensions.WorkflowPublishApproval = true })
	h := e.H
	e.must(e.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": e.Roles["realm-admin"],
		"subject": map[string]any{"type": "user", "id": e.Users["carol"]}}), 201, "carol admin")
	e.EnrollTOTP("carol")
	carol := e.AdminTokenFor("carol").Tokens.Str("access_token")
	waitDef := func(d string) map[string]any {
		return map[string]any{"schema_version": 1, "triggers": []any{map[string]any{"type": "event", "event_types": []string{"user.created"}}},
			"steps": []any{map[string]any{"id": "pause", "type": "wait", "duration": d}, map[string]any{"id": "hello", "type": "notify", "notice": "welcome"}}}
	}
	r := e.must(e.AdminAPI("POST", "/workflows", map[string]any{"name": "welcome", "definition": waitDef("1h")}), 201, "create")
	wf := r.Str("workflow.id")
	if r.Get("workflow.requires_approval") != true {
		t.Fatalf("realm policy not applied: %s", r.Raw)
	}
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/revisions/1/publish", nil), 403, "publish without approval")
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/revisions/1/approve", nil), 403, "self-approval")
	mustStatus(t, h.API("POST", "/workflows/"+wf+"/revisions/1/approve", carol, nil), 200, "second administrator approves")
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/revisions/1/publish", nil), 200, "publish")

	// A run under revision 1 keeps revision 1 after revision 2 is published.
	e.CreateUser("dave")
	pump(t, h, e.w)
	runs := e.runsOf(t, wf)
	if len(runs) != 1 || runs[0]["state"] != "waiting" || runs[0]["revision"].(float64) != 1 {
		t.Fatalf("waiting run: %v", runs)
	}
	first := runs[0]["id"].(string)
	stage := e.must(e.AdminAPI("POST", "/workflows/"+wf+"/revisions", map[string]any{"definition": waitDef("48h")}), 201, "stage r2")
	if stage.Get("number").(float64) != 2 {
		t.Fatalf("revision 2: %s", stage.Raw)
	}
	mustStatus(t, h.API("POST", "/workflows/"+wf+"/revisions/2/approve", carol, nil), 200, "approve r2")
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/revisions/2/publish", nil), 200, "publish r2")
	h.Clock.Advance(2 * time.Hour)
	pump(t, h, e.w)
	e.ReloginAdmin()
	if run := e.run(t, first); run.Str("state") != "succeeded" || run.Get("revision").(float64) != 1 {
		t.Fatalf("pinned run: %s", run.Raw)
	}
	// Rollback to revision 1 publishes its content as revision 3.
	rb := e.must(e.AdminAPI("POST", "/workflows/"+wf+"/rollback", map[string]any{"revision": 1}), 200, "rollback")
	if rb.Get("active_revision").(float64) != 3 {
		t.Fatalf("rollback: %s", rb.Raw)
	}
	revs := e.must(e.AdminAPI("GET", "/workflows/"+wf+"/revisions", nil), 200, "revisions")
	statuses := map[float64]string{}
	hashes := map[float64]string{}
	for _, it := range revs.Get("items").([]any) {
		m := it.(map[string]any)
		statuses[m["number"].(float64)] = m["status"].(string)
		hashes[m["number"].(float64)] = m["definition_hash"].(string)
	}
	if statuses[1] != "superseded" || statuses[2] != "superseded" || statuses[3] != "published" || hashes[3] != hashes[1] {
		t.Fatalf("revision history: %v", statuses)
	}
	if auditCount(t, h, "workflow.rolled_back", wf) != 1 {
		t.Fatal("rollback not audited")
	}
	// Disabling stops triggers and pauses runs; enabling resumes them.
	e.CreateUser("erin")
	pump(t, h, e.w)
	second := e.runsOf(t, wf)[0]["id"].(string)
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/disable", map[string]any{"reason": "INCIDENT"}), 200, "disable")
	e.CreateUser("frank")
	h.Clock.Advance(2 * time.Hour)
	pump(t, h, e.w)
	e.ReloginAdmin()
	if n := len(e.runsOf(t, wf)); n != 2 {
		t.Fatalf("disabled workflow started runs: %d", n)
	}
	if run := e.run(t, second); run.Str("state") != "waiting" {
		t.Fatalf("disabled workflow's run advanced: %s", run.Raw)
	}
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+wf+"/enable", nil), 200, "enable")
	pump(t, h, e.w)
	if run := e.run(t, second); run.Str("state") != "succeeded" {
		t.Fatalf("re-enabled workflow's run: %s", run.Raw)
	}
	// Cancelling a waiting run ends it cancelled.
	e.CreateUser("gina")
	pump(t, h, e.w)
	third := e.runsOf(t, wf)[0]["id"].(string)
	mustStatus(t, e.AdminAPI("POST", "/workflow-runs/"+third+"/cancel", nil), 202, "cancel")
	mustStatus(t, e.AdminAPI("POST", "/workflow-runs/"+third+"/cancel", nil), 409, "cancel twice")
	pump(t, h, e.w)
	if run := e.run(t, third); run.Str("state") != "cancelled" {
		t.Fatalf("cancelled run: %s", run.Raw)
	}
	// A workflow with runs is kept as evidence.
	mustStatus(t, e.AdminAPI("DELETE", "/workflows/"+wf, nil), 409, "delete with runs")
}

// TestWorkflowScheduleAndOffboarding covers scheduled access expiry (one
// firing per slot, bounded selectors), offboarding steps that are never
// reversed, and loop protection between workflows.
func TestWorkflowScheduleAndOffboarding(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	ctx := e.ctx
	for _, u := range []string{"bob", "carol"} {
		e.must(e.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": e.Roles["user-admin"], "subject": map[string]any{"type": "user", "id": e.Users[u]}}),
			201, "user-admin "+u)
	}
	expiry := e.createWorkflow(t, "user-admin expiry", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "schedule", "every": "24h", "select": map[string]any{"type": "role_holders", "role_id": e.Roles["user-admin"]}}},
		"steps": []any{
			map[string]any{"id": "warn", "type": "notify", "notice": "access_expiring"},
			map[string]any{"id": "grace", "type": "wait", "duration": "1h"},
			map[string]any{"id": "revoke", "type": "remove_access", "access": "role", "role_id": e.Roles["user-admin"], "scope": "realm", "reason": "RECERTIFICATION"},
		}})
	if n, err := h.App.Workflows.FireSchedules(ctx); err != nil || n != 0 {
		t.Fatalf("schedule fired early: %d %v", n, err)
	}
	h.Clock.Advance(25 * time.Hour)
	if n, err := h.App.Workflows.FireSchedules(ctx); err != nil || n != 2 {
		t.Fatalf("schedule firing: %d %v", n, err)
	}
	if n, err := h.App.Workflows.FireSchedules(ctx); err != nil || n != 0 {
		t.Fatalf("a slot fired twice: %d %v", n, err)
	}
	pump(t, h, e.w)
	if body := h.Mail("bob@example.test", "workflow_notice"); !strings.Contains(body, "about to expire") {
		t.Fatalf("expiry notice: %q", body)
	}
	h.Clock.Advance(2 * time.Hour)
	pump(t, h, e.w)
	e.ReloginAdmin()
	for _, u := range []string{"bob", "carol"} {
		if len(e.assignments(t, u, e.Roles["user-admin"])) != 0 {
			t.Fatalf("%s kept the expiring role", u)
		}
	}
	for _, r := range e.runsOf(t, expiry) {
		if r["trigger_type"] != "schedule" || r["state"] != "succeeded" {
			t.Fatalf("scheduled run: %v", r)
		}
	}

	// Offboarding: a membership removal suspends the account and removes the
	// other memberships; nothing is reversed when a later step fails.
	e.ep.status(400)
	off := e.createWorkflow(t, "offboarding", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "event", "event_types": []string{"organization.membership.removed"}, "organization_id": e.Acme}},
		"steps": []any{
			map[string]any{"id": "leave", "type": "remove_access", "access": "membership", "organization_id": e.Globex, "reason": "OFFBOARDING"},
			map[string]any{"id": "lock", "type": "suspend_user", "reason": "OFFBOARDING"},
			map[string]any{"id": "hr", "type": "call_webhook", "subscription_id": e.subID, "retry": map[string]any{"max_attempts": 1, "backoff": "1s"}},
		}})
	mustStatus(t, e.AdminAPI("DELETE", "/organizations/"+e.Acme+"/members/"+e.MemberAcme["bob"], nil), 204, "remove bob from acme")
	pump(t, h, e.w)
	runs := e.runsOf(t, off)
	if len(runs) != 1 {
		t.Fatalf("offboarding runs: %v", runs)
	}
	run := e.run(t, runs[0]["id"].(string))
	if run.Str("state") != "failed" || run.Str("error_category") != "http_400" {
		t.Fatalf("offboarding run: %s", run.Raw)
	}
	user := e.must(e.AdminAPI("GET", "/users/"+e.Users["bob"], nil), 200, "bob")
	if user.Str("state") != "suspended" {
		t.Fatalf("bob not suspended: %s", user.Raw)
	}
	var globexState string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM memberships WHERE id=$1`, e.MemberGlobex["bob"]).Scan(&globexState)
	if globexState != "removed" {
		t.Fatalf("globex membership %s", globexState)
	}
	for _, a := range attemptsOf(run) {
		if a["state"] == "succeeded" && (a["compensation"] != "none" || a["compensation_state"] != "not_needed") {
			t.Fatalf("offboarding step would be reversed: %v", a)
		}
	}
	// Loop protection: events a run causes carry the run's ID, and a
	// workflow never triggers itself from them.
	mustStatus(t, e.AdminAPI("POST", "/workflows/"+off+"/disable", nil), 200, "disable offboarding")
	loop := e.createWorkflow(t, "loop", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "event", "event_types": []string{"organization.membership.removed"}}},
		"steps":    []any{map[string]any{"id": "leave", "type": "remove_access", "access": "membership", "organization_id": e.Acme}}})
	e.CreateUser("zed")
	e.addMember(t, e.Acme, "zed")
	zedGlobex := e.addMember(t, e.Globex, "zed")
	pump(t, h, e.w)
	mustStatus(t, e.AdminAPI("DELETE", "/organizations/"+e.Globex+"/members/"+zedGlobex, nil), 204, "remove zed from globex")
	pump(t, h, e.w)
	pump(t, h, e.w)
	if n := len(e.runsOf(t, loop)); n != 1 {
		t.Fatalf("loop workflow runs: %d", n)
	}
	if auditCount(t, h, "workflow.trigger.suppressed", loop) == 0 {
		t.Fatal("self-trigger not suppressed")
	}
	var corr string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT payload->>'correlation_id' FROM outbox_events WHERE event_type='organization.membership.removed'
		ORDER BY seq DESC LIMIT 1`).Scan(&corr)
	if !strings.HasPrefix(corr, "wrn_") {
		t.Fatalf("workflow-caused event correlation: %q", corr)
	}
}

// TestWorkflowValidation covers definition validation (strict, bounded,
// references checked) and the self-service approval API's refusals.
func TestWorkflowValidation(t *testing.T) {
	e := newWorkflowEnv(t)
	base := func(steps ...any) map[string]any {
		return map[string]any{"schema_version": 1, "triggers": []any{map[string]any{"type": "manual"}}, "steps": steps}
	}
	many := []any{}
	for i := 0; i < 21; i++ {
		many = append(many, map[string]any{"id": fmt.Sprintf("s%d", i), "type": "wait", "duration": "1h"})
	}
	orgSub := e.must(e.AdminAPI("POST", "/webhooks", map[string]any{"name": "acme only", "organization_id": e.Acme, "destination_url": e.ep.srv.URL + "/org",
		"event_types": []string{"organization.created"}, "allow_private_network": true}), 201, "org subscription").Str("subscription.id")
	bad := map[string]map[string]any{
		"schema version":   {"schema_version": 2, "triggers": []any{map[string]any{"type": "manual"}}, "steps": []any{map[string]any{"id": "x", "type": "end"}}},
		"unknown member":   base(map[string]any{"id": "x", "type": "end", "script": "return true"}),
		"foreign member":   base(map[string]any{"id": "x", "type": "wait", "duration": "1h", "role_id": e.Roles["member"]}),
		"unknown type":     base(map[string]any{"id": "x", "type": "exec"}),
		"too many steps":   base(many...),
		"long wait":        base(map[string]any{"id": "x", "type": "wait", "duration": "2400h"}),
		"bad duration":     base(map[string]any{"id": "x", "type": "wait", "duration": "3 days"}),
		"duplicate ids":    base(map[string]any{"id": "x", "type": "end"}, map[string]any{"id": "x", "type": "end"}),
		"end not last":     base(map[string]any{"id": "x", "type": "end"}, map[string]any{"id": "y", "type": "wait", "duration": "1h"}),
		"unknown approver": base(map[string]any{"id": "x", "type": "approval", "approvers": []string{"usr_00000000000000000000000000"}, "expires_in": "1h"}),
		"unknown role":     base(map[string]any{"id": "x", "type": "assign_role", "role_id": "rol_00000000000000000000000000", "scope": "realm"}),
		"boundary":         base(map[string]any{"id": "x", "type": "assign_role", "role_id": e.Roles["orders-viewer"], "scope": "realm"}),
		"org subscription": base(map[string]any{"id": "x", "type": "call_webhook", "subscription_id": orgSub}),
		"free text notice": base(map[string]any{"id": "x", "type": "notify", "notice": "click https://evil.example"}),
		"bad event":        {"schema_version": 1, "triggers": []any{map[string]any{"type": "event", "event_types": []string{"user.signed_in"}}}, "steps": []any{map[string]any{"id": "x", "type": "end"}}},
		"short schedule":   {"schema_version": 1, "triggers": []any{map[string]any{"type": "schedule", "every": "1m", "select": map[string]any{"type": "role_holders", "role_id": e.Roles["member"]}}}, "steps": []any{map[string]any{"id": "x", "type": "end"}}},
		"approvers notice": base(map[string]any{"id": "x", "type": "notify", "notice": "welcome", "recipient": "approvers"}),
		"retry bounds":     base(map[string]any{"id": "x", "type": "suspend_user", "retry": map[string]any{"max_attempts": 50, "backoff": "1s"}}),
	}
	for name, def := range bad {
		if r := e.AdminAPI("POST", "/workflows", map[string]any{"name": "bad " + name, "definition": def}); r.Status != 422 {
			t.Errorf("%s: %d %s", name, r.Status, r.Raw)
		}
	}
	// A definition the server accepts also matches the published schema.
	schemas := apiSchemas(t)
	good := base(map[string]any{"id": "x", "type": "suspend_user", "reason": "TEST"})
	if err := schemas.Validate("definition.v1.json", good); err != nil {
		t.Fatal(err)
	}
	e.must(e.AdminAPI("POST", "/workflows", map[string]any{"name": "good", "definition": good}), 201, "valid definition")
	mustStatus(t, e.AdminAPI("POST", "/workflows", map[string]any{"name": "good", "definition": good}), 409, "duplicate name")
	// Approvals are visible to named approvers only.
	bob := e.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, e.H.API("POST", "/me/workflow-approvals/wap_00000000000000000000000000/decision", bob, map[string]any{"decision": "approve"}), 404, "unknown approval")
	machine := e.MachineToken(e.Clients["orders-rs"], e.H.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	mustStatus(t, e.H.API("GET", "/workflows", machine, nil), 403, "service principal without permission")
}

var _ = json.Marshal
var _ = http.StatusOK

// TestWorkflowEndpointCompensation: an endpoint step that asked for it gets
// a compensating call (its own idempotency key) when a later step fails; an
// endpoint step that did not is recorded as impossible to take back.
func TestWorkflowEndpointCompensation(t *testing.T) {
	e := newWorkflowEnv(t)
	h := e.H
	schemas := apiSchemas(t)
	globexGroup := e.must(e.AdminAPI("POST", "/organizations/"+e.Globex+"/groups", map[string]any{"name": "globex team"}), 201, "group").Str("id")
	wf := e.createWorkflow(t, "provision then fail", map[string]any{"schema_version": 1,
		"triggers": []any{map[string]any{"type": "manual"}},
		"steps": []any{
			map[string]any{"id": "announce", "type": "call_webhook", "subscription_id": e.subID},
			map[string]any{"id": "provision", "type": "call_webhook", "subscription_id": e.subID, "compensate": true},
			// Alice is no member of Globex: this step fails permanently.
			map[string]any{"id": "team", "type": "add_to_group", "group_id": globexGroup},
		}})
	run := e.must(e.AdminAPI("POST", "/workflows/"+wf+"/runs", map[string]any{"subject_id": e.Users["alice"]}), 202, "start")
	runID := run.Str("id")
	pump(t, h, e.w)
	got := e.run(t, runID)
	if got.Str("state") != "compensated" || got.Str("error_category") != "not_a_member" {
		t.Fatalf("run: %s", got.Raw)
	}
	states := map[string]string{}
	for _, a := range attemptsOf(got) {
		if a["state"] == "succeeded" {
			states[a["step_id"].(string)] = a["compensation"].(string) + "/" + a["compensation_state"].(string)
		}
	}
	if states["announce"] != "impossible/impossible" || states["provision"] != "notify_endpoint/done" {
		t.Fatalf("compensation records: %v", states)
	}
	calls := e.ep.received("/steps")
	if len(calls) != 3 {
		t.Fatalf("endpoint calls: %d", len(calls))
	}
	last := calls[2]
	var body map[string]any
	_ = json.Unmarshal(last.Body, &body)
	if body["action"] != "compensate" || body["step_id"] != "provision" || last.Header.Get("Idempotency-Key") != runID+".provision.compensate" {
		t.Fatalf("compensating call: %s %v", last.Body, last.Header)
	}
	for _, c := range calls {
		if err := schemas.ValidateBytes("step-call.v1.json", c.Body); err != nil {
			t.Fatal(err)
		}
	}
}
