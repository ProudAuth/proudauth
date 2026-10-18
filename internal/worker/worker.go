// Package worker runs durable background work after commit: outbox dispatch,
// notification, webhook and back-channel logout delivery, jobs, key lifecycle,
// audit sealing, retention and lifecycle jobs (§5.1). Every task is safe to run
// on several workers concurrently: claims use leases or SKIP LOCKED, and side
// effects use stable identifiers so retries never duplicate grants (DEP-011).
package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/platform/tracing"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/token"
	"github.com/proudauth/proudauth/internal/webhooks"
)

// Worker executes background tasks.
type Worker struct {
	App      *httpapi.App
	ID       string
	Webhooks *webhooks.Service
	Jobs     *jobs.Service
	Handlers map[string]jobs.Handler
	Egress   egress.Policy
}

// New builds a worker.
func New(app *httpapi.App, id string) *Worker {
	if id == "" {
		id = ids.New("wrk")
	}
	cfg := app.D.Cfg
	w := &Worker{App: app, ID: id, Webhooks: webhooks.NewService(app.D), Jobs: jobs.NewService(app.D),
		Egress: egress.Policy{AllowPrivate: cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: cfg.Delivery.EgressAllowlist,
			RequireHTTPS: cfg.Mode == "production", Timeout: cfg.Delivery.WebhookTimeout}}
	w.Handlers = w.jobHandlers()
	w.Webhooks.Observe = func(state string) { app.Metrics.DeliveryOutcomes.Inc("webhook", state) }
	app.Notify.Observe = func(state string) { app.Metrics.DeliveryOutcomes.Inc("notification", state) }
	w.Jobs.OnDeadLetter = func(jobType string) { app.Metrics.JobsFailed.Inc(jobType) }
	return w
}

// Task is one unit of periodic work.
type Task struct {
	Name  string
	Every time.Duration
	Run   func(ctx context.Context) (int, error)
}

// Tasks lists periodic tasks.
func (w *Worker) Tasks() []Task {
	cfg := w.App.D.Cfg
	return []Task{
		{"outbox.dispatch", time.Second, w.DispatchOutbox},
		{"notifications.deliver", time.Second, func(ctx context.Context) (int, error) {
			return w.App.Notify.DeliverDue(ctx, w.ID, cfg.Workers.BatchSize, cfg.Workers.LeaseDuration)
		}},
		{"invitations.delivery_state", 5 * time.Second, func(ctx context.Context) (int, error) {
			n, err := w.App.Orgs.SyncDeliveryStates(ctx)
			return int(n), err
		}},
		{"webhooks.deliver", time.Second, func(ctx context.Context) (int, error) { return w.Webhooks.DeliverDue(ctx, w.ID, cfg.Workers.BatchSize) }},
		{"logout.deliver", 2 * time.Second, w.DeliverBackchannelLogout},
		// Security Event Tokens to push receivers (AUD-016).
		{"ssf.deliver", 2 * time.Second, func(ctx context.Context) (int, error) {
			return w.App.SSF.Deliver(ctx, func(ctx context.Context, id string) (*realm.Realm, error) { return w.App.Realms.ByID(ctx, nil, id) })
		}},
		// Directory runs are queued before jobs run, so a due run starts in
		// the same pass (PROV-012); outbound deliveries follow (PROV-010).
		{"directory.schedule", 15 * time.Second, w.App.Directory.Schedule},
		{"jobs.run", time.Second, w.RunJobs},
		// Lifecycle workflows (EXT-015, EXT-016): runs advance under leases;
		// schedules fire once per slot.
		{"workflows.run", time.Second, func(ctx context.Context) (int, error) {
			return w.App.Workflows.RunDue(ctx, w.ID, cfg.Workers.BatchSize, cfg.Workers.LeaseDuration, cfg.Workers.TenantBatchShare)
		}},
		{"workflows.schedule", time.Minute, w.App.Workflows.FireSchedules},
		{"directory.outbound.deliver", 2 * time.Second, func(ctx context.Context) (int, error) {
			return w.App.Directory.DeliverDue(ctx, w.ID, cfg.Workers.BatchSize)
		}},
		{"keys.lifecycle", time.Minute, w.KeyLifecycle},
		{"audit.seal", cfg.Workers.AuditSealEvery, func(ctx context.Context) (int, error) {
			return audit.SealBatch(ctx, w.App.D.DB, 5000, audit.BatchSigner(w.App.D.Keys))
		}},
		{"lifecycle.expiry", 30 * time.Second, w.Expiry},
		{"retention.cleanup", 5 * time.Minute, w.Retention},
		{"alerts.credentials_expiring", time.Hour, w.CredentialExpiryAlerts},
		{"recovery.assisted_due", time.Minute, w.App.Auth.ExecuteDueRecoveries},
		{"registration.approvals_expiry", time.Hour, w.App.Auth.ExpireRegistrationApprovals},
		{"account_merges.expiry", time.Hour, w.App.Auth.ExpireMerges},
		{"lifecycle.users", 10 * time.Minute, w.UserLifecycle},
		{"domains.recheck", time.Hour, func(ctx context.Context) (int, error) { return w.App.Orgs.RecheckDomains(ctx, 100) }},
		{"machine.owner_departures", time.Hour, w.OwnerDepartures},
		{"audit.verify_recent", time.Hour, w.VerifyRecentAudit},
		{"audit.archive", time.Minute, func(ctx context.Context) (int, error) {
			if dir := cfg.Privacy.AuditArchiveDir; dir != "" {
				return audit.ArchiveBatchesWith(ctx, w.App.D.DB, dir, 500, func(seq int64, sub string) {
					_, _ = w.App.D.Audit.Record(ctx, w.App.D.DB.Pool, audit.Event{Type: "audit.archive.forked", Actor: audit.System, Category: "audit",
						Outcome: audit.Success, Metadata: map[string]any{"sequence": seq, "directory": sub}})
				})
			}
			return 0, nil
		}},
		{"groups.dynamic", 5 * time.Minute, func(ctx context.Context) (int, error) {
			// Recompute in batches until every rule is comfortably within the
			// staleness bound, so rule-derived roles do not lapse while many
			// groups wait (AZ-010); a run handles at most 100 + 24×200 = 4900 groups.
			schema := func(ctx context.Context, realmID string) []identity.AttributeDef {
				if rlm, err := w.App.Realms.ByID(ctx, nil, realmID); err == nil {
					return rlm.Policy.Profile.Attributes
				}
				return nil
			}
			staleness := w.App.D.Cfg.Security.DynamicGroupMaxStaleness
			if staleness <= 0 {
				staleness = time.Hour
			}
			// Every run refreshes the least recently computed groups, so
			// attribute changes are picked up within minutes; then it catches up
			// on any group nearing the bound.
			total, err := w.App.Orgs.RecomputeDynamicGroups(ctx, 100, schema)
			if err != nil {
				return total, err
			}
			for i := 0; i < 24; i++ {
				var due int
				if err := w.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE dynamic_rule IS NOT NULL
					AND (rule_recomputed_at IS NULL OR rule_recomputed_at < $1)`, w.App.D.Now().Add(-staleness/2)).Scan(&due); err != nil {
					return total, err
				}
				if due == 0 {
					break
				}
				n, err := w.App.Orgs.RecomputeDynamicGroups(ctx, min(due, 200), schema)
				total += n
				if err != nil || n == 0 {
					return total, err
				}
			}
			return total, nil
		}},
	}
}

// RunOnce runs every task once (tests, CLI maintenance).
func (w *Worker) RunOnce(ctx context.Context) map[string]error {
	out := map[string]error{}
	for _, t := range w.Tasks() {
		_, err := t.Run(ctx)
		out[t.Name] = err
	}
	return out
}

// Run loops until ctx is cancelled (OPS-012). On shutdown it stops claiming new
// work at once, lets the task in flight finish for at most
// workers.drain_timeout (each task commits or rolls back its own transactions,
// so nothing is reported done that did not commit), and then releases the
// leases this worker still holds so another worker resumes the work without
// waiting for them to expire.
func (w *Worker) Run(ctx context.Context) {
	log := w.App.D.Log
	last := map[string]time.Time{}
	tick := time.NewTicker(w.App.D.Cfg.Workers.PollInterval)
	defer tick.Stop()
	work, cancelWork := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelWork()
	go func() {
		select {
		case <-ctx.Done():
			drain := w.App.D.Cfg.Workers.DrainTimeout
			if drain <= 0 {
				drain = 20 * time.Second
			}
			select {
			case <-time.After(drain):
				cancelWork()
			case <-work.Done():
			}
		case <-work.Done():
		}
	}()
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if n, err := w.ReleaseLeases(rctx); err != nil {
			log.Error("releasing worker leases failed", "error", err)
		} else if n > 0 {
			log.Info("released worker leases", "count", n)
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if w.App.Maintenance != nil {
			// Picks up operator debug windows (SEC-015) on worker nodes too.
			w.App.Maintenance.Current(ctx, w.App.D.DB.Pool)
		}
		for _, t := range w.Tasks() {
			if ctx.Err() != nil {
				return // stop claiming new work once shutdown has begun
			}
			if time.Since(last[t.Name]) < t.Every {
				continue
			}
			last[t.Name] = time.Now()
			tctx, cancel := context.WithTimeout(work, 2*time.Minute)
			// Sampled task runs are traced like requests (OPS-003): the run is
			// one span, and outbound calls it makes are its children.
			var span *tracing.Span
			if rate := w.App.D.Cfg.Observability.TraceSampling; tracing.Enabled() && rate > 0 && mrand.Float64() < rate {
				span = &tracing.Span{TraceID: hex.EncodeToString(secret.Random(16)), SpanID: tracing.NewSpanID(), Name: "worker " + t.Name,
					Kind: tracing.KindInternal, Start: time.Now()}
				tctx = reqctx.With(tctx, reqctx.Info{TraceID: span.TraceID, SpanID: span.SpanID, Sampled: true})
			}
			n, err := t.Run(tctx)
			cancel()
			if span != nil {
				span.End, span.Status = time.Now(), tracing.StatusOK
				if err != nil {
					span.Status = tracing.StatusError
				}
				span.Attributes = map[string]any{"proudauth.worker.task": t.Name, "proudauth.worker.items": n}
				tracing.Export(*span)
			}
			outcome := "ok"
			if err != nil {
				outcome = "error"
				log.Error("worker task failed", "task", t.Name, "error", err)
			} else if n > 0 {
				log.Debug("worker task", "task", t.Name, "count", n)
			}
			w.App.Metrics.WorkerRuns.Inc(t.Name, outcome)
		}
	}
}

// ReleaseLeases hands back the work this worker still holds at shutdown: running
// jobs return to the queue (handlers are checkpointed and idempotent) and
// notification and webhook attempts become due again immediately.
func (w *Worker) ReleaseLeases(ctx context.Context) (int64, error) {
	d := w.App.D
	var total int64
	for _, q := range []string{
		`UPDATE jobs SET state='queued', lease_owner=NULL, lease_expires_at=NULL, run_after=$2, updated_at=$2 WHERE lease_owner=$1 AND state='running'`,
		`UPDATE notification_jobs SET lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=$2, updated_at=$2 WHERE lease_owner=$1 AND state IN ('queued','attempted')`,
		`UPDATE webhook_deliveries SET lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=$2 WHERE lease_owner=$1 AND state IN ('pending','retrying')`,
		`UPDATE workflow_runs SET lease_owner=NULL, lease_expires_at=NULL, next_run_at=least(next_run_at, $2) WHERE lease_owner=$1`,
		`UPDATE outbound_deliveries SET lease_owner=NULL, lease_expires_at=NULL, next_attempt_at=$2 WHERE lease_owner=$1 AND state IN ('pending','retrying')`,
	} {
		tag, err := d.DB.Pool.Exec(ctx, q, w.ID, d.Now())
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	return total, nil
}

// DispatchOutbox fans committed events out to webhook deliveries (ARC-003). The
// dispatch and the delivery rows commit together, so an event is dispatched at
// least once and never lost.
func (w *Worker) DispatchOutbox(ctx context.Context) (int, error) {
	d := w.App.D
	n := 0
	err := d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT seq, id, coalesce(realm_id,''), coalesce(organization_id,''), event_type, payload FROM outbox_events
			WHERE state='pending' ORDER BY seq LIMIT $1 FOR UPDATE SKIP LOCKED`, d.Cfg.Workers.BatchSize)
		if err != nil {
			return err
		}
		type ev struct {
			seq                 int64
			id, realm, org, typ string
			payload             []byte
		}
		var list []ev
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.seq, &e.id, &e.realm, &e.org, &e.typ, &e.payload); err != nil {
				rows.Close()
				return err
			}
			list = append(list, e)
		}
		rows.Close()
		for _, e := range list {
			if e.realm != "" {
				if _, err := w.Webhooks.FanOut(ctx, tx, e.realm, e.org, e.id, e.typ, e.payload); err != nil {
					return err
				}
				// Event-triggered lifecycle workflows start in the same
				// transaction, once per event (EXT-015).
				if _, err := w.App.Workflows.OnEvent(ctx, tx, e.realm, e.org, e.id, e.typ, e.payload); err != nil {
					return err
				}
				// Outbound provisioning deliveries commit with the dispatch,
				// like webhook deliveries (PROV-010).
				if err := w.App.Directory.FanOut(ctx, tx, e.realm, e.org, e.id, e.typ, e.payload); err != nil {
					return err
				}
			}
			if strings.HasPrefix(e.typ, "security.") {
				d.Log.Warn("security event", "event_type", e.typ, "realm_id", e.realm) // alertable signal (OPS-004, AUD-012)
				w.App.Metrics.SecurityEvents.Inc(e.typ)
			}
			if _, err := tx.Exec(ctx, `UPDATE outbox_events SET state='dispatched', dispatched_at=$2, attempts=attempts+1 WHERE seq=$1`, e.seq, d.Now()); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// DeliverBackchannelLogout sends signed logout tokens to registered clients (SES-017).
func (w *Worker) DeliverBackchannelLogout(ctx context.Context) (int, error) {
	d := w.App.D
	now := d.Now()
	rows, err := d.DB.Pool.Query(ctx, `UPDATE logout_deliveries SET attempts=attempts+1, next_attempt_at=$2
		WHERE id IN (SELECT id FROM logout_deliveries WHERE state IN ('pending','retrying') AND next_attempt_at <= $1 ORDER BY next_attempt_at LIMIT 50
		FOR UPDATE SKIP LOCKED) RETURNING id, realm_id, client_ref, session_id, user_id, attempts`, now, now.Add(time.Minute))
	if err != nil {
		return 0, err
	}
	type item struct {
		id, realm, client, sid, user string
		attempts                     int
	}
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.realm, &it.client, &it.sid, &it.user, &it.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, it)
	}
	rows.Close()
	client := w.Egress.Client()
	for _, it := range list {
		c, err := w.App.Apps.ClientByRef(ctx, nil, it.realm, it.client)
		if err != nil || c.BackchannelLogoutURI == "" {
			_, _ = d.DB.Pool.Exec(ctx, `UPDATE logout_deliveries SET state='failed' WHERE id=$1`, it.id)
			continue
		}
		rlm, err := w.App.Realms.ByID(ctx, nil, it.realm)
		if err != nil {
			continue
		}
		// The logout token names the subject exactly as the client knows it
		// (pairwise when configured), never the internal user ID (APP-012).
		sub, err := w.App.OAuth.SubjectFor(ctx, c, it.user)
		if err != nil {
			continue
		}
		claims := map[string]any{"iss": rlm.Issuer, "aud": jwt.Audience{c.ClientID}, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
			"jti": ids.New("lgt"), "sub": sub, "sid": it.sid, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}}
		tok, err := w.App.Signer.Sign(ctx, it.realm, token.TypeLogout, claims)
		if err != nil {
			continue
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.BackchannelLogoutURI, strings.NewReader(url.Values{"logout_token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		res, err := client.Do(req)
		status := 0
		if err == nil {
			status = res.StatusCode
			res.Body.Close()
		}
		switch {
		case err == nil && status >= 200 && status < 300:
			_, _ = d.DB.Pool.Exec(ctx, `UPDATE logout_deliveries SET state='delivered', delivered_at=$2, last_status_code=$3 WHERE id=$1`, it.id, now, status)
			w.App.Metrics.DeliveryOutcomes.Inc("backchannel_logout", "delivered")
		case it.attempts >= 8:
			_, _ = d.DB.Pool.Exec(ctx, `UPDATE logout_deliveries SET state='failed', last_status_code=$2 WHERE id=$1`, it.id, status)
			w.App.Metrics.DeliveryOutcomes.Inc("backchannel_logout", "failed")
		default:
			backoff := time.Duration(1<<min(it.attempts, 10)) * 10 * time.Second
			_, _ = d.DB.Pool.Exec(ctx, `UPDATE logout_deliveries SET state='retrying', next_attempt_at=$2, last_status_code=$3 WHERE id=$1`, it.id, now.Add(backoff), status)
		}
	}
	return len(list), nil
}

// RunJobs runs due jobs until none remain (bounded).
//
// Up to workers.concurrency jobs run in parallel; each claim uses
// FOR UPDATE SKIP LOCKED with a lease, so runners (and other worker processes)
// never execute the same job twice (DEP-011). The bound keeps expensive jobs from
// starving other worker tasks (DEP-015).
func (w *Worker) RunJobs(ctx context.Context) (int, error) {
	conc := w.App.D.Cfg.Workers.Concurrency
	if conc < 1 {
		conc = 1
	}
	var mu sync.Mutex
	n, budget := 0, 20
	var firstErr error
	var wg sync.WaitGroup
	for r := 0; r < conc; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				if budget == 0 || firstErr != nil {
					mu.Unlock()
					return
				}
				budget--
				mu.Unlock()
				ran, err := w.Jobs.RunOnce(ctx, w.ID, w.App.D.Cfg.Workers.LeaseDuration, w.Handlers)
				mu.Lock()
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if ran {
					n++
				}
				mu.Unlock()
				if err != nil || !ran {
					return
				}
			}
		}()
	}
	wg.Wait()
	return n, firstErr
}

// KeyLifecycle activates prepublished keys, retires expired ones and schedules
// planned rotations (TOK-012). A scheduled rotation keeps each realm's
// algorithm, that of its active key; keys.signing_algorithm only applies to a
// realm without one. A rotation Rotate refuses for one realm (TOK-005,
// ADV-001) is logged and counted, and the other realms still rotate.
func (w *Worker) KeyLifecycle(ctx context.Context) (int, error) {
	cfg := w.App.D.Cfg
	publishFor := cfg.Tokens.MaxAccessTokenTTL + cfg.Keys.RetirementPeriod
	n, err := w.App.KeyMgr.ActivateDue(ctx, cfg.Keys.PrepublishPeriod, publishFor)
	if err != nil {
		return n, err
	}
	if _, err := w.App.KeyMgr.RetireExpired(ctx); err != nil {
		return n, err
	}
	due, err := w.App.KeyMgr.DueForRotation(ctx, cfg.Keys.RotationInterval)
	if err != nil {
		return n, err
	}
	for _, realmID := range due {
		if _, err := w.App.KeyMgr.Rotate(ctx, realmID, "", token.RotationPlanned, audit.System, "scheduled_rotation"); err != nil {
			reason := ""
			switch {
			case errors.Is(err, token.ErrRotationPinnedResources):
				reason = "pinned_resources"
			case errors.Is(err, token.ErrRotationFAPI2Clients):
				reason = "fapi2_clients"
			default:
				return n, err
			}
			w.App.Metrics.RotationsRefused.Inc(reason)
			w.App.D.Log.Warn("scheduled signing key rotation refused", "component", "worker", "realm_id", realmID, "reason", reason, "error", err)
			continue
		}
		n++
	}
	return n, nil
}

// Expiry applies time-based state transitions.
func (w *Worker) Expiry(ctx context.Context) (int, error) {
	total := 0
	add := func(n int64, err error) error {
		total += int(n)
		return err
	}
	a := w.App
	if err := add(a.Sessions.ExpireSessions(ctx)); err != nil {
		return total, err
	}
	if err := add(a.Orgs.ExpireInvitations(ctx)); err != nil {
		return total, err
	}
	if err := add(a.Orgs.ExpireJoinRequests(ctx)); err != nil {
		return total, err
	}
	if n, err := a.Orgs.ExpireMemberships(ctx); err != nil {
		return total, err
	} else {
		total += n
	}
	if n, err := a.Authz.ExpireAssignments(ctx); err != nil {
		return total, err
	} else {
		total += n
	}
	// Shares past their expires_at are stored as expired (AZ-027).
	if n, err := a.Authz.ExpireShares(ctx, ""); err != nil {
		return total, err
	} else {
		total += n
	}
	// Project grants end at valid_until, with what was assigned through them
	// (TEN-020).
	if n, err := a.Apps.ExpireProjectGrants(ctx); err != nil {
		return total, err
	} else {
		total += n
	}
	// Access review campaigns close and apply at their due date (AZ-025).
	if n, err := a.Authz.CloseDueReviews(ctx); err != nil {
		return total, err
	} else {
		total += n
	}
	if err := add(a.Imp.ExpireGrants(ctx)); err != nil {
		return total, err
	}
	if err := add(a.Machine.ExpireCredentials(ctx)); err != nil {
		return total, err
	}
	n, err := w.CompleteDeletions(ctx)
	return total + n, err
}

// CompleteDeletions finishes scheduled account deletions after the grace period (USR-012).
func (w *Worker) CompleteDeletions(ctx context.Context) (int, error) {
	d := w.App.D
	rows, err := d.DB.Pool.Query(ctx, `SELECT id, realm_id FROM users WHERE state='pending_deletion' AND deletion_scheduled_at <= $1 LIMIT 100`, d.Now())
	if err != nil {
		return 0, err
	}
	type u struct{ id, realm string }
	var list []u
	for rows.Next() {
		var x u
		if err := rows.Scan(&x.id, &x.realm); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, x)
	}
	rows.Close()
	done := 0
	for _, x := range list {
		// Counted only once the deletion committed: a postponed or failed
		// deletion is not a completed one.
		deleted := false
		if err := d.DB.Tx(ctx, func(tx pgx.Tx) error {
			deleted = false
			// Ownership may have been acquired during the grace period: the
			// deletion waits until it is transferred (USR-020), and says so.
			sole, err := w.App.Orgs.SoleOwnerships(ctx, tx, x.id)
			if err != nil {
				return err
			}
			owned, err := w.App.Orgs.OwnedResources(ctx, tx, x.id)
			if err != nil {
				return err
			}
			if len(sole) > 0 || len(owned) > 0 {
				if _, err := tx.Exec(ctx, `UPDATE users SET deletion_scheduled_at=$2 WHERE id=$1`, x.id, d.Now().Add(24*time.Hour)); err != nil {
					return err
				}
				_, err := d.Audit.Record(ctx, tx, audit.Event{Type: "user.deletion.postponed", RealmID: x.realm, Actor: audit.System,
					Subject: &audit.Ref{Type: "user", ID: x.id}, ReasonCode: "OWNERSHIP_NOT_TRANSFERRED",
					Metadata: map[string]any{"organizations": sole, "owned": owned}})
				return err
			}
			if err := w.App.Users.DeleteNowTx(ctx, tx, x.realm, x.id, audit.System, "scheduled_deletion"); err != nil {
				return err
			}
			deleted = true
			return nil
		}); err != nil {
			return done, err
		}
		if deleted {
			done++
		}
	}
	return done, nil
}

// Retention removes expired artifacts and old records (OPS-009, PRV-004, REG-011).
// Every step runs on its own: a failing step (a lock timeout, one bad table)
// never keeps the others from running, so one problem cannot stall all
// retention. Failures are collected, named by step, and returned together
// (the task loop logs them).
func (w *Worker) Retention(ctx context.Context) (int, error) {
	a := w.App
	d := a.D
	total := 0
	var errs []error
	step := func(name string, run func() (int64, error)) {
		n, err := run()
		total += int(n)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	exec := func(sql string, args ...any) func() (int64, error) {
		return func() (int64, error) {
			tag, err := d.DB.Pool.Exec(ctx, sql, args...)
			return tag.RowsAffected(), err
		}
	}
	if a.Passkeys != nil {
		step("passkeys", func() (int64, error) { return a.Passkeys.Cleanup(ctx) })
	}
	if a.Federation != nil {
		step("federation", func() (int64, error) { return a.Federation.Cleanup(ctx) })
	}
	// SAML requests, replay records, session participation and retired
	// signing keys (APP-018, FED-014).
	if a.SAML != nil {
		step("saml_idp", func() (int64, error) { return a.SAML.Cleanup(ctx) })
	}
	if a.Federation != nil && a.Federation.SAML != nil {
		step("saml_broker", func() (int64, error) { return a.Federation.SAML.Cleanup(ctx) })
	}
	if a.SAMLKeys != nil {
		step("saml_keys", func() (int64, error) { return a.SAMLKeys.Cleanup(ctx) })
	}
	step("challenges", func() (int64, error) { return a.Auth.CleanupChallenges(ctx) })
	step("sessions", func() (int64, error) { return a.Sessions.CleanupExpired(ctx, d.Cfg.Privacy.SessionRetention) })
	step("rate_limits", func() (int64, error) { return a.Limiter.Cleanup(ctx) })
	// Known-device quota facts older than security.rate_limits.known_quota_days
	// (owner decision 9 of 0.2.0-alpha.6, PRV-004).
	step("known_sign_ins", func() (int64, error) { return a.Auth.CleanupKnownSignIns(ctx) })
	step("assertion_jtis", func() (int64, error) { return a.Apps.CleanupAssertionJTIs(ctx) })
	// Workload assertion replay records past their expiry (ADV-004).
	if a.Workload != nil {
		step("workload_assertion_jtis", func() (int64, error) { return a.Workload.PruneJTIs(ctx) })
	}
	step("hook_invocations", func() (int64, error) { return a.Hooks.PruneInvocations(ctx, 7*24*time.Hour) })
	step("notification_payloads", func() (int64, error) { return a.Notify.PurgePayloads(ctx, d.Cfg.Delivery.PayloadRetention) })
	step("job_results", func() (int64, error) { return w.Jobs.PurgeResults(ctx) })
	// Audit retention removes only sealed events older than the retention
	// period; imported history is pruned in its own transaction, so a
	// problem with one never holds back the other.
	pruneAudit := func(prune func(pgx.Tx, audit.Retention) (int, error)) func() (int64, error) {
		return func() (int64, error) {
			var n int
			err := d.DB.Tx(ctx, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
					return err
				}
				r, err := w.auditRetention(ctx, tx)
				if err != nil {
					return err
				}
				n, err = prune(tx, r)
				return err
			})
			if err != nil {
				return 0, err // rolled back: nothing was pruned
			}
			return int64(n), nil
		}
	}
	step("audit_events", pruneAudit(func(tx pgx.Tx, r audit.Retention) (int, error) { return audit.PruneExpired(ctx, tx, r, 100) }))
	step("imported_audit_events", pruneAudit(func(tx pgx.Tx, r audit.Retention) (int, error) { return audit.PruneImported(ctx, tx, r, 1000) }))
	step("outbox", func() (int64, error) { return events.PruneDispatched(ctx, d.DB.Pool, d.Now().Add(-7*24*time.Hour)) })
	step("ssf_events", func() (int64, error) { return w.App.SSF.Prune(ctx) })
	step("ssf_received_events", func() (int64, error) { return w.App.SSF.PruneReceived(ctx) })
	// Federation transfer maps (FED-016) name upstream subjects; once a
	// transfer is finished its per-entry detail goes after 180 days and the
	// summary stays as evidence.
	step("federation_transfer_entries", exec(`DELETE FROM federation_transfer_entries WHERE transfer_id IN (SELECT id FROM federation_transfers
		WHERE state IN ('applied','cancelled') AND coalesce(applied_at, created_at) < $1)`, d.Now().Add(-180*24*time.Hour)))
	// Directory run findings (entry DNs), finished runs and finished
	// outbound deliveries go after 90 days, or privacy.history_retention
	// when shorter (PROV-018, PRV-004).
	if a.Directory != nil {
		step("directory_history", func() (int64, error) { return a.Directory.PruneHistory(ctx) })
	}
	step("dev_mailbox", exec(`DELETE FROM dev_mailbox WHERE created_at < $1`, d.Now().Add(-24*time.Hour)))
	step("idempotency_records", exec(`DELETE FROM idempotency_records WHERE expires_at < $1`, d.Now()))
	// Operational history (PRV-004): what no longer serves delivery,
	// consent or invitation handling goes after privacy.history_retention.
	// Audit evidence of these events is governed by audit retention.
	history := d.Now().Add(-d.Cfg.Privacy.HistoryRetention)
	for _, h := range []struct{ name, sql string }{
		{"consents", `DELETE FROM consents WHERE revoked_at IS NOT NULL AND revoked_at < $1`},
		{"invitations", `DELETE FROM invitations WHERE state IN ('accepted','declined','expired','revoked') AND updated_at < $1`},
		{"notification_jobs", `DELETE FROM notification_jobs WHERE state IN ('accepted','failed','expired','suppressed') AND updated_at < $1`},
		{"webhook_deliveries", `DELETE FROM webhook_deliveries WHERE state IN ('delivered','dead_letter') AND created_at < $1`},
		{"logout_deliveries", `DELETE FROM logout_deliveries WHERE state IN ('delivered','failed') AND created_at < $1`},
		// Finished workflow runs (attempts and approvals cascade); their
		// audit evidence follows audit retention.
		{"workflow_runs", `DELETE FROM workflow_runs WHERE state IN ('succeeded','failed','compensated','compensation_failed','cancelled') AND finished_at < $1`},
	} {
		step(h.name, exec(h.sql, history))
	}
	return total, errors.Join(errs...)
}

// auditRetention reads the deployment's audit retention policy with the
// realm and organization overrides (AUD-009).
func (w *Worker) auditRetention(ctx context.Context, tx pgx.Tx) (audit.Retention, error) {
	d := w.App.D
	r := audit.Retention{Default: d.Now().Add(-d.Cfg.Privacy.AuditRetention), Categories: map[string]time.Time{}, Keep: []string{"emergency"}}
	if d.Cfg.Privacy.AuditArchiveDir != "" {
		// Evidence leaves the database only after the archive holds it.
		r.Archiving = true
		if err := tx.QueryRow(ctx, `SELECT last_sequence FROM audit_archive_state`).Scan(&r.ArchivedThrough); err != nil {
			return r, err
		}
	}
	for cat, keep := range d.Cfg.Privacy.AuditRetentionByCategory {
		r.Categories[cat] = d.Now().Add(-keep)
	}
	// Realms and organizations that keep evidence longer (AUD-009).
	r.Realms, r.Orgs = map[string]time.Time{}, map[string]time.Time{}
	for _, sc := range []struct {
		sql string
		m   map[string]time.Time
	}{
		{`SELECT id, (settings->'audit'->>'retention_days')::int FROM realms WHERE coalesce((settings->'audit'->>'retention_days')::int, 0) > 0`, r.Realms},
		{`SELECT id, (policy->>'audit_retention_days')::int FROM organizations WHERE coalesce((policy->>'audit_retention_days')::int, 0) > 0`, r.Orgs},
	} {
		rows, err := tx.Query(ctx, sc.sql)
		if err != nil {
			return r, err
		}
		for rows.Next() {
			var id string
			var days int
			if err := rows.Scan(&id, &days); err != nil {
				rows.Close()
				return r, err
			}
			sc.m[id] = d.Now().AddDate(0, 0, -days)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return r, err
		}
	}
	return r, nil
}

// VerifyRecentAudit checks the most recent sealed batches of the audit chain
// on a schedule (AUD-014): event content hashes, batch digests, links and
// signatures. Problems set proudauth_audit_integrity_problems and raise the
// audit_failure security signal; the full chain stays verifiable with
// identity-cli verify-audit.
func (w *Worker) VerifyRecentAudit(ctx context.Context) (int, error) {
	rep, err := audit.VerifyRecent(ctx, w.App.D.DB.Pool, 200, audit.BatchVerifier(w.App.D.Keys, false))
	if err != nil {
		return 0, err
	}
	w.App.Metrics.AuditIntegrity.Set(int64(len(rep.Problems)))
	if len(rep.Problems) > 0 {
		w.App.Metrics.SecuritySignals.Inc("audit_failure")
		w.App.D.Log.Error("audit integrity problems", "component", "worker", "event_code", "audit.integrity_failed", "problems", len(rep.Problems))
	}
	return rep.Batches, nil
}

// OwnerDepartures applies each realm's service-principal owner-departure
// policy (MCH-007).
func (w *Worker) OwnerDepartures(ctx context.Context) (int, error) {
	realms, err := w.App.Realms.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var firstErr error
	for _, rlm := range realms {
		pol := rlm.Policy.Machine
		k, err := w.App.Machine.HandleOwnerDepartures(ctx, rlm.ID, pol.OwnerDeparture, time.Duration(pol.OwnerDepartureGraceDays)*24*time.Hour)
		n += k
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("realm %s: %w", rlm.Name, err)
		}
	}
	return n, firstErr
}

// UserLifecycle applies each realm's account lifecycle rules in bounded
// batches (USR-015, REG-011): abandoned unverified registrations, unused
// guests, dormant accounts and scheduled deactivations.
func (w *Worker) UserLifecycle(ctx context.Context) (int, error) {
	realms, err := w.App.Realms.List(ctx)
	if err != nil {
		return 0, err
	}
	// One realm's failure never holds up the others; the first error is
	// reported after every realm ran.
	n := 0
	var firstErr error
	for _, rlm := range realms {
		res, err := w.App.Users.ApplyLifecycle(ctx, rlm.ID, rlm.Policy.LifecycleRules(), 100)
		for _, r := range res {
			n += r.Applied
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("realm %s: %w", rlm.Name, err)
		}
	}
	return n, firstErr
}

// CredentialExpiryAlerts notifies owners of expiring client secrets and automation
// credentials (TOK-021, MCH-009).
func (w *Worker) CredentialExpiryAlerts(ctx context.Context) (int, error) {
	d := w.App.D
	// One alert per credential (deduplicated on the credential ID) for API keys,
	// personal tokens and client secrets/keys expiring within 14 days
	// (MCH-009, TOK-021, APP-014). Client alerts go to the owner and every
	// named technical contact, except the contacts of dynamically registered
	// clients: the registrant supplied them and nobody verified them, so
	// they never receive mail (APP-016).
	rows, err := d.DB.Pool.Query(ctx, `
		SELECT a.id, a.realm_id, a.name, a.expires_at, coalesce((SELECT i.original_value FROM user_identifiers i
			WHERE i.user_id = CASE WHEN a.owner_type='user' THEN a.owner_id ELSE (SELECT owner_user_id FROM service_principals WHERE id=a.owner_id) END
			AND i.type='email' AND i.verified_at IS NOT NULL ORDER BY i.is_primary DESC LIMIT 1), '') AS email
		FROM automation_credentials a WHERE a.state='active' AND a.expires_at BETWEEN $1 AND $2
		AND NOT EXISTS (SELECT 1 FROM credential_expiry_alerts x WHERE x.credential_id=a.id)
		UNION ALL
		SELECT cc.id, cc.realm_id, 'client ' || c.client_id || ' ' || cc.kind || coalesce(' ' || cc.display_prefix, ''), cc.expires_at, r.email
		FROM client_credentials cc JOIN clients c ON c.id=cc.client_ref
		CROSS JOIN LATERAL (
			SELECT i.original_value AS email FROM user_identifiers i WHERE i.user_id=c.owner_user_id AND i.type='email'
				AND i.verified_at IS NOT NULL AND i.is_primary
			UNION SELECT unnest(c.contacts) WHERE NOT c.dynamically_registered) r
		WHERE cc.state='active' AND cc.expires_at BETWEEN $1 AND $2 AND c.state='active'
		AND NOT EXISTS (SELECT 1 FROM credential_expiry_alerts x WHERE x.credential_id=cc.id)`,
		d.Now(), d.Now().Add(14*24*time.Hour))
	if err != nil {
		return 0, err
	}
	type item struct {
		id, realm, name, email string
		exp                    time.Time
	}
	var list []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.realm, &it.name, &it.exp, &it.email); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, it)
	}
	rows.Close()
	// Claim each credential's alert and enqueue all of its recipients in one
	// transaction: the claim row makes the alert exactly-once across replicas
	// and retries, and a failed enqueue releases the claim.
	byCred := map[string][]item{}
	var order []string
	for _, it := range list {
		if it.email == "" {
			continue
		}
		if _, ok := byCred[it.id]; !ok {
			order = append(order, it.id)
		}
		byCred[it.id] = append(byCred[it.id], it)
	}
	n := 0
	realmNames := map[string]string{}
	for _, id := range order {
		items := byCred[id]
		name, ok := realmNames[items[0].realm]
		if !ok {
			// Notices name the realm as users know it, never its internal ID.
			name = items[0].realm
			if rlm, err := w.App.Realms.ByID(ctx, nil, items[0].realm); err == nil {
				name = rlm.DisplayName
				if name == "" {
					name = rlm.Name
				}
			}
			realmNames[items[0].realm] = name
		}
		sent := 0
		err := d.DB.Tx(ctx, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `INSERT INTO credential_expiry_alerts (credential_id, realm_id, sent_at) VALUES ($1,$2,$3)
				ON CONFLICT DO NOTHING`, id, items[0].realm, d.Now())
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			for _, it := range items {
				if _, err := w.App.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: it.realm, Template: notification.TplCredentialExpiry,
					Recipient: it.email, Mandatory: true, ReferenceType: "credential_expiry", ReferenceID: it.id,
					Data: map[string]string{"realm": name, "credential": it.name, "expires": notification.Timestamp(it.exp)}}); err != nil {
					return err
				}
				sent++
			}
			return nil
		})
		if err != nil {
			return n, err
		}
		n += sent // counted only once the transaction committed
	}
	return n, nil
}

// jobHandlers registers asynchronous job types (API-011).
func (w *Worker) jobHandlers() map[string]jobs.Handler {
	return map[string]jobs.Handler{
		"organization.delete": func(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
			orgID, _ := j.Input["organization_id"].(string)
			// The requester must still hold org.delete when the job runs, like
			// every job's requester (INT-006). A refused job leaves the
			// organization closed (deleting) for an operator who holds the
			// authority to finish by requesting the deletion again.
			requester := authorization.Subject{Type: j.RequestedByType, ID: j.RequestedByID}
			if ok, err := w.App.Authz.HeldForOrganizationDeletion(ctx, j.RealmID, requester, orgID); err != nil {
				return nil, nil, err
			} else if !ok {
				return nil, nil, fmt.Errorf("%w: the requester no longer holds org.delete", jobs.ErrPermanent)
			}
			if err := w.App.Orgs.FinishDeletion(ctx, j.RealmID, orgID); err != nil {
				return nil, nil, err
			}
			return map[string]any{"organization_id": orgID, "state": "deleted"}, nil, nil
		},
		"user.export":   w.exportUser,
		"audit.export":  w.exportAudit,
		"config.export": w.exportConfig,
		"realm.export":  w.exportRealm,
		"user.import":   w.importUsers,
		"user.bulk":     w.bulkUsers,
		// Directory synchronization and outbound reconciliation runs
		// (PROV-012, PROV-017); the handler re-checks the requester.
		"directory.sync": w.App.Directory.RunJob,
	}
}

func marshal(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}

var _ = fmt.Sprintf
