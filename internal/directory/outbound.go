package directory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

const (
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	// scimMediaType is the SCIM media type (RFC 7644 section 8.1), sent as
	// the request Content-Type and as the only Accept value.
	scimMediaType = "application/scim+json"
)

// outboundEvents are the outbox events that can change what a downstream
// system should hold for an account (PROV-010).
var outboundEvents = []string{"user.created", "user.suspended", "user.reactivated", "user.locked", "user.recovery_restricted", "user.deleted",
	"user.merged", "organization.membership.added", "organization.membership.removed", "organization.membership.suspended",
	"organization.membership.reactivated"}

// FanOut enqueues outbound deliveries for a committed outbox event, inside
// the dispatcher's transaction, so an event reaches every outbound connector
// at least once (ARC-003). Deliveries are level-triggered — "make the
// downstream resource match the account now" — so repeated events for one
// account coalesce and ordering does not matter.
func (s *Service) FanOut(ctx context.Context, tx pgx.Tx, realmID, orgID, eventID, eventType string, payload []byte) error {
	if !s.active() || !slices.Contains(outboundEvents, eventType) {
		return nil
	}
	var env struct {
		Data map[string]any `json:"data"`
	}
	if json.Unmarshal(payload, &env) != nil {
		return nil
	}
	var users []string
	for _, k := range []string{"user_id", "merged_user_id"} {
		if v, _ := env.Data[k].(string); v != "" {
			users = append(users, v)
		}
	}
	if len(users) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT `+connCols+` FROM provisioning_connectors WHERE realm_id=$1 AND kind='scim_outbound' AND state='active'`, realmID)
	if err != nil {
		return err
	}
	type target struct{ id, org string }
	var targets []target
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			rows.Close()
			return err
		}
		// A connector without a usable configuration (for example a legacy
		// row from the old /provisioning-connectors API) gets no
		// deliveries: they could only dead-letter. Its health reports why.
		if c.outboundIssue() != "" {
			continue
		}
		targets = append(targets, target{c.ID, c.OrganizationID})
	}
	rows.Close()
	for _, t := range targets {
		for _, uid := range users {
			if t.org != "" {
				// An organization connector hears only about its own
				// organization's members (tenant isolation).
				if orgID != "" && orgID != t.org {
					continue
				}
				if orgID == "" {
					var known bool
					_ = tx.QueryRow(ctx, `SELECT true FROM memberships WHERE organization_id=$1 AND user_id=$2 LIMIT 1`, t.org, uid).Scan(&known)
					if !known {
						continue
					}
				}
			}
			if err := s.enqueue(ctx, tx, t.id, realmID, t.org, "User", uid, eventType, eventID); err != nil {
				return err
			}
		}
	}
	return nil
}

// outboundIssue reports why an outbound connector cannot deliver, or ""
// when it can. Connectors created through /directory-connectors are always
// complete; rows of kind scim_outbound created through the old
// /provisioning-connectors API have no destination and no encrypted
// credential, and stay inert (no deliveries, no runs) until an
// administrator configures them with PUT /directory-connectors/{id} and
// PUT .../credential.
func (c *Connector) outboundIssue() string {
	if issue := c.outboundConfigIssue(); issue != "" {
		return issue
	}
	if c.Kind == KindOutbound && len(c.secretCT) == 0 {
		return "the credential is not set"
	}
	return ""
}

// outboundConfigIssue is the configuration part of outboundIssue (health
// reports a missing credential as needs_credential).
func (c *Connector) outboundConfigIssue() string {
	if c.Kind != KindOutbound {
		return ""
	}
	if c.out == nil || strings.TrimSpace(c.out.BaseURL) == "" {
		return "base_url is not configured"
	}
	if u, err := url.Parse(c.out.BaseURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "base_url is not a valid URL"
	}
	if c.out.MaxAttempts < 1 || c.out.TimeoutSeconds < 1 {
		return "the configuration is incomplete"
	}
	return ""
}

// outboundReadySQL is the part of outboundIssue a query can check (alias c
// for provisioning_connectors).
const outboundReadySQL = `coalesce(c.config->>'base_url','') <> '' AND c.secret_ciphertext IS NOT NULL`

// enqueue opens a delivery, or bumps the generation of the open one so a
// change arriving during an attempt is delivered after it.
func (s *Service) enqueue(ctx context.Context, q storage.Querier, connectorID, realmID, orgID, resourceType, localID, trigger, eventID string) error {
	now := s.d.Now()
	_, err := q.Exec(ctx, `INSERT INTO outbound_deliveries (id, realm_id, organization_id, connector_id, resource_type, local_id, trigger, event_id,
		next_attempt_at, created_at, updated_at) VALUES ($1,$2,nullif($3,''),$4,$5,$6,$7,nullif($8,''),$9,$9,$9)
		ON CONFLICT (connector_id, resource_type, local_id) WHERE state IN ('pending','retrying')
		DO UPDATE SET generation=outbound_deliveries.generation+1, trigger=EXCLUDED.trigger, event_id=EXCLUDED.event_id, updated_at=EXCLUDED.updated_at`,
		ids.New(ids.Delivery), realmID, orgID, connectorID, resourceType, localID, trigger, eventID, now)
	return err
}

// Delivery is an outbound delivery's state (no payloads, no credentials).
type Delivery struct {
	ID                string     `json:"id"`
	ResourceType      string     `json:"resource_type"`
	LocalID           string     `json:"local_id"`
	Trigger           string     `json:"trigger"`
	State             string     `json:"state"`
	Attempts          int        `json:"attempts"`
	Operation         string     `json:"operation,omitempty"`
	LastStatusCode    *int       `json:"last_status_code,omitempty"`
	LastErrorCategory string     `json:"last_error_category,omitempty"`
	NextAttemptAt     time.Time  `json:"next_attempt_at"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// Deliveries lists a connector's deliveries, newest first.
func (s *Service) Deliveries(ctx context.Context, realmID, orgID, id, state string, limit int) ([]Delivery, error) {
	if _, err := s.Get(ctx, realmID, orgID, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, resource_type, local_id, trigger, state, attempts, coalesce(operation,''), last_status_code,
		coalesce(last_error_category,''), next_attempt_at, delivered_at, created_at, updated_at FROM outbound_deliveries WHERE connector_id=$1
		AND ($2='' OR state=$2) ORDER BY created_at DESC, id DESC LIMIT $3`, id, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ResourceType, &d.LocalID, &d.Trigger, &d.State, &d.Attempts, &d.Operation, &d.LastStatusCode,
			&d.LastErrorCategory, &d.NextAttemptAt, &d.DeliveredAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Replay re-opens a dead-lettered delivery as a fresh attempt series
// (operator action, PROV-018).
func (s *Service) Replay(ctx context.Context, realmID, orgID, id, deliveryID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		c, err := s.load(ctx, tx, realmID, orgID, id, false)
		if err != nil {
			return err
		}
		var typ, local, state string
		if err := tx.QueryRow(ctx, `SELECT resource_type, local_id, state FROM outbound_deliveries WHERE connector_id=$1 AND id=$2 FOR UPDATE`, id, deliveryID).
			Scan(&typ, &local, &state); err != nil {
			return problem.ErrNotFound
		}
		if state != "dead_letter" {
			return problem.ErrConflict.WithDetail("only dead-lettered deliveries can be replayed")
		}
		if issue := c.outboundIssue(); issue != "" {
			return problem.ErrConflict.WithDetail("the outbound connector has no usable configuration (" + issue + "); update it first")
		}
		if _, err := tx.Exec(ctx, `UPDATE outbound_deliveries SET state='replayed', updated_at=$2 WHERE id=$1`, deliveryID, s.d.Now()); err != nil {
			return err
		}
		if err := s.enqueue(ctx, tx, c.ID, c.RealmID, c.OrganizationID, typ, local, "replay", ""); err != nil {
			return err
		}
		if err := s.recordOperatorAction(ctx, tx, c, "delivery_replayed", actor); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.outbound.replayed", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: actor,
			Category: "operations", Target: &audit.Ref{Type: "connector", ID: c.ID}, Metadata: map[string]any{"delivery_id": deliveryID, "resource_type": typ}})
		return err
	})
}

// DeliverDue sends due outbound deliveries under leases. Each connector
// gets a bounded share of a batch, so one slow downstream cannot starve the
// others (TEN-018). Each delivery is claimed by exactly one worker (DEP-011):
// the claim re-checks state, due time and lease on the row version it locks.
func (s *Service) DeliverDue(ctx context.Context, worker string, batch int) (int, error) {
	if !s.active() {
		return 0, nil
	}
	if batch <= 0 {
		batch = 100
	}
	now := s.d.Now()
	share := max(batch/4, 10)
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE outbound_deliveries SET lease_owner=$1, lease_expires_at=$2, attempts=attempts+1, updated_at=$3
		WHERE id IN (SELECT id FROM outbound_deliveries WHERE id IN (
			SELECT id FROM (SELECT d.id, d.next_attempt_at, row_number() OVER (PARTITION BY d.connector_id ORDER BY d.next_attempt_at) AS rn
				FROM outbound_deliveries d JOIN provisioning_connectors c ON c.id=d.connector_id
				WHERE d.state IN ('pending','retrying') AND d.next_attempt_at <= $3 AND c.state='active' AND `+outboundReadySQL+`
				AND (d.lease_expires_at IS NULL OR d.lease_expires_at < $3)) due WHERE rn <= $5 ORDER BY next_attempt_at LIMIT $4)
			-- Checked again on the row version the lock finds (DEP-011): the
			-- window above reads this statement's snapshot, so a delivery
			-- another worker claimed or delivered since is skipped instead of
			-- being claimed and sent a second time.
			AND state IN ('pending','retrying') AND next_attempt_at <= $3 AND (lease_expires_at IS NULL OR lease_expires_at < $3)
			FOR UPDATE SKIP LOCKED)
		RETURNING id, connector_id, resource_type, local_id, attempts, generation`, worker, now.Add(2*time.Minute), now, batch, share)
	if err != nil {
		return 0, err
	}
	type item struct {
		id, connector, typ, local string
		attempts                  int
		gen                       int64
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.connector, &it.typ, &it.local, &it.attempts, &it.gen); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	conns := map[string]*Connector{}
	for _, it := range items {
		c, ok := conns[it.connector]
		if !ok {
			c, err = s.byID(ctx, nil, it.connector)
			if err != nil {
				continue
			}
			conns[it.connector] = c
		}
		if c.outboundIssue() != "" {
			// Not attempted: the delivery waits, without using up an
			// attempt, until the connector is configured.
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE outbound_deliveries SET attempts=greatest(attempts-1,0), lease_owner=NULL, lease_expires_at=NULL,
				next_attempt_at=$2 WHERE id=$1`, it.id, now.Add(time.Hour))
			continue
		}
		res := s.deliver(ctx, c, it.typ, it.local)
		s.settle(ctx, c, it.id, it.attempts, it.gen, res)
	}
	return len(items), nil
}

// outcome is one delivery attempt's result.
type outcome struct {
	op         string
	status     int
	category   string // "" on success
	retryable  bool
	retryAfter time.Duration
}

func (s *Service) settle(ctx context.Context, c *Connector, id string, attempts int, gen int64, res outcome) {
	now := s.d.Now()
	var code *int
	if res.status > 0 {
		code = &res.status
	}
	if res.category == "" {
		s.m.outbound.Inc(res.op, "delivered")
		tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE outbound_deliveries SET state='delivered', delivered_at=$2, operation=$3, last_status_code=$4,
			last_error_category=NULL, lease_owner=NULL, lease_expires_at=NULL, updated_at=$2 WHERE id=$1 AND generation=$5`, id, now, res.op, code, gen)
		if err == nil && tag.RowsAffected() == 0 {
			// The account changed while the attempt was in flight: deliver
			// the newer state.
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE outbound_deliveries SET state='pending', attempts=0, next_attempt_at=$2, lease_owner=NULL,
				lease_expires_at=NULL, operation=$3, updated_at=$2 WHERE id=$1`, id, now, res.op)
		}
		return
	}
	maxAttempts := c.out.MaxAttempts
	if !res.retryable || attempts >= maxAttempts {
		s.m.outbound.Inc(res.op, "dead_letter")
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE outbound_deliveries SET state='dead_letter', operation=$2, last_status_code=$3, last_error_category=$4,
				lease_owner=NULL, lease_expires_at=NULL, updated_at=$5 WHERE id=$1`, id, res.op, code, res.category, now); err != nil {
				return err
			}
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.outbound.dead_lettered", RealmID: c.RealmID, OrgID: c.OrganizationID,
				Actor: c.Ref(), Category: "operations", Target: &audit.Ref{Type: "connector", ID: c.ID}, Outcome: audit.Failure,
				ReasonCode: strings.ToUpper(res.category), Metadata: map[string]any{"delivery_id": id, "operation": res.op, "attempts": attempts, "status_code": res.status}})
			return err
		})
		if err != nil {
			s.d.Log.Error("dead-lettering an outbound delivery failed", "delivery_id", id, "error", err)
		}
		return
	}
	s.m.outbound.Inc(res.op, "retrying")
	backoff := time.Duration(1<<min(attempts, 10)) * 5 * time.Second
	backoff += time.Duration(rand.Int64N(int64(backoff/4) + 1))
	if backoff > time.Hour {
		backoff = time.Hour
	}
	if res.retryAfter > backoff {
		backoff = min(res.retryAfter, 6*time.Hour)
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE outbound_deliveries SET state='retrying', next_attempt_at=$2, operation=$3, last_status_code=$4,
		last_error_category=$5, lease_owner=NULL, lease_expires_at=NULL, updated_at=$6 WHERE id=$1`, id, now.Add(backoff), res.op, code, res.category, now)
}

// client is the downstream HTTP client: the delivery egress policy, and
// private destinations only for connectors that opted in where the operator
// policy allows them (EXT-007, TEST-052).
func (s *Service) client(c *Connector) (*http.Client, egress.Policy) {
	p := s.Outbound
	if !c.out.AllowPrivateNetwork {
		p.AllowPrivate, p.AllowCIDRs = false, nil
	}
	p.Timeout = time.Duration(c.out.TimeoutSeconds) * time.Second
	return p.Client(), p
}

// scimCall performs one SCIM request and classifies the response.
func (s *Service) scimCall(ctx context.Context, c *Connector, method, path string, body any) (int, map[string]any, outcome, error) {
	token, err := s.credential(c)
	if err != nil {
		return 0, nil, outcome{category: "credential_unavailable"}, err
	}
	client, pol := s.client(c)
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.out.BaseURL+path, rd)
	if err != nil {
		return 0, nil, outcome{category: "invalid_destination"}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// One media type, as RFC 7644 section 8.1 recommends: ZITADEL v4 refuses
	// an Accept list ("application/scim+json, application/json") with 400
	// "Invalid accept header" (docs/integrations/outbound-provisioning.md).
	// The response is read as JSON whatever its Content-Type.
	req.Header.Set("Accept", scimMediaType)
	req.Header.Set("User-Agent", "ProudAuth-Provisioning/1")
	if body != nil {
		req.Header.Set("Content-Type", scimMediaType)
	}
	res, err := client.Do(req)
	if err != nil {
		cat := "network_error"
		if errors.Is(err, egress.ErrForbiddenDestination) {
			cat = "egress_denied"
		}
		return 0, nil, outcome{category: cat, retryable: true}, err
	}
	defer res.Body.Close()
	raw, _ := pol.ReadLimited(res.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	o := outcome{status: res.StatusCode}
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
	case res.StatusCode == 404:
		o.category = "not_found"
	case res.StatusCode == 409:
		o.category = "conflict"
	case res.StatusCode == 429 || res.StatusCode == 408 || res.StatusCode == 425 || res.StatusCode >= 500:
		o.category, o.retryable = "server_error", true
		if res.StatusCode == 429 {
			o.category = "throttled"
		}
		if secs, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && secs > 0 {
			o.retryAfter = time.Duration(secs) * time.Second
		}
	case res.StatusCode == 401 || res.StatusCode == 403:
		o.category = "unauthorized"
	default:
		o.category = "rejected"
	}
	return res.StatusCode, doc, o, nil
}

// remoteMapping is a downstream resource this connector created.
type remoteMapping struct {
	remoteID, digest string
}

func (s *Service) remote(ctx context.Context, q storage.Querier, c *Connector, typ, localID string) (*remoteMapping, error) {
	var m remoteMapping
	err := q.QueryRow(ctx, `SELECT external_id, coalesce(snapshot_digest,'') FROM connector_external_ids WHERE connector_id=$1 AND resource_type=$2
		AND local_id=$3`, c.ID, typ, localID).Scan(&m.remoteID, &m.digest)
	if storage.IsNoRows(err) {
		return nil, nil
	}
	return &m, err
}

func (s *Service) setRemote(ctx context.Context, c *Connector, typ, localID, remoteID, dig string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.setRemoteTx(ctx, tx, c, typ, localID, remoteID, dig)
	})
}

func (s *Service) setRemoteTx(ctx context.Context, tx pgx.Tx, c *Connector, typ, localID, remoteID, dig string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM connector_external_ids WHERE connector_id=$1 AND resource_type=$2 AND local_id=$3`, c.ID, typ, localID); err != nil {
		return err
	}
	if remoteID == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id, link_kind, snapshot_digest, last_seen_at)
		VALUES ($1,$2,$3,$4,'outbound',$5,$6)`, c.ID, typ, remoteID, localID, dig, s.d.Now())
	return err
}

// reconcileWrite keeps mapping repair and its delivery in the owning job's
// fenced transaction. Remote inventory reads cannot confer write ownership.
func (s *Service) reconcileWrite(ctx context.Context, c *Connector, r *runCtx, typ, localID string, remoteID *string, enqueue bool) error {
	return s.runTx(ctx, r, func(tx pgx.Tx) error {
		if remoteID != nil {
			if err := s.setRemoteTx(ctx, tx, c, typ, localID, *remoteID, ""); err != nil {
				return err
			}
		}
		if enqueue {
			return s.enqueue(ctx, tx, c.ID, c.RealmID, c.OrganizationID, typ, localID, "reconcile", "")
		}
		return nil
	})
}

// desiredUser computes what the downstream should hold for an account:
// eligible reports whether it should hold the account at all, and the
// document carries active=false for suspended accounts and memberships.
func (s *Service) desiredUser(ctx context.Context, c *Connector, userID string) (doc map[string]any, eligible bool, err error) {
	cfg := c.out
	u, err := s.Users.User(ctx, nil, c.RealmID, userID)
	if err != nil {
		if problem.Is(err, problem.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if u.State == identity.StateDeleted || u.State == identity.StatePendingDeletion || u.IsGuest || slices.Contains(cfg.ExcludeCreatedVia, u.CreatedVia) {
		return nil, false, nil
	}
	active := u.State == identity.StateActive || u.State == identity.StateRecoveryRestricted
	if c.OrganizationID != "" {
		var mid, state string
		if s.d.DB.Pool.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state IN ('active','suspended')`,
			c.OrganizationID, userID).Scan(&mid, &state) != nil {
			return nil, false, nil
		}
		active = active && state == "active"
		if len(cfg.EligibleGroupIDs) > 0 {
			var in bool
			_ = s.d.DB.Pool.QueryRow(ctx, `SELECT true FROM group_memberships WHERE membership_id=$1 AND group_id = ANY($2) LIMIT 1`, mid, cfg.EligibleGroupIDs).Scan(&in)
			if !in {
				return nil, false, nil
			}
		}
	} else if len(cfg.EligibleOrganizationIDs) > 0 {
		var in bool
		_ = s.d.DB.Pool.QueryRow(ctx, `SELECT true FROM memberships WHERE user_id=$1 AND organization_id = ANY($2) AND state='active' LIMIT 1`,
			userID, cfg.EligibleOrganizationIDs).Scan(&in)
		if !in {
			return nil, false, nil
		}
	}
	return buildUserDoc(cfg, u, active), true, nil
}

func sourceValue(u *identity.User, src string) string {
	v := viewOf(u)
	switch src {
	case "user_id":
		return u.ID
	case "email":
		if e := u.PrimaryEmail(); e != nil && e.Verified() {
			return e.Value
		}
		return ""
	}
	return localValue(v, src)
}

// buildUserDoc maps an account to a SCIM User (RFC 7643). Unverified
// emails are not pushed: a downstream system would treat them as proven.
func buildUserDoc(cfg *OutboundConfig, u *identity.User, active bool) map[string]any {
	doc := map[string]any{"schemas": []string{scimUserSchema}, "active": active}
	name := map[string]any{}
	for target, src := range cfg.AttributeMapping {
		v := sourceValue(u, src)
		if v == "" {
			continue
		}
		switch target {
		case "name.givenName":
			name["givenName"] = v
		case "name.familyName":
			name["familyName"] = v
		case "emails":
			doc["emails"] = []map[string]any{{"value": v, "primary": true, "type": "work"}}
		default:
			doc[target] = v
		}
	}
	if len(name) > 0 {
		doc["name"] = name
	}
	if doc["userName"] == nil || doc["userName"] == "" {
		if e := u.PrimaryEmail(); e != nil && e.Verified() {
			doc["userName"] = e.Value
		} else {
			doc["userName"] = u.ID
		}
	}
	doc["externalId"] = u.ID
	return doc
}

func docDigest(doc map[string]any) string {
	b, _ := json.Marshal(doc)
	return digest(map[string]string{"doc": string(b)})
}

// deliver makes the downstream match the current local state of one
// resource.
func (s *Service) deliver(ctx context.Context, c *Connector, typ, localID string) outcome {
	if typ == "Group" {
		return s.deliverGroup(ctx, c, localID)
	}
	doc, eligible, err := s.desiredUser(ctx, c, localID)
	if err != nil {
		return outcome{op: "read", category: "local_error", retryable: true}
	}
	m, err := s.remote(ctx, s.d.DB.Pool, c, "User", localID)
	if err != nil {
		return outcome{op: "read", category: "local_error", retryable: true}
	}
	if !eligible {
		if m == nil {
			return outcome{op: "noop"}
		}
		if c.out.DeprovisionAction == "delete" {
			_, _, o, _ := s.scimCall(ctx, c, http.MethodDelete, "/Users/"+url.PathEscape(m.remoteID), nil)
			o.op = "delete"
			if o.category == "" || o.category == "not_found" {
				if err := s.setRemote(ctx, c, "User", localID, "", ""); err != nil {
					return outcome{op: "delete", category: "local_error", retryable: true}
				}
				s.enqueueGroupsOf(ctx, c, localID)
				return outcome{op: "delete", status: o.status}
			}
			return o
		}
		if m.digest == "deactivated" {
			return outcome{op: "noop"}
		}
		patch := map[string]any{"schemas": []string{scimPatchSchema}, "Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}
		_, _, o, _ := s.scimCall(ctx, c, http.MethodPatch, "/Users/"+url.PathEscape(m.remoteID), patch)
		o.op = "deactivate"
		switch o.category {
		case "":
			if err := s.setRemote(ctx, c, "User", localID, m.remoteID, "deactivated"); err != nil {
				return outcome{op: "deactivate", category: "local_error", retryable: true}
			}
			s.enqueueGroupsOf(ctx, c, localID)
		case "not_found":
			_ = s.setRemote(ctx, c, "User", localID, "", "")
			return outcome{op: "deactivate", status: o.status}
		}
		return o
	}
	dig := docDigest(doc)
	if m != nil && m.digest == dig {
		return outcome{op: "noop"}
	}
	if m != nil {
		_, _, o, _ := s.scimCall(ctx, c, http.MethodPut, "/Users/"+url.PathEscape(m.remoteID), withID(doc, m.remoteID))
		o.op = "update"
		switch o.category {
		case "":
			if err := s.setRemote(ctx, c, "User", localID, m.remoteID, dig); err != nil {
				return outcome{op: "update", category: "local_error", retryable: true}
			}
			return o
		case "not_found":
			// Deleted downstream: create it again below.
			_ = s.setRemote(ctx, c, "User", localID, "", "")
		default:
			return o
		}
	}
	_, res, o, _ := s.scimCall(ctx, c, http.MethodPost, "/Users", doc)
	o.op = "create"
	switch o.category {
	case "":
		rid, _ := res["id"].(string)
		if rid == "" {
			return outcome{op: "create", status: o.status, category: "invalid_response"}
		}
		if err := s.setRemote(ctx, c, "User", localID, rid, dig); err != nil {
			return outcome{op: "create", category: "local_error", retryable: true}
		}
		s.enqueueGroupsOf(ctx, c, localID)
		return o
	case "conflict":
		// An earlier attempt may have created the resource before its
		// response was lost: adopt it only if its externalId is this
		// account's ID, never an unrelated account with the same userName.
		rid, ok := s.findOwn(ctx, c, "/Users", localID)
		if !ok {
			return outcome{op: "create", status: o.status, category: "conflict"}
		}
		_, _, o2, _ := s.scimCall(ctx, c, http.MethodPut, "/Users/"+url.PathEscape(rid), withID(doc, rid))
		o2.op = "create"
		if o2.category != "" {
			return o2
		}
		if err := s.setRemote(ctx, c, "User", localID, rid, dig); err != nil {
			return outcome{op: "create", category: "local_error", retryable: true}
		}
		return o2
	}
	return o
}

func withID(doc map[string]any, id string) map[string]any {
	out := make(map[string]any, len(doc)+1)
	for k, v := range doc {
		out[k] = v
	}
	out["id"] = id
	return out
}

// findOwn looks a resource up by the externalId this connector sets.
func (s *Service) findOwn(ctx context.Context, c *Connector, coll, localID string) (string, bool) {
	q := url.Values{"filter": {`externalId eq "` + localID + `"`}}
	_, res, o, _ := s.scimCall(ctx, c, http.MethodGet, coll+"?"+q.Encode(), nil)
	if o.category != "" {
		return "", false
	}
	list, _ := res["Resources"].([]any)
	if len(list) != 1 {
		return "", false
	}
	r, _ := list[0].(map[string]any)
	id, _ := r["id"].(string)
	if ext, _ := r["externalId"].(string); ext != localID || id == "" {
		return "", false
	}
	return id, true
}

// enqueueGroupsOf queues the pushed groups an account belongs to, so their
// member lists follow the account's downstream lifecycle.
func (s *Service) enqueueGroupsOf(ctx context.Context, c *Connector, userID string) {
	if len(c.out.PushGroupIDs) == 0 || c.OrganizationID == "" {
		return
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT DISTINCT gm.group_id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
		WHERE m.user_id=$1 AND m.organization_id=$2 AND gm.group_id = ANY($3)`, userID, c.OrganizationID, c.out.PushGroupIDs)
	if err != nil {
		return
	}
	var groups []string
	for rows.Next() {
		var g string
		if rows.Scan(&g) == nil {
			groups = append(groups, g)
		}
	}
	rows.Close()
	for _, g := range groups {
		_ = s.enqueue(ctx, s.d.DB.Pool, c.ID, c.RealmID, c.OrganizationID, "Group", g, "member_changed", "")
	}
}

// deliverGroup pushes a group with the downstream IDs of its members that
// the connector provisioned (PROV-010). Groups not listed for pushing are
// removed downstream if the connector created them.
func (s *Service) deliverGroup(ctx context.Context, c *Connector, groupID string) outcome {
	m, err := s.remote(ctx, s.d.DB.Pool, c, "Group", groupID)
	if err != nil {
		return outcome{op: "read", category: "local_error", retryable: true}
	}
	g, gerr := s.Orgs.GetGroup(ctx, c.OrganizationID, groupID)
	if gerr != nil || !slices.Contains(c.out.PushGroupIDs, groupID) {
		if m == nil {
			return outcome{op: "noop"}
		}
		_, _, o, _ := s.scimCall(ctx, c, http.MethodDelete, "/Groups/"+url.PathEscape(m.remoteID), nil)
		o.op = "delete"
		if o.category == "" || o.category == "not_found" {
			_ = s.setRemote(ctx, c, "Group", groupID, "", "")
			return outcome{op: "delete", status: o.status}
		}
		return o
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT x.external_id FROM group_memberships gm JOIN memberships m ON m.id=gm.membership_id
		JOIN connector_external_ids x ON x.connector_id=$2 AND x.resource_type='User' AND x.local_id=m.user_id
		WHERE gm.group_id=$1 AND m.state='active' AND coalesce(x.snapshot_digest,'') <> 'deactivated' ORDER BY x.external_id`, groupID, c.ID)
	if err != nil {
		return outcome{op: "read", category: "local_error", retryable: true}
	}
	members := []map[string]any{}
	for rows.Next() {
		var rid string
		if rows.Scan(&rid) == nil {
			members = append(members, map[string]any{"value": rid})
		}
	}
	rows.Close()
	doc := map[string]any{"schemas": []string{scimGroupSchema}, "displayName": g.Name, "externalId": g.ID, "members": members}
	dig := docDigest(doc)
	if m != nil && m.digest == dig {
		return outcome{op: "noop"}
	}
	if m != nil {
		_, _, o, _ := s.scimCall(ctx, c, http.MethodPut, "/Groups/"+url.PathEscape(m.remoteID), withID(doc, m.remoteID))
		o.op = "update"
		if o.category == "" {
			_ = s.setRemote(ctx, c, "Group", groupID, m.remoteID, dig)
			return o
		}
		if o.category != "not_found" {
			return o
		}
		_ = s.setRemote(ctx, c, "Group", groupID, "", "")
	}
	_, res, o, _ := s.scimCall(ctx, c, http.MethodPost, "/Groups", doc)
	o.op = "create"
	if o.category == "conflict" {
		if rid, ok := s.findOwn(ctx, c, "/Groups", groupID); ok {
			_, _, o2, _ := s.scimCall(ctx, c, http.MethodPut, "/Groups/"+url.PathEscape(rid), withID(doc, rid))
			if o2.category == "" {
				_ = s.setRemote(ctx, c, "Group", groupID, rid, dig)
			}
			o2.op = "create"
			return o2
		}
		return o
	}
	if o.category != "" {
		return o
	}
	rid, _ := res["id"].(string)
	if rid == "" {
		return outcome{op: "create", status: o.status, category: "invalid_response"}
	}
	_ = s.setRemote(ctx, c, "Group", groupID, rid, dig)
	return o
}

// reconcileOutbound compares the downstream with what it should hold
// (PROV-010, PROV-017): accounts missing downstream, attribute drift,
// accounts that should be deprovisioned, and downstream resources the
// connector created but lost track of. Local data is the authority: a
// difference is corrected by a delivery (unless dry run), never by changing
// the local account. Downstream resources the connector did not create are
// reported and never deleted.
func (s *Service) reconcileOutbound(ctx context.Context, c *Connector, run *Run, r *runCtx, progress func(map[string]any) error) (string, error) {
	cfg := c.out
	limit := s.maxEntriesLimit()
	var q string
	var args []any
	switch {
	case c.OrganizationID != "":
		q, args = `SELECT DISTINCT user_id FROM memberships WHERE organization_id=$1 AND state IN ('active','suspended')
			UNION SELECT local_id FROM connector_external_ids WHERE connector_id=$2 AND resource_type='User' ORDER BY 1 LIMIT $3`, []any{c.OrganizationID, c.ID, limit + 1}
	case len(cfg.EligibleOrganizationIDs) > 0:
		q, args = `SELECT DISTINCT user_id FROM memberships WHERE organization_id = ANY($1) AND state='active'
			UNION SELECT local_id FROM connector_external_ids WHERE connector_id=$2 AND resource_type='User' ORDER BY 1 LIMIT $3`, []any{cfg.EligibleOrganizationIDs, c.ID, limit + 1}
	default:
		q, args = `SELECT id FROM users WHERE realm_id=$1 AND NOT is_guest AND state NOT IN ('deleted','pending_deletion')
			UNION SELECT local_id FROM connector_external_ids WHERE connector_id=$2 AND resource_type='User' ORDER BY 1 LIMIT $3`, []any{c.RealmID, c.ID, limit + 1}
	}
	rows, err := s.d.DB.Pool.Query(ctx, q, args...)
	if err != nil {
		return "failed", err
	}
	var users []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			users = append(users, id)
		}
	}
	rows.Close()
	if len(users) > limit {
		return "failed", problem.ErrValidation.WithDetail(fmt.Sprintf("more than %d candidate accounts; raise directory.max_entries_per_run", limit))
	}
	type want struct {
		doc      map[string]any
		eligible bool
		mapping  *remoteMapping
	}
	wanted := map[string]*want{}
	byRemote := map[string]string{} // remote ID -> local ID
	for i, uid := range users {
		doc, eligible, err := s.desiredUser(ctx, c, uid)
		if err != nil {
			return "failed", err
		}
		m, err := s.remote(ctx, s.d.DB.Pool, c, "User", uid)
		if err != nil {
			return "failed", err
		}
		wanted[uid] = &want{doc, eligible, m}
		if m != nil {
			byRemote[m.remoteID] = uid
		}
		if progress != nil && i%500 == 499 {
			if err := progress(map[string]any{"run_id": run.ID, "processed": i + 1}); err != nil {
				return "failed", err
			}
		}
	}
	// Read the downstream inventory (bounded) to find drift and lost
	// resources. A downstream that cannot list is reported, and the local
	// comparison still runs.
	remoteSeen := map[string]bool{}
	remoteListed := true
	for start := 1; start <= limit; {
		_, res, o, err := s.scimCall(ctx, c, http.MethodGet, "/Users?startIndex="+strconv.Itoa(start)+"&count=100", nil)
		if err != nil || o.category != "" {
			remoteListed = false
			r.add(Finding{Kind: FindError, Reason: "remote_list_unavailable", Detail: map[string]any{"status_code": o.status, "category": o.category}})
			break
		}
		list, _ := res["Resources"].([]any)
		for _, el := range list {
			doc, _ := el.(map[string]any)
			rid, _ := doc["id"].(string)
			if rid == "" {
				continue
			}
			remoteSeen[rid] = true
			uid, mapped := byRemote[rid]
			if !mapped {
				ext, _ := doc["externalId"].(string)
				if w, ours := wanted[ext]; ours && w.mapping == nil {
					// Created by an attempt whose response was lost.
					r.add(Finding{Kind: "orphan_remote", ExternalID: rid, LocalID: ext, Applied: !r.dry})
					if !r.dry {
						if err := s.reconcileWrite(ctx, c, r, "User", ext, &rid, true); err != nil {
							return "failed", err
						}
					}
					w.mapping = &remoteMapping{remoteID: rid}
					continue
				}
				r.add(Finding{Kind: "unmanaged_remote", ExternalID: rid})
				continue
			}
			w := wanted[uid]
			if w.eligible {
				if attrs := driftAttributes(w.doc, doc); len(attrs) > 0 {
					r.add(Finding{Kind: "drift", ExternalID: rid, LocalID: uid, Attributes: attrs, Applied: !r.dry})
					if !r.dry {
						if err := s.reconcileWrite(ctx, c, r, "User", uid, &rid, true); err != nil {
							return "failed", err
						}
					}
				}
			}
		}
		total, _ := res["totalResults"].(float64)
		if len(list) == 0 || start+len(list) > int(total) {
			break
		}
		start += len(list)
	}
	for _, uid := range sortedKeys(wanted) {
		w := wanted[uid]
		switch {
		case w.eligible && w.mapping == nil:
			r.add(Finding{Kind: "missing_remote", LocalID: uid, Applied: !r.dry})
		case w.eligible && remoteListed && !remoteSeen[w.mapping.remoteID]:
			r.add(Finding{Kind: "missing_remote", Reason: "deleted_downstream", ExternalID: w.mapping.remoteID, LocalID: uid, Applied: !r.dry})
			if !r.dry {
				empty := ""
				if err := s.reconcileWrite(ctx, c, r, "User", uid, &empty, true); err != nil {
					return "failed", err
				}
				continue
			}
		case w.eligible && w.mapping.digest != docDigest(w.doc) && w.mapping.digest != "":
			r.add(Finding{Kind: "drift", Reason: "changed_locally", ExternalID: w.mapping.remoteID, LocalID: uid, Applied: !r.dry})
		case !w.eligible && w.mapping != nil && (cfg.DeprovisionAction == "delete" || w.mapping.digest != "deactivated"):
			r.add(Finding{Kind: FindDeprovision, ExternalID: w.mapping.remoteID, LocalID: uid, Applied: !r.dry})
		default:
			continue
		}
		if !r.dry {
			if err := s.reconcileWrite(ctx, c, r, "User", uid, nil, true); err != nil {
				return "failed", err
			}
		}
	}
	if !r.dry {
		for _, g := range cfg.PushGroupIDs {
			if err := s.reconcileWrite(ctx, c, r, "Group", g, nil, true); err != nil {
				return "failed", err
			}
		}
	}
	r.counts["candidates"] = len(users)
	return "succeeded", nil
}

// driftAttributes compares what the downstream holds with what it should.
func driftAttributes(want, have map[string]any) []string {
	var out []string
	for _, k := range []string{"userName", "displayName", "active", "locale", "timezone", "title"} {
		if fmt.Sprint(want[k]) != fmt.Sprint(have[k]) && !(want[k] == nil && have[k] == nil) {
			if k == "userName" && strings.EqualFold(fmt.Sprint(want[k]), fmt.Sprint(have[k])) {
				continue
			}
			out = append(out, k)
		}
	}
	wn, _ := want["name"].(map[string]any)
	hn, _ := have["name"].(map[string]any)
	for _, k := range []string{"givenName", "familyName"} {
		if fmt.Sprint(wn[k]) != fmt.Sprint(hn[k]) {
			out = append(out, "name."+k)
		}
	}
	if primary(want["emails"]) != primary(have["emails"]) {
		out = append(out, "emails")
	}
	return out
}

func primary(v any) string {
	b, _ := json.Marshal(v)
	var list []map[string]any
	_ = json.Unmarshal(b, &list)
	first := ""
	for _, e := range list {
		val, _ := e["value"].(string)
		if first == "" {
			first = val
		}
		if p, _ := e["primary"].(bool); p {
			return strings.ToLower(val)
		}
	}
	return strings.ToLower(first)
}
