// Package webhooks delivers outbox events to subscribed endpoints (§22).
//
// Delivery is at-least-once: consumers deduplicate by the stable event ID and must
// tolerate reordering (EXT-002). Each attempt signs "<id>.<timestamp>.<body>" with
// HMAC-SHA256 under a versioned, rotatable secret (EXT-003); receivers verify the
// signature and reject stale timestamps (EXT-004). Retries use bounded exponential
// backoff with jitter and end in a dead-letter state with manual replay (EXT-005).
// Destinations pass the egress policy at registration and on every connection (EXT-006).
package webhooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/contracts"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// EventTypes lists the published event types (EXT-008, api/events).
var EventTypes = []string{
	"user.created", "user.signed_in", "user.suspended", "user.reactivated", "user.locked", "user.recovery_restricted", "user.deleted", "user.password_reset",
	"user.merged",
	"session.revoked", "security.refresh_reuse_detected", "security.credential_compromised",
	"organization.created", "organization.suspended", "organization.reactivated", "organization.archived", "organization.deleted",
	"organization.membership.added", "organization.membership.removed", "organization.membership.suspended", "organization.membership.reactivated",
	"organization.invitation.created", "organization.join_request.created",
	"authorization.role.assigned", "authorization.role.unassigned",
	"client.state_changed", "service_principal.state_changed", "signing_key.rotated",
	"support.impersonation.started", "support.impersonation.ended",
	"security.alert",
}

// Subscription is a webhook registration.
type Subscription struct {
	ID                  string   `json:"id"`
	OrganizationID      string   `json:"organization_id,omitempty"`
	Name                string   `json:"name"`
	DestinationURL      string   `json:"destination_url"`
	EventTypes          []string `json:"event_types"`
	State               string   `json:"state"`
	AllowPrivateNetwork bool     `json:"allow_private_network"`
	PayloadForm         string   `json:"payload_form"`
	// EventVersion is the event schema version deliveries are rendered to
	// (EXT-018); existing subscriptions keep 1.
	EventVersion int    `json:"event_version"`
	OwnerUserID  string `json:"owner_user_id,omitempty"`
	// PluginID is set when a plugin manages the subscription (EXT-014).
	PluginID  string    `json:"plugin_id,omitempty"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Delivery is per-attempt delivery state (no secrets, no payload by default).
type Delivery struct {
	ID             string     `json:"id"`
	EventID        string     `json:"event_id"`
	EventType      string     `json:"event_type"`
	State          string     `json:"state"`
	Attempts       int        `json:"attempts"`
	NextAttemptAt  time.Time  `json:"next_attempt_at"`
	LastStatusCode *int       `json:"last_status_code,omitempty"`
	LastResponse   string     `json:"last_response_category,omitempty"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// Service manages webhooks.
type Service struct {
	d           *runtime.Deps
	Policy      egress.Policy
	MaxAttempts int
	// Observe, when set, sees each delivery's final state (metrics).
	Observe func(state string)
}

// NewService returns the webhook service.
func NewService(d *runtime.Deps) *Service {
	p := egress.Policy{AllowPrivate: d.Cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: d.Cfg.Delivery.EgressAllowlist,
		RequireHTTPS: d.Cfg.Mode == "production", Timeout: d.Cfg.Delivery.WebhookTimeout, MaxBytes: 64 << 10}
	return &Service{d: d, Policy: p, MaxAttempts: d.Cfg.Delivery.WebhookMaxAttempts}
}

// Input creates or updates a subscription.
type Input struct {
	OrganizationID      string   `json:"organization_id"`
	Name                string   `json:"name"`
	DestinationURL      string   `json:"destination_url"`
	EventTypes          []string `json:"event_types"`
	AllowPrivateNetwork bool     `json:"allow_private_network"`
	PayloadForm         string   `json:"payload_form"`
	// EventVersion chooses the event schema version (EXT-018); 0 means the
	// default, which stays 1 while version 1 is supported.
	EventVersion int `json:"event_version"`
	// pluginID marks a subscription created for a plugin (EXT-014); it is
	// set by ApplyPluginTx, never from a request.
	pluginID string
}

func (s *Service) validate(in *Input) error {
	if in.EventVersion == 0 {
		in.EventVersion = contracts.Default(contracts.WebhookEvents)
	}
	if !contracts.IsSupported(contracts.WebhookEvents, in.EventVersion) {
		return problem.ErrValidation.WithField("event_version", "supported event versions: "+contracts.SupportedList(contracts.WebhookEvents))
	}
	if in.Name == "" || len(in.Name) > 200 {
		return problem.ErrValidation.WithField("name", "required")
	}
	if len(in.EventTypes) == 0 {
		return problem.ErrValidation.WithField("event_types", "at least one event type")
	}
	for _, e := range in.EventTypes {
		if e != "*" && !slices.Contains(EventTypes, e) {
			return problem.ErrValidation.WithField("event_types", "unknown event type "+e)
		}
	}
	if in.PayloadForm == "" {
		in.PayloadForm = "minimal"
	}
	if in.PayloadForm != "minimal" && in.PayloadForm != "standard" {
		return problem.ErrValidation.WithField("payload_form", "minimal or standard")
	}
	pol := s.Policy
	if in.AllowPrivateNetwork && !pol.AllowPrivate && len(pol.AllowCIDRs) == 0 {
		return problem.ErrValidation.WithField("allow_private_network", "the operator egress policy does not permit private destinations (EXT-007)")
	}
	if !in.AllowPrivateNetwork {
		// Delivery for this subscription will use the public-only policy, so a
		// private destination is refused now rather than dead-lettered later.
		pol = s.publicPolicy()
	}
	if err := pol.ValidateURL(in.DestinationURL); err != nil {
		return problem.ErrValidation.WithField("destination_url", "destination is not allowed by the egress policy")
	}
	return nil
}

// Create registers a subscription and returns the signing secret once.
func (s *Service) Create(ctx context.Context, realmID string, in Input, actor audit.Ref) (*Subscription, string, error) {
	var id, plain string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		id, plain, err = s.CreateTx(ctx, tx, realmID, in, actor)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	sub, err := s.Get(ctx, realmID, id)
	return sub, plain, err
}

// CreateTx registers a subscription in tx and returns its ID and signing
// secret.
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, realmID string, in Input, actor audit.Ref) (string, string, error) {
	if err := s.validate(&in); err != nil {
		return "", "", err
	}
	plain := "whsec_" + base64.StdEncoding.EncodeToString(secret.Random(32))
	id := ids.New(ids.Webhook)
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeWebhook, []byte(plain), []byte("webhook:"+id))
	if err != nil {
		return "", "", err
	}
	owner := ""
	if actor.Type == "user" {
		owner = actor.ID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO webhook_subscriptions (id, realm_id, organization_id, name, destination_url, event_types,
		secret_ciphertext, key_version, allow_private_network, payload_form, owner_user_id, created_at, updated_at, event_version, plugin_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13,$14)`, id, realmID, nilIfEmpty(in.OrganizationID), in.Name, in.DestinationURL,
		in.EventTypes, ct, ver, in.AllowPrivateNetwork, in.PayloadForm, nilIfEmpty(owner), s.d.Now(), in.EventVersion, nilIfEmpty(in.pluginID)); err != nil {
		return "", "", err
	}
	meta := map[string]any{"event_types": in.EventTypes, "destination_host": hostOf(in.DestinationURL), "event_version": in.EventVersion}
	if in.pluginID != "" {
		meta["plugin_id"] = in.pluginID
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.created", RealmID: realmID, OrgID: in.OrganizationID, Actor: actor,
		Target: &audit.Ref{Type: "webhook", ID: id}, Metadata: meta})
	return id, plain, err
}

func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

const subCols = `id, coalesce(organization_id,''), name, destination_url, event_types, state, allow_private_network, payload_form, coalesce(owner_user_id,''), version, created_at,
	event_version, coalesce(plugin_id,'')`

func scanSub(row pgx.Row) (*Subscription, error) {
	var s Subscription
	err := row.Scan(&s.ID, &s.OrganizationID, &s.Name, &s.DestinationURL, &s.EventTypes, &s.State, &s.AllowPrivateNetwork, &s.PayloadForm, &s.OwnerUserID, &s.Version, &s.CreatedAt,
		&s.EventVersion, &s.PluginID)
	return &s, err
}

// Get loads a subscription.
func (s *Service) Get(ctx context.Context, realmID, id string) (*Subscription, error) {
	sub, err := scanSub(s.d.DB.Pool.QueryRow(ctx, `SELECT `+subCols+` FROM webhook_subscriptions WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return sub, err
}

// List lists subscriptions, optionally for one organization.
func (s *Service) List(ctx context.Context, realmID, orgID string) ([]*Subscription, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+subCols+` FROM webhook_subscriptions WHERE realm_id=$1 AND ($2='' OR organization_id=$2) ORDER BY created_at`, realmID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Subscription{}
	for rows.Next() {
		sub, err := scanSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// Patch changes selected fields of a subscription; absent fields keep their
// current values.
type Patch struct {
	Name                *string  `json:"name"`
	DestinationURL      *string  `json:"destination_url"`
	EventTypes          []string `json:"event_types"`
	AllowPrivateNetwork *bool    `json:"allow_private_network"`
	PayloadForm         *string  `json:"payload_form"`
	State               string   `json:"state"`
	EventVersion        *int     `json:"event_version"`
}

// Update changes destination, events or state.
func (s *Service) Update(ctx context.Context, realmID, id string, expectedVersion int64, p Patch, actor audit.Ref) (*Subscription, error) {
	cur, err := s.Get(ctx, realmID, id)
	if err != nil {
		return nil, err
	}
	if expectedVersion != 0 && cur.Version != expectedVersion {
		return nil, problem.ErrPrecondition
	}
	in := Input{OrganizationID: cur.OrganizationID, Name: cur.Name, DestinationURL: cur.DestinationURL, EventTypes: cur.EventTypes,
		AllowPrivateNetwork: cur.AllowPrivateNetwork, PayloadForm: cur.PayloadForm, EventVersion: cur.EventVersion}
	if p.EventVersion != nil {
		in.EventVersion = *p.EventVersion
		if !contracts.IsSupported(contracts.WebhookEvents, in.EventVersion) {
			return nil, problem.ErrValidation.WithField("event_version", "supported event versions: "+contracts.SupportedList(contracts.WebhookEvents))
		}
	}
	if p.Name != nil {
		in.Name = *p.Name
	}
	if p.DestinationURL != nil {
		in.DestinationURL = *p.DestinationURL
	}
	if p.EventTypes != nil {
		in.EventTypes = p.EventTypes
	}
	if p.AllowPrivateNetwork != nil {
		in.AllowPrivateNetwork = *p.AllowPrivateNetwork
	}
	if p.PayloadForm != nil {
		in.PayloadForm = *p.PayloadForm
	}
	// A state-only change (pause, resume) never re-resolves the destination,
	// so it works even while the receiver's DNS is failing.
	if p.Name != nil || p.DestinationURL != nil || p.EventTypes != nil || p.AllowPrivateNetwork != nil || p.PayloadForm != nil {
		if err := s.validate(&in); err != nil {
			return nil, err
		}
	}
	state := p.State
	if state == "" {
		state = cur.State
	}
	if state != "active" && state != "paused" && state != "disabled" {
		return nil, problem.ErrValidation.WithField("state", "active, paused or disabled")
	}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The version read above must still be current: a concurrent update in
		// between makes this one fail instead of overwriting it (API-010).
		tag, err := tx.Exec(ctx, `UPDATE webhook_subscriptions SET name=$3, destination_url=$4, event_types=$5, allow_private_network=$6,
			payload_form=$7, state=$8, version=version+1, updated_at=$9, event_version=$11 WHERE realm_id=$1 AND id=$2 AND version=$10`, realmID, id, in.Name,
			in.DestinationURL, in.EventTypes, in.AllowPrivateNetwork, in.PayloadForm, state, s.d.Now(), cur.Version, in.EventVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrPrecondition
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.updated", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "webhook", ID: id},
			Metadata: map[string]any{"state": state, "destination_host": hostOf(in.DestinationURL), "event_version": in.EventVersion}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, id)
}

// Backlog is a destination's delivery backlog (EXT-005).
type Backlog struct {
	Pending           int        `json:"pending"`
	Retrying          int        `json:"retrying"`
	DeadLetter        int        `json:"dead_letter"`
	Delivered         int        `json:"delivered"`
	OldestDueSeconds  int        `json:"oldest_due_seconds"`
	LastDeliveredAt   *time.Time `json:"last_delivered_at,omitempty"`
	LastFailureReason string     `json:"last_failure_category,omitempty"`
}

// Backlog reports one subscription's delivery backlog.
func (s *Service) Backlog(ctx context.Context, realmID, id string) (*Backlog, error) {
	if _, err := s.Get(ctx, realmID, id); err != nil {
		return nil, err
	}
	b := &Backlog{}
	var oldest *time.Time
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='retrying'),
		count(*) FILTER (WHERE state='dead_letter'), count(*) FILTER (WHERE state='delivered'),
		min(next_attempt_at) FILTER (WHERE state IN ('pending','retrying')), max(delivered_at),
		(SELECT last_response_category FROM webhook_deliveries x WHERE x.subscription_id=$1 AND x.state IN ('retrying','dead_letter')
			ORDER BY x.created_at DESC LIMIT 1)
		FROM webhook_deliveries WHERE subscription_id=$1`, id).Scan(&b.Pending, &b.Retrying, &b.DeadLetter, &b.Delivered, &oldest, &b.LastDeliveredAt,
		nullableString{&b.LastFailureReason})
	if err != nil {
		return nil, err
	}
	if oldest != nil && oldest.Before(s.d.Now()) {
		b.OldestDueSeconds = int(s.d.Now().Sub(*oldest).Seconds())
	}
	return b, nil
}

type nullableString struct{ s *string }

func (n nullableString) Scan(v any) error {
	if v != nil {
		*n.s = fmt.Sprint(v)
	}
	return nil
}

// SetState disables or re-enables a subscription through an emergency control
// (SEC-020) without revalidating its destination.
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref, reason string) error {
	if state != "active" && state != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The switch-off is remembered, so enabling or upgrading a plugin
		// does not undo it (EXT-014).
		tag, err := tx.Exec(ctx, `UPDATE webhook_subscriptions SET state=$3, emergency_disabled=($3='disabled'), version=version+1, updated_at=$4
			WHERE realm_id=$1 AND id=$2`, realmID, id, state, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.state_changed", RealmID: realmID, Actor: actor, Category: "emergency",
			Target: &audit.Ref{Type: "webhook", ID: id}, ReasonCode: reason, Metadata: map[string]any{"state": state}})
		return err
	})
}

// Delete removes a subscription.
func (s *Service) Delete(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE realm_id=$1 AND id=$2`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.deleted", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "webhook", ID: id}})
		return err
	})
}

// RotateSecret issues a new secret; the previous one keeps signing in parallel for
// 24 hours so receivers can roll over without downtime (EXT-003, EXT-004).
func (s *Service) RotateSecret(ctx context.Context, realmID, id string, actor audit.Ref) (string, error) {
	plain := "whsec_" + base64.StdEncoding.EncodeToString(secret.Random(32))
	ct, ver, err := s.d.Keys.Encrypt(keys.PurposeWebhook, []byte(plain), []byte("webhook:"+id))
	if err != nil {
		return "", err
	}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE webhook_subscriptions SET previous_secret_ciphertext=secret_ciphertext, previous_secret_expires_at=$3,
			secret_ciphertext=$4, key_version=$5, version=version+1, updated_at=$6 WHERE realm_id=$1 AND id=$2`, realmID, id,
			s.d.Now().Add(24*time.Hour), ct, ver, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.secret_rotated", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "webhook", ID: id}})
		return err
	})
	return plain, err
}

// FanOut creates deliveries for an outbox event inside the dispatcher transaction.
// The (subscription, event) uniqueness makes fan-out idempotent across retries.
func (s *Service) FanOut(ctx context.Context, tx pgx.Tx, realmID, orgID, eventID, eventType string, envelope []byte) (int, error) {
	rows, err := tx.Query(ctx, `SELECT id, event_types, payload_form, event_version FROM webhook_subscriptions WHERE realm_id=$1 AND state='active'
		AND (organization_id IS NULL OR organization_id=$2)`, realmID, orgID)
	if err != nil {
		return 0, err
	}
	type sub struct {
		id      string
		types   []string
		form    string
		version int
	}
	var subs []sub
	for rows.Next() {
		var x sub
		if err := rows.Scan(&x.id, &x.types, &x.form, &x.version); err != nil {
			rows.Close()
			return 0, err
		}
		subs = append(subs, x)
	}
	rows.Close()
	n := 0
	for _, x := range subs {
		if !slices.Contains(x.types, "*") && !slices.Contains(x.types, eventType) {
			continue
		}
		payload := envelope
		if x.form == "minimal" {
			payload = minimal(envelope)
		}
		// Rendered to the subscription's event schema version (EXT-018);
		// version 1 is the stored envelope unchanged.
		if payload, err = contracts.RenderEvent(payload, x.version, x.form); err != nil {
			return n, err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO webhook_deliveries (id, realm_id, subscription_id, event_id, event_type, payload, next_attempt_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$7) ON CONFLICT (subscription_id, event_id) DO NOTHING`, ids.New(ids.Delivery), realmID, x.id, eventID,
			eventType, payload, s.d.Now())
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, nil
}

// minimalKeep are non-identifier members a minimal payload keeps: states and
// classifications that carry no personal data and without which a consumer
// could not act on the event (a security alert without its signal).
var minimalKeep = map[string]bool{"state": true, "reason": true, "authorization_revision": true, "mode": true,
	"signal": true, "event_type": true, "actor_type": true, "subject_type": true,
	"client_ref": true, "new_kid": true, "previous_kid": true, "previous_key_compromised": true}

// minimal strips data members other than identifiers (minimal-PII form, EXT-008).
func minimal(envelope []byte) []byte {
	var m map[string]any
	if json.Unmarshal(envelope, &m) != nil {
		return envelope
	}
	if data, ok := m["data"].(map[string]any); ok {
		for k := range data {
			if !strings.HasSuffix(k, "_id") && !minimalKeep[k] {
				delete(data, k)
			}
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// Sign computes the signature header value for one secret.
func Sign(secretValue, id string, ts int64, body []byte) string {
	key := secretValue
	if strings.HasPrefix(key, "whsec_") {
		// Standard Webhooks secrets are padded base64; secrets issued by earlier
		// versions were unpadded, so both decode.
		if raw, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(strings.TrimPrefix(key, "whsec_"), "=")); err == nil {
			key = string(raw)
		}
	}
	m := hmac.New(sha256.New, []byte(key))
	m.Write([]byte(id + "." + strconv.FormatInt(ts, 10) + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// VerifySignature is the receiver-side check (published for SDKs and fixtures,
// TEST-054): signature over the exact body, timestamp within tolerance.
func VerifySignature(secretValue, id, timestamp, header string, body []byte, now time.Time, tolerance time.Duration) error {
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return errors.New("stale or future timestamp")
	}
	want := Sign(secretValue, id, ts, body)
	for _, part := range strings.Fields(header) {
		if hmac.Equal([]byte(part), []byte(want)) {
			return nil
		}
	}
	return errors.New("signature mismatch")
}

// DeliverDue sends due deliveries with leases and backoff. Each delivery is
// claimed by exactly one worker (DEP-011): the claim re-checks state, due time
// and lease on the row version it locks.
func (s *Service) DeliverDue(ctx context.Context, worker string, batch int) (int, error) {
	now := s.d.Now()
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE webhook_deliveries SET lease_owner=$1, lease_expires_at=$2, attempts=attempts+1
		WHERE id IN (SELECT id FROM webhook_deliveries WHERE id IN (
			-- Fair share (TEN-018, EXT-005): a slow or flooded destination gets at
			-- most $5 attempts per batch, so it cannot starve other subscriptions.
			SELECT id FROM (SELECT d.id, d.next_attempt_at, row_number() OVER (PARTITION BY d.subscription_id ORDER BY d.next_attempt_at) AS rn
				FROM webhook_deliveries d JOIN webhook_subscriptions s ON s.id=d.subscription_id
				WHERE d.state IN ('pending','retrying') AND d.next_attempt_at <= $3 AND s.state='active'
				AND (d.lease_expires_at IS NULL OR d.lease_expires_at < $3)) due
			WHERE rn <= $5 ORDER BY next_attempt_at LIMIT $4)
		-- Checked again on the row version the lock finds (DEP-011): the
		-- window above reads this statement's snapshot, so a delivery another
		-- worker claimed or delivered since is skipped instead of being
		-- claimed and sent a second time.
		AND state IN ('pending','retrying') AND next_attempt_at <= $3 AND (lease_expires_at IS NULL OR lease_expires_at < $3)
		FOR UPDATE SKIP LOCKED)
		RETURNING id, subscription_id, event_id, payload, attempts`, worker, now.Add(time.Minute), now, batch, share(s.d.Cfg.Workers.TenantBatchShare, batch))
	if err != nil {
		return 0, err
	}
	type item struct {
		id, sub, event string
		payload        []byte
		attempts       int
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.sub, &it.event, &it.payload, &it.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, it)
	}
	rows.Close()
	// Only subscriptions that opted in may reach private destinations, and then
	// only as far as the operator egress policy allows (EXT-007).
	clients := map[bool]*http.Client{false: s.publicPolicy().Client(), true: s.Policy.Client()}
	for _, it := range items {
		s.deliverOne(ctx, clients, it.id, it.sub, it.event, it.payload, it.attempts)
	}
	return len(items), nil
}

// publicPolicy is the egress policy for subscriptions without
// allow_private_network: public destinations only.
func (s *Service) publicPolicy() egress.Policy {
	p := s.Policy
	p.AllowPrivate = false
	p.AllowCIDRs = nil
	return p
}

func (s *Service) deliverOne(ctx context.Context, clients map[bool]*http.Client, id, subID, eventID string, payload []byte, attempts int) {
	var dest string
	var ct, prev []byte
	var prevExp *time.Time
	var allowPrivate bool
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT destination_url, secret_ciphertext, previous_secret_ciphertext, previous_secret_expires_at, allow_private_network
		FROM webhook_subscriptions WHERE id=$1`, subID).Scan(&dest, &ct, &prev, &prevExp, &allowPrivate); err != nil {
		return
	}
	sec, err := s.d.Keys.Decrypt(keys.PurposeWebhook, ct, []byte("webhook:"+subID))
	if err != nil {
		s.finish(ctx, id, "dead_letter", nil, "secret_unavailable", attempts)
		return
	}
	ts := s.d.Now().Unix()
	sig := Sign(string(sec), eventID, ts, payload)
	if prev != nil && prevExp != nil && s.d.Now().Before(*prevExp) {
		if p, err := s.d.Keys.Decrypt(keys.PurposeWebhook, prev, []byte("webhook:"+subID)); err == nil {
			sig += " " + Sign(string(p), eventID, ts, payload)
		}
	}
	client := clients[allowPrivate]
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(payload))
	if err != nil {
		s.finish(ctx, id, "dead_letter", nil, "invalid_destination", attempts)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webhook-Id", eventID)
	req.Header.Set("Webhook-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("Webhook-Signature", sig)
	req.Header.Set("User-Agent", "ProudAuth-Webhooks/1")
	res, err := client.Do(req)
	if err != nil {
		category := "network_error"
		if errors.Is(err, egress.ErrForbiddenDestination) {
			category = "egress_denied"
		}
		s.retry(ctx, id, nil, category, attempts)
		return
	}
	_, _ = s.Policy.ReadLimited(res.Body)
	res.Body.Close()
	code := res.StatusCode
	switch {
	case code >= 200 && code < 300:
		s.finish(ctx, id, "delivered", &code, "success", attempts)
	case code == 410:
		s.finish(ctx, id, "dead_letter", &code, "gone", attempts)
	default:
		s.retry(ctx, id, &code, fmt.Sprintf("http_%d", code/100*100), attempts)
	}
}

func (s *Service) retry(ctx context.Context, id string, code *int, category string, attempts int) {
	if attempts >= s.MaxAttempts {
		s.finish(ctx, id, "dead_letter", code, category, attempts)
		return
	}
	base := time.Duration(1<<min(attempts, 12)) * 5 * time.Second
	if base > 6*time.Hour {
		base = 6 * time.Hour
	}
	jitter := time.Duration(rand.Int64N(int64(base / 4)))
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE webhook_deliveries SET state='retrying', next_attempt_at=$2, last_status_code=$3, last_response_category=$4,
		lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`, id, s.d.Now().Add(base+jitter), code, category)
}

func (s *Service) finish(ctx context.Context, id, state string, code *int, category string, attempts int) {
	var delivered *time.Time
	if state == "delivered" {
		t := s.d.Now()
		delivered = &t
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE webhook_deliveries SET state=$2, last_status_code=$3, last_response_category=$4, delivered_at=$5,
		lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`, id, state, code, category, delivered)
	if s.Observe != nil {
		s.Observe(state)
	}
}

// Deliveries lists delivery history (EXT-017 diagnostics; payloads are not exposed).
//
// Newest first; with afterAt set, only deliveries before (afterAt, afterID).
func (s *Service) Deliveries(ctx context.Context, realmID, subID string, limit int, afterAt *time.Time, afterID string) ([]Delivery, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, event_id, event_type, state, attempts, next_attempt_at, last_status_code, coalesce(last_response_category,''),
		delivered_at, created_at FROM webhook_deliveries WHERE realm_id=$1 AND subscription_id=$2
		AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5)) ORDER BY created_at DESC, id DESC LIMIT $3`, realmID, subID, limit, afterAt, afterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.EventID, &d.EventType, &d.State, &d.Attempts, &d.NextAttemptAt, &d.LastStatusCode, &d.LastResponse,
			&d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Replay re-queues a delivery with its original event ID (EXT-005).
func (s *Service) Replay(ctx context.Context, realmID, subID, deliveryID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state='pending', next_attempt_at=$4, attempts=0, lease_owner=NULL, lease_expires_at=NULL
			WHERE realm_id=$1 AND subscription_id=$2 AND id=$3`, realmID, subID, deliveryID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.delivery.replayed", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "webhook_delivery", ID: deliveryID}})
		return err
	})
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// share is the per-subscription cap within one delivery batch (TEN-018).
func share(n, batch int) int {
	if n <= 0 || n > batch {
		return batch
	}
	return n
}
