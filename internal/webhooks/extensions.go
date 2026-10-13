package webhooks

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// Validate checks a subscription exactly as the API does. Plugin packages
// validate every part they would configure before a review starts (EXT-014).
func (s *Service) Validate(in *Input) error { return s.validate(in) }

// ErrPluginManaged refuses ordinary API changes to a subscription a plugin
// manages: the plugin is changed, disabled or rolled back instead, so its
// parts never drift from the reviewed package (EXT-014).
var ErrPluginManaged = problem.ErrConflict.WithDetail("this subscription is managed by a plugin; change, disable or roll back the plugin instead")

// PluginOf returns the plugin managing a subscription ("" when none).
func (s *Service) PluginOf(ctx context.Context, realmID, id string) (string, error) {
	var p string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT coalesce(plugin_id,'') FROM webhook_subscriptions WHERE realm_id=$1 AND id=$2`, realmID, id).Scan(&p)
	if storage.IsNoRows(err) {
		return "", nil
	}
	return p, err
}

// GuardManual returns ErrPluginManaged for a plugin-managed subscription.
func (s *Service) GuardManual(ctx context.Context, realmID, id string) error {
	p, err := s.PluginOf(ctx, realmID, id)
	if err != nil {
		return err
	}
	if p != "" {
		return ErrPluginManaged.WithExtension("plugin_id", p)
	}
	return nil
}

// ApplyPluginTx creates or updates, by name, a subscription a plugin manages
// (EXT-014). An update keeps the signing secret, so receivers keep verifying
// across plugin upgrades and rollbacks; the secret of a new subscription is
// returned once. A subscription of the same name that the plugin does not
// manage is never taken over.
func (s *Service) ApplyPluginTx(ctx context.Context, tx pgx.Tx, realmID, pluginID string, in Input, actor audit.Ref) (string, string, error) {
	if err := s.validate(&in); err != nil {
		return "", "", err
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT id FROM webhook_subscriptions WHERE realm_id=$1 AND plugin_id=$2 AND name=$3 FOR UPDATE`, realmID, pluginID, in.Name).Scan(&id)
	if storage.IsNoRows(err) {
		var taken bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM webhook_subscriptions WHERE realm_id=$1 AND name=$2 AND coalesce(plugin_id,'') <> $3)`,
			realmID, in.Name, pluginID).Scan(&taken); err != nil {
			return "", "", err
		}
		if taken {
			return "", "", problem.ErrConflict.WithField("webhooks", "a subscription named "+in.Name+" exists and is not managed by this plugin")
		}
		in.pluginID = pluginID
		id, plain, err := s.CreateTx(ctx, tx, realmID, in, actor)
		return id, plain, err
	}
	if err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE webhook_subscriptions SET organization_id=$3, destination_url=$4, event_types=$5, allow_private_network=$6,
		payload_form=$7, event_version=$8, state=CASE WHEN emergency_disabled THEN 'disabled' ELSE 'active' END, version=version+1, updated_at=$9
		WHERE realm_id=$1 AND id=$2`, realmID, id,
		nilIfEmpty(in.OrganizationID), in.DestinationURL, in.EventTypes, in.AllowPrivateNetwork, in.PayloadForm, in.EventVersion, s.d.Now()); err != nil {
		return "", "", err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.updated", RealmID: realmID, OrgID: in.OrganizationID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: "webhook", ID: id}, Metadata: map[string]any{"plugin_id": pluginID, "destination_host": hostOf(in.DestinationURL),
			"event_version": in.EventVersion}})
	return id, "", err
}

// RemovePluginPartsTx deletes the plugin's subscriptions whose names are not
// in keep (all of them for an empty keep) and returns their IDs.
func (s *Service) RemovePluginPartsTx(ctx context.Context, tx pgx.Tx, realmID, pluginID string, keep []string, actor audit.Ref) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id, name FROM webhook_subscriptions WHERE realm_id=$1 AND plugin_id=$2 FOR UPDATE`, realmID, pluginID)
	if err != nil {
		return nil, err
	}
	var drop []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		if !slices.Contains(keep, name) {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		if _, err := tx.Exec(ctx, `DELETE FROM webhook_subscriptions WHERE id=$1`, id); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "webhook.deleted", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "webhook", ID: id}, Metadata: map[string]any{"plugin_id": pluginID}}); err != nil {
			return nil, err
		}
	}
	return drop, nil
}

// SetPluginStateTx activates or disables every subscription of a plugin in
// the caller's transaction (EXT-014: disabling a plugin stops all its parts
// at once). Deliveries already queued stay queued and resume on re-enable;
// the dispatcher skips inactive subscriptions meanwhile.
func (s *Service) SetPluginStateTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, state string) (int, error) {
	if state != "active" && state != "disabled" {
		return 0, problem.ErrValidation.WithField("state", "active or disabled")
	}
	// Parts an administrator switched off in an emergency stay off.
	tag, err := tx.Exec(ctx, `UPDATE webhook_subscriptions SET state=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND plugin_id=$2 AND state<>$3
		AND NOT (emergency_disabled AND $3='active')`, realmID, pluginID, state, s.d.Now())
	return int(tag.RowsAffected()), err
}

// CallResult is the outcome of one direct call.
type CallResult struct {
	Status int
	// Outcome is a coarse, non-sensitive classification (success, gone,
	// http_400, http_500, timeout, network_error, egress_denied, ...).
	Outcome string
	// Permanent failures are not retried: the receiver refused the message
	// (4xx other than 408 and 429, or 410) or the subscription is disabled.
	Permanent bool
}

// ErrCallFailed marks an unsuccessful direct call; the result says why.
var ErrCallFailed = errors.New("webhooks: call failed")

// Call POSTs one signed message to an active subscription's destination
// outside the event pipeline: lifecycle workflow steps (EXT-015) reuse the
// subscription's destination, signing secret and egress policy instead of
// carrying endpoints and secrets of their own. The request is signed like an
// event delivery (Webhook-Id is msgID) and carries idempotencyKey as the
// Idempotency-Key header, stable across retries, so the receiver can
// deduplicate a repeated step (EXT-016).
func (s *Service) Call(ctx context.Context, realmID, subID, msgID, idempotencyKey string, body []byte, timeout time.Duration) (CallResult, error) {
	var dest, state string
	var ct, prev []byte
	var prevExp *time.Time
	var allowPrivate bool
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT destination_url, state, secret_ciphertext, previous_secret_ciphertext, previous_secret_expires_at,
		allow_private_network FROM webhook_subscriptions WHERE realm_id=$1 AND id=$2`, realmID, subID).Scan(&dest, &state, &ct, &prev, &prevExp, &allowPrivate); err != nil {
		if storage.IsNoRows(err) {
			return CallResult{Outcome: "subscription_missing", Permanent: true}, ErrCallFailed
		}
		return CallResult{Outcome: "error"}, err
	}
	if state != "active" {
		// A paused subscription may resume; a disabled one was stopped on
		// purpose (an emergency control or a disabled plugin).
		return CallResult{Outcome: "subscription_" + state, Permanent: state == "disabled"}, ErrCallFailed
	}
	sec, err := s.d.Keys.Decrypt(keys.PurposeWebhook, ct, []byte("webhook:"+subID))
	if err != nil {
		return CallResult{Outcome: "secret_unavailable", Permanent: true}, ErrCallFailed
	}
	if msgID == "" {
		msgID = ids.New("wmc")
	}
	ts := s.d.Now().Unix()
	sig := Sign(string(sec), msgID, ts, body)
	if prev != nil && prevExp != nil && s.d.Now().Before(*prevExp) {
		if p, err := s.d.Keys.Decrypt(keys.PurposeWebhook, prev, []byte("webhook:"+subID)); err == nil {
			sig += " " + Sign(string(p), msgID, ts, body)
		}
	}
	pol := s.Policy
	if !allowPrivate {
		pol = s.publicPolicy()
	}
	if timeout > 0 && (pol.Timeout == 0 || timeout < pol.Timeout) {
		pol.Timeout = timeout
	}
	cctx := ctx
	if pol.Timeout > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, pol.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, dest, bytes.NewReader(body))
	if err != nil {
		return CallResult{Outcome: "invalid_destination", Permanent: true}, ErrCallFailed
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webhook-Id", msgID)
	req.Header.Set("Webhook-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("Webhook-Signature", sig)
	req.Header.Set("Idempotency-Key", idempotencyKey)
	req.Header.Set("User-Agent", "ProudAuth-Workflows/1")
	res, err := pol.Client().Do(req)
	if err != nil {
		category := "network_error"
		if errors.Is(err, egress.ErrForbiddenDestination) {
			category = "egress_denied"
		} else if errors.Is(err, context.DeadlineExceeded) {
			category = "timeout"
		}
		return CallResult{Outcome: category}, ErrCallFailed
	}
	_, _ = pol.ReadLimited(res.Body)
	res.Body.Close()
	code := res.StatusCode
	switch {
	case code >= 200 && code < 300:
		return CallResult{Status: code, Outcome: "success"}, nil
	case code == http.StatusGone:
		return CallResult{Status: code, Outcome: "gone", Permanent: true}, ErrCallFailed
	case code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests:
		return CallResult{Status: code, Outcome: "http_400", Permanent: true}, ErrCallFailed
	}
	return CallResult{Status: code, Outcome: "http_" + strconv.Itoa(code/100*100)}, ErrCallFailed
}
