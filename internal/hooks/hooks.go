// Package hooks runs operator-provided synchronous pre-action hooks
// (EXT-009..EXT-012, EXT-017): registration eligibility, profile validation,
// access-token claims enrichment and authorization decisions.
//
// Safety contract:
//   - Hooks are HTTPS endpoints called through the egress policy (dial-time
//     address checks, no redirects, size and time limits).
//   - Requests are signed like webhooks ("v1,<base64 HMAC-SHA256>" over
//     "<id>.<timestamp>.<body>") so the hook can authenticate the server.
//   - Security-decision hooks (eligibility, profile validation, authorization)
//     always fail closed. Claims enrichment fails closed unless the hook is
//     explicitly configured with failure_mode "skip".
//   - Hooks can only restrict: they cannot grant permissions, skip required
//     authentication, override reserved claims or widen scopes, and every
//     denial is still audited by the caller (EXT-011).
//   - Post-action integrations are not hooks: they run asynchronously from the
//     transactional outbox (webhooks), so a slow integration can never leave
//     security state inconsistent (EXT-010).
package hooks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"net"
	"net/http"
	"net/url"
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
	"github.com/proudauth/proudauth/internal/token"
)

// Hook kinds.
const (
	KindRegistration  = "registration.eligibility"
	KindProfile       = "profile.validation"
	KindClaims        = "token.claims"
	KindAuthorization = "authorization.decision"
	// KindRisk supplies a risk level to authentication flow rules (AUT-014).
	// It never blocks on its own: a failure leaves the signal missing, and the
	// realm's rules decide what a missing signal means.
	KindRisk = "authentication.risk"
)

// MaxResponseBytes bounds hook responses.
const MaxResponseBytes = 64 << 10

// ErrHookDenied is returned when a hook refuses an action.
var ErrHookDenied = problem.ErrForbidden.WithDetail("the action was refused by policy")

// ErrHookUnavailable is returned when a fail-closed hook cannot be evaluated.
var ErrHookUnavailable = problem.ErrUnavailable.WithDetail("a required policy check is unavailable; try again later")

// Hook is a registered hook (the secret is never returned after creation).
type Hook struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	Kind                string     `json:"kind"`
	URL                 string     `json:"url"`
	TimeoutMS           int        `json:"timeout_ms"`
	FailureMode         string     `json:"failure_mode"`
	ClientIDs           []string   `json:"client_ids"`
	AllowPrivateNetwork bool       `json:"allow_private_network"`
	State               string     `json:"state"`
	Invocations         int64      `json:"invocations"`
	Failures            int64      `json:"failures"`
	LastLatencyMS       *int       `json:"last_latency_ms,omitempty"`
	LastFailureAt       *time.Time `json:"last_failure_at,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	// ContractVersion is the request/response contract the hook speaks,
	// sent as the ProudAuth-Hook-Version header (EXT-018).
	ContractVersion int `json:"contract_version"`
	// PluginID is set when a plugin manages the hook (EXT-014).
	PluginID  string    `json:"plugin_id,omitempty"`
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	secretCT  []byte
}

// Input creates or updates a hook.
type Input struct {
	Name                string   `json:"name"`
	Kind                string   `json:"kind"`
	URL                 string   `json:"url"`
	TimeoutMS           int      `json:"timeout_ms"`
	FailureMode         string   `json:"failure_mode"`
	ClientIDs           []string `json:"client_ids"`
	AllowPrivateNetwork bool     `json:"allow_private_network"`
	State               string   `json:"state"`
	// OwnerUserID is the accountable owner (DOM-009); it defaults to the
	// creating user.
	OwnerUserID string `json:"owner_user_id"`
	// ContractVersion pins the hook contract (EXT-018); 0 means the default.
	ContractVersion int `json:"contract_version"`
}

// Service manages and invokes hooks.
type Service struct {
	d *runtime.Deps
	// Egress is the base outbound policy; AllowPrivate is applied per hook only
	// when the operator permits private delivery destinations.
	Egress egress.Policy
	// Observe records invocation outcomes for metrics (kind, outcome).
	Observe func(kind, outcome string)
}

// New builds the service.
func New(d *runtime.Deps) *Service {
	return &Service{d: d, Egress: egress.Policy{RequireHTTPS: d.Cfg.Mode == "production", AllowCIDRs: d.Cfg.Delivery.EgressAllowlist,
		MaxBytes: MaxResponseBytes}}
}

const hookCols = `id, name, kind, url, timeout_ms, failure_mode, client_ids, allow_private_network, state, invocations, failures,
	last_latency_ms, last_failure_at, coalesce(last_error,''), version, created_at, secret_ciphertext, contract_version, coalesce(plugin_id,'')`

func scan(row pgx.Row) (*Hook, error) {
	var h Hook
	err := row.Scan(&h.ID, &h.Name, &h.Kind, &h.URL, &h.TimeoutMS, &h.FailureMode, &h.ClientIDs, &h.AllowPrivateNetwork, &h.State, &h.Invocations,
		&h.Failures, &h.LastLatencyMS, &h.LastFailureAt, &h.LastError, &h.Version, &h.CreatedAt, &h.secretCT, &h.ContractVersion, &h.PluginID)
	return &h, err
}

func (s *Service) validate(in *Input) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return problem.ErrValidation.WithField("name", "1..100 characters")
	}
	switch in.Kind {
	case KindRegistration, KindProfile, KindClaims, KindAuthorization, KindRisk:
	default:
		return problem.ErrValidation.WithField("kind", "registration.eligibility, profile.validation, token.claims, authorization.decision or authentication.risk")
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && (s.d.Cfg.Mode == "production" || u.Scheme != "http")) {
		return problem.ErrValidation.WithField("url", "must be an absolute https URL")
	}
	if in.AllowPrivateNetwork && !s.d.Cfg.Delivery.AllowPrivateWebhooks && len(s.d.Cfg.Delivery.EgressAllowlist) == 0 {
		return problem.ErrValidation.WithField("allow_private_network", "the operator egress policy does not permit private destinations (EXT-007)")
	}
	pol := s.policyFor(in.AllowPrivateNetwork)
	if err := pol.ValidateURL(in.URL); err != nil {
		return problem.ErrValidation.WithField("url", "destination not allowed by the egress policy")
	}
	if in.TimeoutMS == 0 {
		in.TimeoutMS = 1500
	}
	if in.TimeoutMS < 100 || in.TimeoutMS > 5000 {
		return problem.ErrValidation.WithField("timeout_ms", "100..5000")
	}
	if in.FailureMode == "" {
		in.FailureMode = "deny"
	}
	if in.FailureMode != "deny" && in.FailureMode != "skip" {
		return problem.ErrValidation.WithField("failure_mode", "deny or skip")
	}
	if in.FailureMode == "skip" && in.Kind != KindClaims {
		// Security-decision hooks always fail closed (EXT-012).
		return problem.ErrValidation.WithField("failure_mode", "only token.claims hooks may skip on failure")
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	if len(in.ClientIDs) > 50 {
		return problem.ErrValidation.WithField("client_ids", "at most 50")
	}
	if in.ClientIDs == nil {
		in.ClientIDs = []string{}
	}
	if in.ContractVersion == 0 {
		in.ContractVersion = contracts.Default(contracts.HookContract)
	}
	if !contracts.IsSupported(contracts.HookContract, in.ContractVersion) {
		return problem.ErrValidation.WithField("contract_version", "supported hook contract versions: "+contracts.SupportedList(contracts.HookContract))
	}
	return nil
}

// policyFor returns the egress policy for a hook: public destinations only,
// unless the hook opted in, in which case the operator's private-network
// policy (blanket switch or CIDR allowlist) applies (EXT-007).
func (s *Service) policyFor(private bool) egress.Policy {
	p := s.Egress
	if !private {
		p.AllowPrivate = false
		p.AllowCIDRs = nil
		return p
	}
	p.AllowPrivate = s.d.Cfg.Delivery.AllowPrivateWebhooks
	p.AllowCIDRs = s.d.Cfg.Delivery.EgressAllowlist
	return p
}

// Create registers a hook and returns its signing secret once.
func (s *Service) Create(ctx context.Context, realmID string, in Input, actor audit.Ref) (*Hook, string, error) {
	if err := s.validate(&in); err != nil {
		return nil, "", err
	}
	plain := "hksec_" + base64.StdEncoding.EncodeToString(secret.Random(32))
	id := ids.New("hok")
	ct, kv, err := s.d.Keys.Encrypt(keys.PurposeWebhook, []byte(plain), []byte("hook:"+id))
	if err != nil {
		return nil, "", err
	}
	var out *Hook
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		owner := in.OwnerUserID
		if owner == "" && actor.Type == "user" {
			owner = actor.ID
		}
		if owner != "" {
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state='active')`, realmID, owner).Scan(&live); err != nil {
				return err
			}
			if !live {
				return problem.ErrValidation.WithField("owner_user_id", "an active account of this realm is required")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO hooks (id, realm_id, name, kind, url, secret_ciphertext, key_version, timeout_ms, failure_mode, client_ids,
			allow_private_network, state, created_at, updated_at, owner_user_id, contract_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15)`,
			id, realmID, in.Name, in.Kind, in.URL, ct, kv, in.TimeoutMS, in.FailureMode, in.ClientIDs, in.AllowPrivateNetwork, in.State, s.d.Now(),
			nilIfEmptyString(owner), in.ContractVersion); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("name", "already in use")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.created", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "hook", ID: id}, Metadata: map[string]any{"kind": in.Kind, "url_host": hostOf(in.URL), "failure_mode": in.FailureMode}}); err != nil {
			return err
		}
		var err error
		out, err = scan(tx.QueryRow(ctx, `SELECT `+hookCols+` FROM hooks WHERE id=$1`, id))
		return err
	})
	return out, plain, err
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// Update replaces a hook's configuration (the secret is kept).
func (s *Service) Update(ctx context.Context, realmID, id string, version int64, in Input, actor audit.Ref) (*Hook, error) {
	if err := s.validate(&in); err != nil {
		return nil, err
	}
	var out *Hook
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE hooks SET name=$4, kind=$5, url=$6, timeout_ms=$7, failure_mode=$8, client_ids=$9, allow_private_network=$10,
			state=$11, version=version+1, updated_at=$12, contract_version=$13 WHERE realm_id=$1 AND id=$2 AND ($3=0 OR version=$3)`, realmID, id, version, in.Name, in.Kind,
			in.URL, in.TimeoutMS, in.FailureMode, in.ClientIDs, in.AllowPrivateNetwork, in.State, s.d.Now(), in.ContractVersion)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrPrecondition
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.updated", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "hook", ID: id}, Metadata: map[string]any{"kind": in.Kind, "state": in.State, "failure_mode": in.FailureMode}}); err != nil {
			return err
		}
		out, err = scan(tx.QueryRow(ctx, `SELECT `+hookCols+` FROM hooks WHERE id=$1`, id))
		return err
	})
	return out, err
}

// Delete removes a hook.
func (s *Service) Delete(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM hooks WHERE realm_id=$1 AND id=$2`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.deleted", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "hook", ID: id}})
		return err
	})
}

// SetState disables or re-enables a hook through an emergency control
// (SEC-020) without revalidating its destination.
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref, reason string) error {
	if state != "active" && state != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The switch-off is remembered, so enabling or upgrading a plugin
		// does not undo it (EXT-014).
		tag, err := tx.Exec(ctx, `UPDATE hooks SET state=$3, emergency_disabled=($3='disabled'), version=version+1, updated_at=$4 WHERE realm_id=$1 AND id=$2`,
			realmID, id, state, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.state_changed", RealmID: realmID, Actor: actor, Category: "emergency",
			Target: &audit.Ref{Type: "hook", ID: id}, ReasonCode: reason, Metadata: map[string]any{"state": state}})
		return err
	})
}

// HasActive reports whether the realm has any active hook, so callers can
// avoid retrying transactions that may call one (DB-014).
func (s *Service) HasActive(ctx context.Context, realmID string) bool {
	var n bool
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hooks WHERE realm_id=$1 AND state='active')`, realmID).Scan(&n); err != nil {
		return true // unknown: assume a hook may run
	}
	return n
}

// Get returns a hook.
func (s *Service) Get(ctx context.Context, realmID, id string) (*Hook, error) {
	h, err := scan(s.d.DB.Pool.QueryRow(ctx, `SELECT `+hookCols+` FROM hooks WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return h, err
}

// List returns a realm's hooks.
func (s *Service) List(ctx context.Context, realmID string) ([]*Hook, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+hookCols+` FROM hooks WHERE realm_id=$1 ORDER BY kind, name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Hook{}
	for rows.Next() {
		h, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Service) active(ctx context.Context, realmID, kind, clientID string) ([]*Hook, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+hookCols+` FROM hooks WHERE realm_id=$1 AND kind=$2 AND state='active' ORDER BY name`, realmID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Hook{}
	for rows.Next() {
		h, err := scan(rows)
		if err != nil {
			return nil, err
		}
		if len(h.ClientIDs) > 0 && clientID != "" && !slices.Contains(h.ClientIDs, clientID) {
			continue
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// call invokes one hook and decodes its JSON response into out.
func (s *Service) call(ctx context.Context, realmID string, h *Hook, payload map[string]any, out any) error {
	key, err := s.d.Keys.Decrypt(keys.PurposeWebhook, h.secretCT, []byte("hook:"+h.ID))
	if err != nil {
		return err
	}
	payload["hook_kind"] = h.Kind
	payload["realm_id"] = realmID
	body, _ := json.Marshal(payload)
	msgID := ids.New("hkm")
	ts := strconv.FormatInt(s.d.Now().Unix(), 10)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(key), "hksec_"))
	mac := hmac.New(sha256.New, raw)
	mac.Write([]byte(msgID + "." + ts + "."))
	mac.Write(body)
	cctx, cancel := context.WithTimeout(ctx, time.Duration(h.TimeoutMS)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Webhook-Id", msgID)
	req.Header.Set("Webhook-Timestamp", ts)
	req.Header.Set("Webhook-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	// The contract version is sent on every call and checked on the answer
	// (EXT-018): a hook built for another version fails as its failure mode
	// dictates instead of being misread.
	contract := h.ContractVersion
	if contract == 0 {
		contract = contracts.Default(contracts.HookContract)
	}
	req.Header.Set(contracts.HookVersionHeader, strconv.Itoa(contract))
	pol := s.policyFor(h.AllowPrivateNetwork)
	pol.Timeout = time.Duration(h.TimeoutMS) * time.Millisecond
	res, err := pol.Client().Do(req)
	if err != nil {
		return fmt.Errorf("hook unreachable: %w", err)
	}
	defer res.Body.Close()
	data, err := pol.ReadLimited(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return statusError{code: res.StatusCode}
	}
	if v := res.Header.Get(contracts.HookVersionHeader); v != "" && v != strconv.Itoa(contract) {
		return errors.New("hook returned a malformed response: contract version " + canonical.Truncate(v, 8) + " was not requested")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return errors.New("hook returned a malformed response")
	}
	return nil
}

// statusError is a non-200 hook response.
type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("hook returned status %d", e.code) }

// errorCategory reduces a hook failure to a coarse, non-sensitive category.
func errorCategory(err error) (string, *int) {
	var se statusError
	switch {
	case err == nil:
		return "", nil
	case errors.As(err, &se):
		return "status", &se.code
	case errors.Is(err, egress.ErrForbiddenDestination):
		return "egress_denied", nil
	case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout") || isTimeout(err):
		return "timeout", nil
	case strings.Contains(err.Error(), "malformed"):
		return "malformed_response", nil
	case strings.Contains(err.Error(), "unreachable"):
		return "unreachable", nil
	}
	return "error", nil
}

// isTimeout reports a network timeout that is not a context deadline, such
// as the transport's response-header timeout.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (s *Service) record(ctx context.Context, h *Hook, start time.Time, failure error) {
	latency := int(time.Since(start).Milliseconds())
	cat, code := errorCategory(failure)
	o := "ok"
	if failure != nil {
		o = "failure"
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `INSERT INTO hook_invocations (hook_id, realm_id, invoked_at, outcome, latency_ms, error_category, status_code)
		SELECT id, realm_id, $2, $3, $4, nullif($5,''), $6 FROM hooks WHERE id=$1`, h.ID, s.d.Now(), o, latency, cat, code)
	outcome := "ok"
	if failure != nil {
		outcome = "failure"
		msg := failure.Error()
		if len(msg) > 200 {
			msg = canonical.Truncate(msg, 200)
		}
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE hooks SET invocations=invocations+1, failures=failures+1, last_latency_ms=$2, last_failure_at=$3, last_error=$4 WHERE id=$1`,
			h.ID, latency, s.d.Now(), msg)
	} else {
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE hooks SET invocations=invocations+1, last_latency_ms=$2 WHERE id=$1`, h.ID, latency)
	}
	if s.Observe != nil {
		s.Observe(h.Kind, outcome)
	}
}

// Invocation is one recorded hook call (EXT-017).
type Invocation struct {
	InvokedAt     time.Time `json:"invoked_at"`
	Outcome       string    `json:"outcome"`
	LatencyMS     int       `json:"latency_ms"`
	ErrorCategory string    `json:"error_category,omitempty"`
	StatusCode    *int      `json:"status_code,omitempty"`
}

// Diagnostics summarizes a hook's recent behavior (EXT-017).
type Diagnostics struct {
	Health      string       `json:"health"`
	Recent      int          `json:"recent_invocations"`
	Failures    int          `json:"recent_failures"`
	P50MS       int          `json:"latency_p50_ms"`
	P95MS       int          `json:"latency_p95_ms"`
	Invocations []Invocation `json:"invocations"`
}

// Diagnose returns the hook's last 100 invocations and a summary. It never
// includes payloads, responses or secrets.
func (s *Service) Diagnose(ctx context.Context, realmID, id string) (*Diagnostics, error) {
	if _, err := s.Get(ctx, realmID, id); err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT invoked_at, outcome, latency_ms, coalesce(error_category,''), status_code FROM hook_invocations
		WHERE realm_id=$1 AND hook_id=$2 ORDER BY invoked_at DESC LIMIT 100`, realmID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d := &Diagnostics{Invocations: []Invocation{}}
	var lat []int
	for rows.Next() {
		var in Invocation
		if err := rows.Scan(&in.InvokedAt, &in.Outcome, &in.LatencyMS, &in.ErrorCategory, &in.StatusCode); err != nil {
			return nil, err
		}
		d.Invocations = append(d.Invocations, in)
		lat = append(lat, in.LatencyMS)
		if in.Outcome != "ok" {
			d.Failures++
		}
	}
	d.Recent = len(d.Invocations)
	if len(lat) > 0 {
		slices.Sort(lat)
		d.P50MS = lat[len(lat)/2]
		d.P95MS = lat[min(len(lat)-1, len(lat)*95/100)]
	}
	switch {
	case d.Recent == 0:
		d.Health = "unknown"
	case d.Failures*10 > d.Recent:
		d.Health = "degraded"
	default:
		d.Health = "healthy"
	}
	return d, rows.Err()
}

// PruneInvocations removes invocation records older than the retention.
func (s *Service) PruneInvocations(ctx context.Context, keep time.Duration) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM hook_invocations WHERE invoked_at < $1`, s.d.Now().Add(-keep))
	return tag.RowsAffected(), err
}

// Decision is a pre-action hook verdict.
type Decision struct {
	Allow      bool              `json:"allow"`
	ReasonCode string            `json:"reason_code,omitempty"`
	Errors     map[string]string `json:"errors,omitempty"`
}

// CheckRegistration asks registration-eligibility hooks; any refusal or
// failure denies (fail closed).
func (s *Service) CheckRegistration(ctx context.Context, realmID, clientID string, subject map[string]any) error {
	return s.decide(ctx, realmID, KindRegistration, clientID, map[string]any{"client_id": clientID, "registration": subject})
}

// CheckProfile asks profile-validation hooks about a proposed profile.
func (s *Service) CheckProfile(ctx context.Context, realmID, userID string, profile map[string]any) error {
	return s.decide(ctx, realmID, KindProfile, "", map[string]any{"user_id": userID, "profile": profile})
}

func (s *Service) decide(ctx context.Context, realmID, kind, clientID string, payload map[string]any) error {
	hs, err := s.active(ctx, realmID, kind, clientID)
	if err != nil {
		return err
	}
	for _, h := range hs {
		start := time.Now()
		var d Decision
		err := s.call(ctx, realmID, h, payload, &d)
		s.record(ctx, h, start, err)
		if err != nil {
			return ErrHookUnavailable
		}
		if !d.Allow {
			e := ErrHookDenied
			if d.ReasonCode != "" && len(d.ReasonCode) <= 64 {
				e = e.WithExtension("reason_code", d.ReasonCode)
			}
			for f, m := range d.Errors {
				if len(f) <= 64 && len(m) <= 200 {
					e = problem.ErrValidation.WithField(f, m)
				}
			}
			return e
		}
	}
	return nil
}

// RiskInput describes a sign-in for risk assessment. It carries no
// credentials and only the truncated network context.
type RiskInput struct {
	UserID         string `json:"user_id"`
	ClientID       string `json:"client_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	Method         string `json:"method"`
	Network        string `json:"network,omitempty"`
	KnownDevice    bool   `json:"known_device"`
	FailedAttempts int    `json:"failed_attempts"`
}

// RiskVerdict is the combined result of risk hooks.
type RiskVerdict struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons,omitempty"`
	// Partial: another hook failed, so Level is only a lower bound.
	Partial bool `json:"-"`
}

var riskRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// Risk asks the realm's authentication.risk hooks for a risk level and
// returns the highest. It returns (nil, nil) when no hook is active. When a
// hook fails or answers outside the contract it returns ErrHookUnavailable
// with the levels the other hooks reported, marked Partial (a lower bound):
// one failing hook never hides another hook's high verdict.
func (s *Service) Risk(ctx context.Context, realmID string, in RiskInput) (*RiskVerdict, error) {
	hs, err := s.active(ctx, realmID, KindRisk, in.ClientID)
	if err != nil || len(hs) == 0 {
		return nil, err
	}
	b, _ := json.Marshal(in)
	var payload map[string]any
	_ = json.Unmarshal(b, &payload)
	out := &RiskVerdict{}
	for _, h := range hs {
		start := time.Now()
		var resp RiskVerdict
		err := s.call(ctx, realmID, h, map[string]any{"authentication": payload}, &resp)
		if err == nil && riskRank[resp.Level] == 0 {
			err = errors.New("hook returned an unknown risk level")
		}
		s.record(ctx, h, start, err)
		if err != nil {
			out.Partial = true
			continue
		}
		if riskRank[resp.Level] > riskRank[out.Level] {
			out.Level = resp.Level
		}
		for _, r := range resp.Reasons {
			if len(out.Reasons) < 10 && len(r) <= 64 && !slices.Contains(out.Reasons, r) {
				out.Reasons = append(out.Reasons, r)
			}
		}
	}
	if out.Partial {
		if out.Level == "" {
			return nil, ErrHookUnavailable
		}
		return out, ErrHookUnavailable
	}
	return out, nil
}

// ClaimsInput describes a token being minted.
type ClaimsInput struct {
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	ClientID    string   `json:"client_id"`
	Audience    string   `json:"audience"`
	Scopes      []string `json:"scopes"`
	OrgID       string   `json:"organization_id,omitempty"`
	TokenKind   string   `json:"token_kind"`
}

// Bounds of hook answers (EXT-009, EXT-011; api/hooks).
const (
	// MaxClaims and MaxClaimsBytes bound one token.claims answer: at most 20
	// claims, at most 4 KiB serialized.
	MaxClaims      = 20
	MaxClaimsBytes = 4 << 10
	// MaxObligations bounds the obligations of one authorization.decision
	// answer.
	MaxObligations = 5
)

// errTooManyObligations marks an authorization answer outside the contract.
var errTooManyObligations = errors.New("hook returned a malformed response: more than 5 obligations")

// checkClaims enforces the token.claims answer contract (EXT-011): no
// reserved claim, roles or permissions, claim names of at most 64
// characters, at most MaxClaims claims and MaxClaimsBytes serialized. An
// answer outside it is malformed: nothing of it is used, and the call fails
// as the hook's failure mode says.
func checkClaims(claims map[string]any) error {
	for k := range claims {
		if token.ReservedClaims[k] || k == "permissions" || k == "roles" || len(k) > 64 {
			return fmt.Errorf("hook returned a malformed response: it attempted to set protected or over-long claim %q", canonical.Truncate(k, 64))
		}
	}
	if raw, _ := json.Marshal(claims); len(claims) > MaxClaims || len(raw) > MaxClaimsBytes {
		return errors.New("hook returned a malformed response: more than 20 claims or more than 4 KiB of claims")
	}
	return nil
}

// Claims returns additional access-token claims from claims hooks. Reserved
// claims, oversized values and more than 20 claims are refused (EXT-011).
func (s *Service) Claims(ctx context.Context, realmID string, in ClaimsInput) (map[string]any, error) {
	hs, err := s.active(ctx, realmID, KindClaims, in.ClientID)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, h := range hs {
		start := time.Now()
		var resp struct {
			Claims map[string]any `json:"claims"`
		}
		b, _ := json.Marshal(in)
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		err := s.call(ctx, realmID, h, map[string]any{"token": payload}, &resp)
		if err == nil {
			err = checkClaims(resp.Claims)
		}
		s.record(ctx, h, start, err)
		if err != nil {
			if h.FailureMode == "skip" {
				continue
			}
			return nil, ErrHookUnavailable
		}
		for k, v := range resp.Claims {
			out[k] = v
		}
	}
	return out, nil
}

// AuthzInput describes an authorization decision.
type AuthzInput struct {
	Subject  map[string]any `json:"subject"`
	Action   string         `json:"action"`
	Resource map[string]any `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// AuthzVerdict is the hook's response: hooks can deny or add obligations only.
type AuthzVerdict struct {
	Allow       bool             `json:"allow"`
	ReasonCode  string           `json:"reason_code,omitempty"`
	Obligations []map[string]any `json:"obligations,omitempty"`
}

// Authorize evaluates authorization-decision hooks after RBAC and policies.
// It returns (allowed, reason, obligations); failures deny.
func (s *Service) Authorize(ctx context.Context, realmID, clientID string, in AuthzInput) (bool, string, []map[string]any) {
	hs, err := s.active(ctx, realmID, KindAuthorization, clientID)
	if err != nil {
		return false, "HOOK_UNAVAILABLE", nil
	}
	var obligations []map[string]any
	b, _ := json.Marshal(in)
	for _, h := range hs {
		var payload map[string]any
		_ = json.Unmarshal(b, &payload)
		start := time.Now()
		var v AuthzVerdict
		err := s.call(ctx, realmID, h, map[string]any{"decision": payload}, &v)
		if err == nil && len(v.Obligations) > MaxObligations {
			// Outside the contract: the answer is malformed, the decision
			// fails closed and the diagnostics record the failure (EXT-017).
			err = errTooManyObligations
		}
		s.record(ctx, h, start, err)
		if errors.Is(err, errTooManyObligations) {
			return false, "HOOK_INVALID_RESPONSE", nil
		}
		if err != nil {
			return false, "HOOK_UNAVAILABLE", nil
		}
		if !v.Allow {
			reason := v.ReasonCode
			if reason == "" || len(reason) > 64 {
				reason = "HOOK_DENIED"
			}
			return false, reason, nil
		}
		obligations = append(obligations, v.Obligations...)
	}
	return true, "", obligations
}

func nilIfEmptyString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
