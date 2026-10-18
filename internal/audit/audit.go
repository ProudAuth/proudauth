// Package audit records structured, actor-aware security evidence.
//
// Events are written inside the same database transaction as the mutation they
// describe, so a privileged change cannot succeed unaudited (AUD-004, DB-009).
// Secrets are never recorded (AUD-003): metadata keys that look secret-bearing are
// redacted before serialization, and values that look like bearer credentials are
// masked as a second line of defense.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/storage"
)

// Outcomes.
const (
	Success = "success"
	Failure = "failure"
	Denied  = "denied"
)

// Ref identifies a principal or object.
type Ref struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	SessionID string `json:"session_id,omitempty"`
}

// System is the actor for server-initiated actions.
var System = Ref{Type: "system", ID: "system"}

// Event is one audit record (AUD-001).
type Event struct {
	ID                   string         `json:"id"`
	SchemaVersion        int            `json:"schema_version"`
	Type                 string         `json:"type"`
	OccurredAt           time.Time      `json:"occurred_at"`
	RealmID              string         `json:"realm_id,omitempty"`
	OrgID                string         `json:"org_id,omitempty"`
	Actor                Ref            `json:"actor"`
	Subject              *Ref           `json:"subject,omitempty"`
	Target               *Ref           `json:"target,omitempty"`
	Outcome              string         `json:"outcome"`
	ReasonCode           string         `json:"reason_code,omitempty"`
	RequestID            string         `json:"request_id,omitempty"`
	ClientID             string         `json:"client_id,omitempty"`
	SessionID            string         `json:"session_id,omitempty"`
	GrantID              string         `json:"grant_id,omitempty"`
	ImpersonationGrantID string         `json:"impersonation_grant_id,omitempty"`
	Source               string         `json:"source"`
	ReportingService     string         `json:"reporting_service,omitempty"`
	IPContext            string         `json:"ip_context,omitempty"`
	Category             string         `json:"category,omitempty"`
	Metadata             map[string]any `json:"metadata,omitempty"`
	ContentHash          string         `json:"content_hash,omitempty"`
	BatchID              string         `json:"batch_id,omitempty"`
}

// Recorder writes audit events.
type Recorder struct {
	Now    func() time.Time
	FullIP bool
	// Observe, when set, sees every recorded event and write error. It feeds
	// alertable security signals (OPS-004); it must not block or fail.
	Observe func(ev Event, err error)
	// Alert, when set, is called in the recording transaction for events that
	// carry a security signal (AUD-012); an error aborts the transaction, so an
	// alert is published exactly when its evidence commits.
	Alert func(ctx context.Context, q storage.Querier, ev Event, signal string) error
	// Hooks run in the recording transaction for every recorded event
	// (security-event transmission, AUD-016); an error aborts the
	// transaction. They are set at startup and must return quickly for the
	// events they ignore.
	Hooks []func(ctx context.Context, q storage.Querier, ev Event) error
}

// SecuritySignal classifies an audit event into a bounded set of alertable
// signals (OPS-004). It returns "" for ordinary events.
func SecuritySignal(ev Event) string {
	switch {
	case ev.Type == "token.refresh.reuse_detected" || ev.Type == "security.refresh_reuse_detected":
		return "refresh_reuse"
	case ev.Type == "support.impersonation.denied":
		return "impersonation_denied"
	case ev.Type == "support.impersonation.started" || ev.Type == "support.impersonation.approved":
		return "impersonation_activity"
	case ev.ReasonCode == "ORGANIZATION_MISMATCH" || ev.ReasonCode == "CROSS_TENANT":
		return "cross_tenant_denial"
	case ev.Type == "recovery.assisted" || ev.Type == "mfa.recovery_code.used" || ev.Type == "recovery.password_reset.completed":
		return "factor_recovery"
	case strings.HasPrefix(ev.Type, "signing_key.") && ev.Type != "signing_key.activated":
		return "signing_key_change"
	case strings.HasPrefix(ev.Type, "bootstrap."):
		return "bootstrap"
	case ev.Type == "automation_credential.created" || ev.Type == "client.credential.issued":
		return "credential_issued"
	case ev.Type == "credential.password.compromised" || ev.Type == "security.credential_compromised":
		return "credential_compromised"
	case strings.HasPrefix(ev.Type, "emergency.") || ev.Category == "emergency":
		return "emergency_action"
	case ev.Type == "authentication.succeeded" && ev.Metadata["protected"] == true:
		return "protected_account_signin"
	case ev.Type == "role.assigned" && ev.Metadata["privileged"] == true:
		return "privileged_grant"
	case ev.Type == "authentication.flow.evaluated" && ev.Metadata["outcome"] == "review":
		return "authentication_review"
	case ev.Type == "realm.policy.updated" || strings.HasPrefix(ev.Type, "federation.provider.") || ev.Type == "hook.created" ||
		ev.Type == "hook.updated" || ev.Type == "webhook.created" || ev.Type == "audit.legal_hold.released":
		return "configuration_change"
	}
	return ""
}

var secretKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|otp|code|seed|cookie|authorization|private|pepper|verifier|assertion|credential_value|recovery|api[_-]?key|access[_-]?key)`)

// allowlisted metadata keys that contain the substrings above but are not secret.
var safeKeys = map[string]bool{
	"reason_code": true, "token_kind": true, "token_type": true, "code_challenge_method": true,
	"credential_type": true, "credential_id": true, "error_code": true, "grant_type": true,
	"token_family_id": true, "recovery_method": true, "code_length": true, "secret_version": true,
	"recovery_codes_remaining": true, "password_changed": true, "token_endpoint_auth_method": true,
	"key_id": true, "display_prefix": true, "authorization_revision": true, "secret_kind": true,
	"recovery_restricted": true, "recovery_id": true, "secret_rotated": true,
}

var bearerLike = regexp.MustCompile(`pa_(rt|ac|at|it|hc|inv|tx|csrf|ses|cs|key|pat|lnk|dc|rat|dl|rmd|scim)_[A-Za-z0-9_\-]{8,}`)
var jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*`)

// Redact returns a copy of metadata with secret-bearing content removed.
func Redact(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if secretKey.MatchString(k) && !safeKeys[strings.ToLower(k)] {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch x := v.(type) {
	case string:
		x = bearerLike.ReplaceAllString(x, "[REDACTED]")
		return jwtLike.ReplaceAllString(x, "[REDACTED]")
	case map[string]any:
		return Redact(x)
	case []any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = redactValue(x[i])
		}
		return out
	case []string:
		out := make([]string, len(x))
		for i := range x {
			out[i] = redactValue(x[i]).(string)
		}
		return out
	default:
		return v
	}
}

// Record writes an event through q, which must be the transaction performing the
// audited mutation. An error here must abort that transaction (AUD-004).
// Events recorded under an Override take its category and, when they carry
// none, its reason.
func (r *Recorder) Record(ctx context.Context, q storage.Querier, ev Event) (string, error) {
	info := reqctx.From(ctx)
	if ev.ID == "" {
		ev.ID = ids.New(ids.AuditEvent)
	}
	ev.SchemaVersion = 1
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = r.Now().UTC()
	}
	if ev.Outcome == "" {
		ev.Outcome = Success
	}
	if ev.Source == "" {
		ev.Source = "server"
	}
	if o, ok := ctx.Value(overrideKey{}).(Override); ok {
		if o.Category != "" {
			ev.Category = o.Category
		}
		if ev.ReasonCode == "" {
			ev.ReasonCode = o.Reason
		}
	}
	if ev.Category == "" {
		ev.Category = "security"
	}
	if ev.RequestID == "" {
		ev.RequestID = info.RequestID
	}
	if ev.IPContext == "" {
		ev.IPContext = reqctx.NetworkContext(info.ClientIP, r.FullIP)
	}
	if ev.Actor.ID == "" {
		ev.Actor = System
	}
	// Identifiers can come from the request (a client_id, a Basic user
	// name): each is stored bounded and printable (BoundID).
	ev.Actor.ID = BoundID(ev.Actor.ID)
	if ev.Subject != nil {
		s := *ev.Subject
		s.ID = BoundID(s.ID)
		ev.Subject = &s
	}
	if ev.Target != nil {
		t := *ev.Target
		t.ID = BoundID(t.ID)
		ev.Target = &t
	}
	ev.Metadata = Redact(ev.Metadata)
	ev.ContentHash = ContentHash(ev)

	meta, err := json.Marshal(ev.Metadata)
	if err != nil {
		return "", err
	}
	if ev.Metadata == nil {
		meta = []byte("{}")
	}
	var subjType, subjID, tgtType, tgtID *string
	if ev.Subject != nil {
		subjType, subjID = &ev.Subject.Type, &ev.Subject.ID
	}
	if ev.Target != nil {
		tgtType, tgtID = &ev.Target.Type, &ev.Target.ID
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_events (id, schema_version, type, occurred_at, recorded_at, realm_id, organization_id,
		actor_type, actor_id, actor_session_id, subject_type, subject_id, target_type, target_id, outcome, reason_code,
		request_id, client_id, session_id, grant_id, impersonation_grant_id, source, reporting_service, ip_context,
		metadata, category, content_hash)
		VALUES ($1,$2,$3,$4,now(),$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`,
		ev.ID, ev.SchemaVersion, ev.Type, ev.OccurredAt, nullable(ev.RealmID), nullable(ev.OrgID),
		ev.Actor.Type, ev.Actor.ID, nullable(ev.Actor.SessionID), subjType, subjID, tgtType, tgtID, ev.Outcome,
		nullable(ev.ReasonCode), nullable(ev.RequestID), nullable(ev.ClientID), nullable(ev.SessionID), nullable(ev.GrantID),
		nullable(ev.ImpersonationGrantID), ev.Source, nullable(ev.ReportingService), nullable(ev.IPContext), meta, ev.Category, ev.ContentHash)
	if r.Observe != nil {
		if err != nil {
			r.Observe(ev, err)
		} else {
			// Signals count evidence that exists: an event is observed when
			// its transaction commits, not when a rolled back or retried
			// attempt writes it.
			observe := r.Observe
			storage.AfterCommit(q, func() { observe(ev, nil) })
		}
	}
	if err != nil {
		return "", err
	}
	if r.Alert != nil {
		if sig := SecuritySignal(ev); sig != "" {
			if err := r.Alert(ctx, q, ev, sig); err != nil {
				return "", err
			}
		}
	}
	for _, h := range r.Hooks {
		if err := h(ctx, q, ev); err != nil {
			return "", err
		}
	}
	return ev.ID, nil
}

// MaxIDBytes bounds the actor, subject and target identifiers an audit record
// stores (AUD-001; the finding httpapi-surface/unauth-audit-amplification).
const MaxIDBytes = 128

// BoundID is the form in which an audit record stores an actor, subject or
// target identifier. An identifier of at most MaxIDBytes bytes, all of them
// printable UTF-8, is stored as it is (every identifier ProudAuth issues is).
// Any other value, which only a request can supply (an unknown client_id, a
// Basic user name), keeps its printable characters up to MaxIDBytes bytes,
// cut at a character boundary, followed by "~" and the first 16 hexadecimal
// digits of the SHA-256 of the whole value: control characters and invalid
// UTF-8 are never stored, the stored value stays far below the size of an
// index row however large the request, and the same value always gives the
// same identifier, so repeated junk still correlates. Audit queries bound
// their identifier filters the same way, so the original value finds its
// records.
func BoundID(id string) string {
	if len(id) <= MaxIDBytes && printable(id) {
		return id
	}
	var b strings.Builder
	for i := 0; i < len(id); {
		r, size := utf8.DecodeRuneInString(id[i:])
		i += size
		if (r == utf8.RuneError && size == 1) || !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+size > MaxIDBytes {
			break
		}
		b.WriteRune(r)
	}
	sum := sha256.Sum256([]byte(id))
	return b.String() + "~" + hex.EncodeToString(sum[:8])
}

// printable reports whether s is valid UTF-8 made only of printable
// characters (unicode.IsPrint: no control or format characters, no space
// but U+0020).
func printable(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || !unicode.IsPrint(r) {
			return false
		}
		i += size
	}
	return true
}

// ContentHash is the integrity digest of an event's security-relevant content.
func ContentHash(ev Event) string {
	c := ev
	c.ContentHash = ""
	c.BatchID = ""
	c.OccurredAt = c.OccurredAt.UTC().Truncate(time.Microsecond)
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Override marks every event recorded with the context as part of one
// operator action, such as an emergency control (SEC-020): the events are
// filed in its category and carry its reason when they have none.
type Override struct {
	Category string
	Reason   string
}

type overrideKey struct{}

// WithOverride returns a context whose audit events use the override.
func WithOverride(ctx context.Context, o Override) context.Context {
	return context.WithValue(ctx, overrideKey{}, o)
}
