// Package ssf is the Shared Signals Framework transmitter (AUD-016): a
// declared profile of OpenID Shared Signals Framework 1.0 with CAEP and RISC
// event types. Receivers are machine clients; each stream carries Security
// Event Tokens about the receiver's own users, delivered by push (RFC 8935)
// or poll (RFC 8936). It is an adapter over the audit log: events are queued
// in the transaction that records their evidence.
package ssf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/token"
)

// Delivery methods.
const (
	MethodPush = "urn:ietf:rfc:8935"
	MethodPoll = "urn:ietf:rfc:8936"
)

const (
	caep = "https://schemas.openid.net/secevent/caep/event-type/"
	risc = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfE = "https://schemas.openid.net/secevent/ssf/event-type/"

	EventSessionRevoked       = caep + "session-revoked"
	EventCredentialChange     = caep + "credential-change"
	EventAccountDisabled      = risc + "account-disabled"
	EventAccountEnabled       = risc + "account-enabled"
	EventAccountPurged        = risc + "account-purged"
	EventCredentialCompromise = risc + "credential-compromise"
	EventIdentifierChanged    = risc + "identifier-changed"
	EventVerification         = ssfE + "verification"
	EventStreamUpdated        = ssfE + "stream-updated"
)

// EventsSupported are the event types a receiver can request. Verification
// and stream-updated events are always delivered.
var EventsSupported = []string{EventSessionRevoked, EventCredentialChange, EventAccountDisabled, EventAccountEnabled, EventAccountPurged,
	EventCredentialCompromise, EventIdentifierChanged}

// TypeSET is the JOSE typ of a Security Event Token (RFC 8417).
const TypeSET = "secevent+jwt"

const (
	maxStreamsPerClient     = 5
	minVerificationInterval = 60 * time.Second
	maxAttempts             = 8
	retention               = 7 * 24 * time.Hour
)

// Delivery is a stream's delivery configuration. For poll the transmitter
// assigns endpoint_url; for push the receiver supplies it, and may supply an
// Authorization header value the transmitter sends with each push
// (write-only, stored encrypted).
type Delivery struct {
	Method              string `json:"method"`
	EndpointURL         string `json:"endpoint_url,omitempty"`
	AuthorizationHeader string `json:"authorization_header,omitempty"`
}

// Stream is a stream configuration (SSF 1.0 §8.1.1).
type Stream struct {
	ID                      string     `json:"stream_id"`
	Issuer                  string     `json:"iss"`
	Audience                string     `json:"aud"`
	Delivery                Delivery   `json:"delivery"`
	EventsSupported         []string   `json:"events_supported"`
	EventsRequested         []string   `json:"events_requested"`
	EventsDelivered         []string   `json:"events_delivered"`
	Description             string     `json:"description,omitempty"`
	MinVerificationInterval int        `json:"min_verification_interval"`
	SubjectScope            string     `json:"subject_scope"`
	Status                  string     `json:"status"`
	StatusReason            string     `json:"reason,omitempty"`
	ClientRef               string     `json:"-"`
	ClientID                string     `json:"client_id,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	LastVerificationAt      *time.Time `json:"-"`
	hasAuthorization        bool
}

// StreamInput creates or updates a stream. Nil members are left unchanged
// by an update.
type StreamInput struct {
	StreamID        string    `json:"stream_id,omitempty"`
	Delivery        *Delivery `json:"delivery,omitempty"`
	EventsRequested *[]string `json:"events_requested,omitempty"`
	Description     *string   `json:"description,omitempty"`
	// SubjectScope: client_users (default) sends events about users who
	// authorized the receiver; listed narrows that to subjects the receiver
	// added. all (every user of the realm) is for administrators to set.
	SubjectScope *string `json:"subject_scope,omitempty"`
	// Read-only members a receiver may echo back on PUT.
	Issuer                  any `json:"iss,omitempty"`
	Audience                any `json:"aud,omitempty"`
	EventsSupported         any `json:"events_supported,omitempty"`
	EventsDelivered         any `json:"events_delivered,omitempty"`
	MinVerificationInterval any `json:"min_verification_interval,omitempty"`
	Status                  any `json:"status,omitempty"`
	Reason                  any `json:"reason,omitempty"`
	ClientID                any `json:"client_id,omitempty"`
	CreatedAt               any `json:"created_at,omitempty"`
	UpdatedAt               any `json:"updated_at,omitempty"`
}

// Service manages streams and delivers events.
type Service struct {
	d      *runtime.Deps
	Apps   *application.Service
	Signer *token.Signer
	// Egress applies to push endpoints and transmitter key sets (the
	// webhook delivery rules).
	Egress egress.Policy
	// jwks caches transmitters' fetched key sets (ADV-007).
	jwks jwksCache
}

// New returns the transmitter.
func New(d *runtime.Deps) *Service {
	return &Service{d: d, Egress: egress.Policy{AllowPrivate: d.Cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: d.Cfg.Delivery.EgressAllowlist,
		RequireHTTPS: d.Cfg.Mode == "production", Timeout: d.Cfg.Delivery.WebhookTimeout, MaxBytes: 64 << 10}}
}

// Enabled reports whether the realm declared the transmitter.
func Enabled(rlm *realm.Realm) bool { return rlm.Policy.SharedSignals.Enabled }

// PollURL is the poll endpoint the transmitter assigns a poll stream.
func PollURL(rlm *realm.Realm, id string) string { return rlm.Issuer + "/ssf/streams/" + id + "/poll" }

// Configuration is the transmitter metadata (SSF 1.0 §7.1).
func Configuration(rlm *realm.Realm) map[string]any {
	iss := rlm.Issuer
	return map[string]any{
		"spec_version":               "1_0",
		"issuer":                     iss,
		"jwks_uri":                   iss + "/jwks",
		"delivery_methods_supported": []string{MethodPush, MethodPoll},
		"configuration_endpoint":     iss + "/ssf/streams",
		"status_endpoint":            iss + "/ssf/streams/status",
		"add_subject_endpoint":       iss + "/ssf/streams/subjects/add",
		"remove_subject_endpoint":    iss + "/ssf/streams/subjects/remove",
		"verification_endpoint":      iss + "/ssf/streams/verify",
		"authorization_schemes":      []map[string]string{{"spec_urn": "urn:ietf:rfc:6749"}},
		"default_subjects":           "NONE",
		"events_supported":           EventsSupported,
	}
}

const streamCols = `s.id, s.client_ref, c.client_id, s.audience, s.delivery_method, coalesce(s.endpoint_url,''), s.authorization_ciphertext IS NOT NULL,
	s.events_requested, s.events_delivered, s.description, s.subject_scope, s.status, coalesce(s.status_reason,''), s.last_verification_at, s.created_at, s.updated_at`

func scanStream(rlm *realm.Realm, row pgx.Row) (*Stream, error) {
	var st Stream
	if err := row.Scan(&st.ID, &st.ClientRef, &st.ClientID, &st.Audience, &st.Delivery.Method, &st.Delivery.EndpointURL, &st.hasAuthorization,
		&st.EventsRequested, &st.EventsDelivered, &st.Description, &st.SubjectScope, &st.Status, &st.StatusReason, &st.LastVerificationAt,
		&st.CreatedAt, &st.UpdatedAt); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	st.Issuer, st.EventsSupported, st.MinVerificationInterval = rlm.Issuer, EventsSupported, int(minVerificationInterval.Seconds())
	if st.Delivery.Method == MethodPoll {
		st.Delivery.EndpointURL = PollURL(rlm, st.ID)
	}
	return &st, nil
}

// streamQuery selects a stream; clientRef "" is an administrator's view.
func (s *Service) stream(ctx context.Context, q storage.Querier, rlm *realm.Realm, clientRef, id string, lock bool) (*Stream, error) {
	sql := `SELECT ` + streamCols + ` FROM ssf_streams s JOIN clients c ON c.id=s.client_ref WHERE s.realm_id=$1 AND s.id=$2 AND ($3='' OR s.client_ref=$3)`
	if lock {
		sql += ` FOR UPDATE OF s`
	}
	return scanStream(rlm, q.QueryRow(ctx, sql, rlm.ID, id, clientRef))
}

// Stream returns one stream.
func (s *Service) Stream(ctx context.Context, rlm *realm.Realm, clientRef, id string) (*Stream, error) {
	return s.stream(ctx, s.d.DB.Pool, rlm, clientRef, id, false)
}

// Streams lists streams; clientRef "" lists every stream of the realm.
func (s *Service) Streams(ctx context.Context, rlm *realm.Realm, clientRef string) ([]*Stream, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+streamCols+` FROM ssf_streams s JOIN clients c ON c.id=s.client_ref
		WHERE s.realm_id=$1 AND ($2='' OR s.client_ref=$2) ORDER BY s.created_at LIMIT 500`, rlm.ID, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Stream{}
	for rows.Next() {
		st, err := scanStream(rlm, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func delivered(requested []string) []string {
	out := []string{}
	for _, e := range requested {
		if slices.Contains(EventsSupported, e) && !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func (s *Service) validateDelivery(d *Delivery) error {
	switch d.Method {
	case MethodPush:
		if err := s.Egress.ValidateURL(d.EndpointURL); err != nil {
			return problem.ErrValidation.WithField("delivery.endpoint_url", "an https URL the delivery egress policy allows")
		}
		if len(d.AuthorizationHeader) > 2048 || strings.ContainsAny(d.AuthorizationHeader, "\r\n") {
			return problem.ErrValidation.WithField("delivery.authorization_header", "a single header value of at most 2048 characters")
		}
	case MethodPoll:
		d.EndpointURL, d.AuthorizationHeader = "", ""
	default:
		return problem.ErrValidation.WithField("delivery.method", MethodPush+" or "+MethodPoll)
	}
	return nil
}

func validateScope(scope string, admin bool) error {
	switch scope {
	case "client_users", "listed":
		return nil
	case "all":
		if admin {
			return nil
		}
		return problem.ErrForbidden.WithDetail("only an administrator can send events about every user")
	}
	return problem.ErrValidation.WithField("subject_scope", "client_users, listed or all")
}

func (s *Service) sealAuthorization(id, header string) ([]byte, error) {
	if header == "" {
		return nil, nil
	}
	ct, _, err := s.d.Keys.Encrypt(keys.PurposeWebhook, []byte(header), []byte("ssf:"+id))
	return ct, err
}

// Create registers a stream for the receiver client.
func (s *Service) Create(ctx context.Context, rlm *realm.Realm, c *application.Client, in StreamInput, actor audit.Ref) (*Stream, error) {
	if in.Delivery == nil {
		in.Delivery = &Delivery{Method: MethodPoll}
	}
	if err := s.validateDelivery(in.Delivery); err != nil {
		return nil, err
	}
	scope := "client_users"
	if in.SubjectScope != nil {
		scope = *in.SubjectScope
	}
	if err := validateScope(scope, false); err != nil {
		return nil, err
	}
	requested := []string{}
	if in.EventsRequested != nil {
		requested = *in.EventsRequested
	}
	if len(requested) > 50 {
		return nil, problem.ErrValidation.WithField("events_requested", "at most 50 event types")
	}
	desc := ""
	if in.Description != nil {
		desc = *in.Description
	}
	if len(desc) > 500 {
		return nil, problem.ErrValidation.WithField("description", "at most 500 characters")
	}
	id := ids.New("sfs")
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssf_streams WHERE client_ref=$1`, c.Ref).Scan(&n); err != nil {
			return err
		}
		if n >= maxStreamsPerClient {
			return problem.ErrConflict.WithDetail(fmt.Sprintf("a receiver can have at most %d streams", maxStreamsPerClient))
		}
		auth, err := s.sealAuthorization(id, in.Delivery.AuthorizationHeader)
		if err != nil {
			return err
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO ssf_streams (id, realm_id, client_ref, audience, delivery_method, endpoint_url, authorization_ciphertext,
			events_requested, events_delivered, description, subject_scope, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
			id, rlm.ID, c.Ref, c.ClientID, in.Delivery.Method, nilIfEmpty(in.Delivery.EndpointURL), auth, requested, delivered(requested), desc, scope, now); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.stream.created", RealmID: rlm.ID, Actor: actor, ClientID: c.ClientID,
			Target: &audit.Ref{Type: "ssf_stream", ID: id}, Category: "security",
			Metadata: map[string]any{"delivery_method": in.Delivery.Method, "events_delivered": delivered(requested), "subject_scope": scope}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Stream(ctx, rlm, c.Ref, id)
}

// Update changes a stream: replace (PUT) sets every member, otherwise
// (PATCH) only the members given. admin allows subject_scope all.
func (s *Service) Update(ctx context.Context, rlm *realm.Realm, clientRef string, in StreamInput, replace, admin bool, actor audit.Ref) (*Stream, error) {
	if in.StreamID == "" {
		return nil, problem.ErrValidation.WithField("stream_id", "required")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		st, err := s.stream(ctx, tx, rlm, clientRef, in.StreamID, true)
		if err != nil {
			return err
		}
		if replace {
			if in.Delivery == nil || in.EventsRequested == nil {
				return problem.ErrValidation.WithField("delivery", "PUT replaces the whole configuration: delivery and events_requested are required")
			}
			if in.Description == nil {
				empty := ""
				in.Description = &empty
			}
		}
		set := []string{"updated_at=$3"}
		args := []any{rlm.ID, st.ID, s.d.Now()}
		add := func(col string, v any) {
			args = append(args, v)
			set = append(set, fmt.Sprintf("%s=$%d", col, len(args)))
		}
		if in.Delivery != nil {
			// A poll endpoint the transmitter assigned may be echoed back.
			if in.Delivery.Method == MethodPoll && in.Delivery.EndpointURL == PollURL(rlm, st.ID) {
				in.Delivery.EndpointURL = ""
			}
			if err := s.validateDelivery(in.Delivery); err != nil {
				return err
			}
			add("delivery_method", in.Delivery.Method)
			add("endpoint_url", nilIfEmpty(in.Delivery.EndpointURL))
			keep := in.Delivery.Method == MethodPush && in.Delivery.AuthorizationHeader == "" && st.Delivery.Method == MethodPush &&
				in.Delivery.EndpointURL == st.Delivery.EndpointURL
			if !keep {
				auth, err := s.sealAuthorization(st.ID, in.Delivery.AuthorizationHeader)
				if err != nil {
					return err
				}
				add("authorization_ciphertext", auth)
			}
		}
		if in.EventsRequested != nil {
			if len(*in.EventsRequested) > 50 {
				return problem.ErrValidation.WithField("events_requested", "at most 50 event types")
			}
			add("events_requested", *in.EventsRequested)
			add("events_delivered", delivered(*in.EventsRequested))
		}
		if in.Description != nil {
			if len(*in.Description) > 500 {
				return problem.ErrValidation.WithField("description", "at most 500 characters")
			}
			add("description", *in.Description)
		}
		// Echoing the current scope back is no change (SSF receivers PUT
		// the configuration they read), even when an administrator set it.
		if in.SubjectScope != nil && *in.SubjectScope != st.SubjectScope {
			if err := validateScope(*in.SubjectScope, admin); err != nil {
				return err
			}
			if st.SubjectScope == "all" && !admin && *in.SubjectScope != "all" {
				return problem.ErrForbidden.WithDetail("an administrator set this stream's subject scope")
			}
			add("subject_scope", *in.SubjectScope)
		}
		if _, err := tx.Exec(ctx, `UPDATE ssf_streams SET `+strings.Join(set, ", ")+` WHERE realm_id=$1 AND id=$2`, args...); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.stream.updated", RealmID: rlm.ID, Actor: actor, ClientID: st.ClientID,
			Target: &audit.Ref{Type: "ssf_stream", ID: st.ID}, Category: "security"})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Stream(ctx, rlm, clientRef, in.StreamID)
}

// Delete removes a stream and its queued events.
func (s *Service) Delete(ctx context.Context, rlm *realm.Realm, clientRef, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		st, err := s.stream(ctx, tx, rlm, clientRef, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ssf_streams WHERE id=$1`, st.ID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.stream.deleted", RealmID: rlm.ID, Actor: actor, ClientID: st.ClientID,
			Target: &audit.Ref{Type: "ssf_stream", ID: st.ID}, Category: "security"})
		return err
	})
}

// SetStatus enables, pauses or disables a stream. A paused stream keeps
// queueing events and delivers them when enabled again; a disabled stream
// queues nothing. notify sends the receiver a stream-updated event (for a
// change the receiver did not make).
func (s *Service) SetStatus(ctx context.Context, rlm *realm.Realm, clientRef, id, status, reason string, notify bool, actor audit.Ref) (*Stream, error) {
	if !slices.Contains([]string{"enabled", "paused", "disabled"}, status) {
		return nil, problem.ErrValidation.WithField("status", "enabled, paused or disabled")
	}
	if len(reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "at most 500 characters")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		st, err := s.stream(ctx, tx, rlm, clientRef, id, true)
		if err != nil {
			return err
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE ssf_streams SET status=$2, status_reason=$3, updated_at=$4 WHERE id=$1`, st.ID, status, nilIfEmpty(reason), now); err != nil {
			return err
		}
		if status == "disabled" {
			if _, err := tx.Exec(ctx, `UPDATE ssf_events SET state='expired' WHERE stream_id=$1 AND state IN ('pending','delivered')`, st.ID); err != nil {
				return err
			}
		}
		if notify {
			payload := map[string]any{"status": status}
			if reason != "" {
				payload["reason"] = reason
			}
			if err := s.queueStreamEvent(ctx, tx, rlm.ID, st.ID, EventStreamUpdated, payload, now); err != nil {
				return err
			}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.stream.status_changed", RealmID: rlm.ID, Actor: actor, ClientID: st.ClientID,
			Target: &audit.Ref{Type: "ssf_stream", ID: st.ID}, ReasonCode: reason, Category: "security",
			Metadata: map[string]any{"status": status, "previous_status": st.Status}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Stream(ctx, rlm, clientRef, id)
}

// Verify queues a verification event (SSF 1.0 §8.1.4), at most once per
// minimum verification interval.
func (s *Service) Verify(ctx context.Context, rlm *realm.Realm, clientRef, id, state string) error {
	if len(state) > 256 {
		return problem.ErrValidation.WithField("state", "at most 256 characters")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		st, err := s.stream(ctx, tx, rlm, clientRef, id, true)
		if err != nil {
			return err
		}
		if st.Status != "enabled" {
			return problem.ErrConflict.WithDetail("the stream is not enabled")
		}
		now := s.d.Now()
		if st.LastVerificationAt != nil && now.Sub(*st.LastVerificationAt) < minVerificationInterval {
			return problem.ErrRateLimited.WithDetail("verification was requested too recently")
		}
		if _, err := tx.Exec(ctx, `UPDATE ssf_streams SET last_verification_at=$2 WHERE id=$1`, st.ID, now); err != nil {
			return err
		}
		payload := map[string]any{}
		if state != "" {
			payload["state"] = state
		}
		return s.queueStreamEvent(ctx, tx, rlm.ID, st.ID, EventVerification, payload, now)
	})
}

func (s *Service) queueStreamEvent(ctx context.Context, q storage.Querier, realmID, streamID, typ string, payload map[string]any, now time.Time) error {
	body, _ := json.Marshal(payload)
	_, err := q.Exec(ctx, `INSERT INTO ssf_events (id, stream_id, realm_id, event_type, payload, occurred_at, next_attempt_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`,
		ids.New("set"), streamID, realmID, typ, body, now)
	return err
}

// ---------- subjects ----------

// Subject is an SSF subject identifier (RFC 9493): iss_sub (sub as the
// receiver knows it, pairwise included) or email (a verified address).
type Subject map[string]any

func (s *Service) resolve(ctx context.Context, rlm *realm.Realm, c *application.Client, subj Subject) (string, error) {
	str := func(k string) string { v, _ := subj[k].(string); return v }
	var userID string
	var err error
	switch str("format") {
	case "iss_sub":
		if str("iss") != rlm.Issuer || str("sub") == "" {
			return "", nil
		}
		if c.SubjectType == "pairwise" {
			err = s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND subject=$3`,
				rlm.ID, c.SectorIdentifier, str("sub")).Scan(&userID)
		} else {
			err = s.d.DB.Pool.QueryRow(ctx, `SELECT id FROM users WHERE realm_id=$1 AND id=$2`, rlm.ID, str("sub")).Scan(&userID)
		}
	case "email":
		typ, canon, ok := identity.CanonicalizeLogin(str("email"))
		if !ok || typ != "email" {
			return "", problem.ErrValidation.WithField("subject.email", "an email address")
		}
		err = s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2
			AND verified_at IS NOT NULL`, rlm.ID, canon).Scan(&userID)
	default:
		return "", problem.ErrValidation.WithField("subject.format", "iss_sub or email")
	}
	if err != nil && !storage.IsNoRows(err) {
		return "", err
	}
	return userID, nil
}

// AddSubject adds a subject to a stream. An unknown subject, or one that
// never authorized the receiver, is accepted without effect, so the
// endpoint reveals nothing about accounts (SSF 1.0 §8.1.3.1).
func (s *Service) AddSubject(ctx context.Context, rlm *realm.Realm, c *application.Client, id string, subj Subject) error {
	st, err := s.Stream(ctx, rlm, c.Ref, id)
	if err != nil {
		return err
	}
	userID, err := s.resolve(ctx, rlm, c, subj)
	if err != nil || userID == "" {
		return err
	}
	var n int
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM ssf_stream_subjects WHERE stream_id=$1`, st.ID).Scan(&n); err != nil {
		return err
	}
	if n >= 100000 {
		return problem.ErrConflict.WithDetail("the stream has the maximum number of subjects")
	}
	_, err = s.d.DB.Pool.Exec(ctx, `INSERT INTO ssf_stream_subjects (stream_id, user_id, created_at) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		st.ID, userID, s.d.Now())
	return err
}

// RemoveSubject removes a subject.
func (s *Service) RemoveSubject(ctx context.Context, rlm *realm.Realm, c *application.Client, id string, subj Subject) error {
	st, err := s.Stream(ctx, rlm, c.Ref, id)
	if err != nil {
		return err
	}
	userID, err := s.resolve(ctx, rlm, c, subj)
	if err != nil || userID == "" {
		return err
	}
	_, err = s.d.DB.Pool.Exec(ctx, `DELETE FROM ssf_stream_subjects WHERE stream_id=$1 AND user_id=$2`, st.ID, userID)
	return err
}

// ---------- events from the audit log ----------

// mapAudit translates a recorded audit event into a CAEP or RISC event.
func mapAudit(ev audit.Event) (string, map[string]any, bool) {
	if ev.Subject == nil || ev.Subject.Type != "user" || ev.Outcome != audit.Success || ev.RealmID == "" {
		return "", nil, false
	}
	cred := func(typ, change string) (string, map[string]any, bool) {
		return EventCredentialChange, map[string]any{"credential_type": typ, "change_type": change}, true
	}
	switch ev.Type {
	case "session.revoked":
		initiator := "system"
		switch r := ev.ReasonCode; {
		case strings.Contains(r, "admin"):
			initiator = "admin"
		case strings.Contains(r, "logout") || strings.Contains(r, "user"):
			initiator = "user"
		case strings.HasPrefix(r, "account_") || strings.Contains(r, "risk") || strings.Contains(r, "policy") || strings.Contains(r, "compromise"):
			initiator = "policy"
		}
		return EventSessionRevoked, map[string]any{"initiating_entity": initiator}, true
	case "credential.password.changed", "recovery.password_reset.completed":
		return cred("password", "update")
	case "mfa.totp.enrolled", "mfa.hotp.enrolled":
		return cred("app", "create")
	case "mfa.totp.removed", "mfa.hotp.removed":
		return cred("app", "delete")
	case "mfa.webauthn.enrolled", "mfa.webauthn.removed":
		typ := "fido2-roaming"
		if a, _ := ev.Metadata["attachment"].(string); a == "platform" {
			typ = "fido2-platform"
		}
		if ev.Type == "mfa.webauthn.enrolled" {
			return cred(typ, "create")
		}
		return cred(typ, "delete")
	case "credential.certificate.bound":
		return cred("x509", "create")
	case "credential.certificate.unbound":
		return cred("x509", "delete")
	case "user.suspended", "user.locked":
		return EventAccountDisabled, map[string]any{}, true
	case "user.reactivated":
		return EventAccountEnabled, map[string]any{}, true
	case "user.deleted":
		return EventAccountPurged, map[string]any{}, true
	case "credential.password.compromised":
		return EventCredentialCompromise, map[string]any{"credential_type": "password"}, true
	case "user.identifier.primary_changed":
		return EventIdentifierChanged, map[string]any{}, true
	}
	return "", nil, false
}

// OnAudit queues events for the streams that should receive them, in the
// transaction recording the audit event. A stream receives events about a
// user who authorized its receiver (narrowed to added subjects for listed
// scope), or about every user when an administrator set scope all.
func (s *Service) OnAudit(ctx context.Context, q storage.Querier, ev audit.Event) error {
	typ, payload, ok := mapAudit(ev)
	if !ok {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT st.id, st.client_ref FROM ssf_streams st WHERE st.realm_id=$1 AND st.status IN ('enabled','paused')
		AND $2 = ANY(st.events_delivered)
		AND (st.subject_scope = 'all' OR (EXISTS (SELECT 1 FROM authorization_grants g WHERE g.realm_id=st.realm_id AND g.subject_type='user'
			AND g.subject_id=$3 AND g.client_ref=st.client_ref)
			AND (st.subject_scope = 'client_users' OR EXISTS (SELECT 1 FROM ssf_stream_subjects ss WHERE ss.stream_id=st.id AND ss.user_id=$3))))`,
		ev.RealmID, typ, ev.Subject.ID)
	if err != nil {
		return err
	}
	type target struct{ stream, client string }
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.stream, &t.client); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if len(targets) == 0 {
		return nil
	}
	payload["event_timestamp"] = ev.OccurredAt.Unix()
	body, _ := json.Marshal(payload)
	for _, t := range targets {
		c, err := s.Apps.ClientByRef(ctx, q, ev.RealmID, t.client)
		if err != nil {
			return err
		}
		sub, err := s.subjectTx(ctx, q, c, ev.Subject.ID)
		if err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO ssf_events (id, stream_id, realm_id, event_type, user_id, subject, session_id, payload, occurred_at, next_attempt_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, ids.New("set"), t.stream, ev.RealmID, typ, ev.Subject.ID, sub, nilIfEmpty(ev.SessionID), body,
			ev.OccurredAt); err != nil {
			return err
		}
	}
	return nil
}

// subjectTx is the subject the receiver knows, fixed when the event is
// queued so it survives the account's erasure: the stored pairwise value
// when there is one, or the derivation that produced it.
func (s *Service) subjectTx(ctx context.Context, q storage.Querier, c *application.Client, userID string) (string, error) {
	if c.SubjectType != "pairwise" {
		return userID, nil
	}
	var sub string
	err := q.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3`, c.RealmID, c.SectorIdentifier, userID).Scan(&sub)
	if err == nil {
		return sub, nil
	}
	if !storage.IsNoRows(err) {
		return "", err
	}
	b := s.d.Keys.DeriveBytes(keys.PurposePairwise, c.SectorIdentifier, userID)
	return "pws_" + base64.RawURLEncoding.EncodeToString(b[:20]), nil
}

// ---------- tokens ----------

type queued struct {
	id, stream, realm, typ, subject, session, setJWT string
	payload                                          []byte
	occurred                                         time.Time
	attempts                                         int
}

// set returns the event's Security Event Token, signing it once: a
// re-delivery or re-poll returns the same token.
func (s *Service) set(ctx context.Context, rlm *realm.Realm, audience string, e queued) (string, error) {
	if e.setJWT != "" {
		return e.setJWT, nil
	}
	var body map[string]any
	_ = json.Unmarshal(e.payload, &body)
	claims := map[string]any{"iss": rlm.Issuer, "jti": e.id, "iat": e.occurred.Unix(), "aud": audience, "events": map[string]any{e.typ: body}}
	switch {
	case e.subject == "":
		claims["sub_id"] = map[string]any{"format": "opaque", "id": e.stream}
	case e.typ == EventSessionRevoked && e.session != "":
		claims["sub_id"] = map[string]any{"format": "complex", "user": map[string]any{"format": "iss_sub", "iss": rlm.Issuer, "sub": e.subject},
			"session": map[string]any{"format": "opaque", "id": e.session}}
	default:
		claims["sub_id"] = map[string]any{"format": "iss_sub", "iss": rlm.Issuer, "sub": e.subject}
	}
	tok, err := s.Signer.Sign(ctx, e.realm, TypeSET, claims)
	if err != nil {
		return "", err
	}
	if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET set_jwt=$2 WHERE id=$1 AND set_jwt IS NULL`, e.id, tok); err != nil {
		return "", err
	}
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT set_jwt FROM ssf_events WHERE id=$1`, e.id).Scan(&tok); err != nil {
		return "", err
	}
	return tok, nil
}

const queuedCols = `e.id, e.stream_id, e.realm_id, e.event_type, coalesce(e.subject,''), coalesce(e.session_id,''), coalesce(e.set_jwt,''), e.payload, e.occurred_at, e.attempts`

func scanQueued(rows pgx.Rows) ([]queued, error) {
	defer rows.Close()
	var out []queued
	for rows.Next() {
		var e queued
		if err := rows.Scan(&e.id, &e.stream, &e.realm, &e.typ, &e.subject, &e.session, &e.setJWT, &e.payload, &e.occurred, &e.attempts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

var errPermanent = errors.New("permanent")
