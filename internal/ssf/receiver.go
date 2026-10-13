package ssf

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/storage"
)

// Receiver side (ADV-007): Security Event Tokens pushed to the realm by
// transmitters an administrator registered. Every event maps to an explicit
// local action; nothing happens that the policy does not name.

// Local actions an event can be mapped to.
const (
	ActionRecord            = "record_only"
	ActionRevokeSessions    = "revoke_sessions"
	ActionRevokeAll         = "revoke_all"
	ActionMarkCompromised   = "mark_password_compromised"
	ActionSuspend           = "suspend_user"
	EventAssuranceChange    = caep + "assurance-level-change"
	receivedRetention       = 30 * 24 * time.Hour
	maxSETBytes             = 64 << 10
	jwksCacheTTL            = 10 * time.Minute
	pushSecretPrefix        = "pa_ssfp_"
	defaultMaxEventAge      = 24 * time.Hour
	maxFutureSkew           = 5 * time.Minute
	transmitterIDPrefix     = "sft"
	maxTransmittersPerRealm = 50
)

// AllowedActions bounds what each event type can trigger: an account is
// never re-enabled from outside, and identifier changes are only recorded.
var AllowedActions = map[string][]string{
	EventSessionRevoked:       {ActionRecord, ActionRevokeSessions, ActionRevokeAll},
	EventCredentialChange:     {ActionRecord, ActionRevokeSessions},
	EventAssuranceChange:      {ActionRecord, ActionRevokeSessions},
	EventCredentialCompromise: {ActionRecord, ActionRevokeAll, ActionMarkCompromised},
	EventAccountDisabled:      {ActionRecord, ActionRevokeAll, ActionSuspend},
	EventAccountPurged:        {ActionRecord, ActionRevokeAll, ActionSuspend},
	EventAccountEnabled:       {ActionRecord},
	EventIdentifierChanged:    {ActionRecord},
}

// Transmitter is a trusted source of security events.
type Transmitter struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	Issuer             string            `json:"issuer"`
	JWKSURI            string            `json:"jwks_uri,omitempty"`
	JWKS               json.RawMessage   `json:"jwks,omitempty"`
	ProviderID         string            `json:"provider_id,omitempty"`
	AllowEmailSubjects bool              `json:"allow_email_subjects"`
	Actions            map[string]string `json:"actions"`
	MaxEventAgeSeconds int               `json:"max_event_age_seconds"`
	State              string            `json:"state"`
	PushEndpoint       string            `json:"push_endpoint"`
	Audience           string            `json:"audience"`
	Version            int64             `json:"version"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
	secretDigest       string
}

// TransmitterInput registers or updates a transmitter.
type TransmitterInput struct {
	Name               string            `json:"name"`
	Issuer             string            `json:"issuer"`
	JWKSURI            string            `json:"jwks_uri"`
	JWKS               json.RawMessage   `json:"jwks"`
	ProviderID         string            `json:"provider_id"`
	AllowEmailSubjects bool              `json:"allow_email_subjects"`
	Actions            map[string]string `json:"actions"`
	MaxEventAgeSeconds int               `json:"max_event_age_seconds"`
	State              string            `json:"state"`
}

// LocalActions perform mapped actions inside the receiving transaction.
type LocalActions struct {
	RevokeUserTx    func(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, includeOffline bool) error
	SuspendUserTx   func(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref, reason string) error
	MarkCompromised func(ctx context.Context, realmID, userID string, actor audit.Ref, reason string) error
}

const transmitterCols = `id, name, issuer, coalesce(jwks_uri,''), jwks, push_secret_digest, coalesce(provider_id,''), allow_email_subjects, actions,
	max_event_age_seconds, state, version, created_at, updated_at`

func (s *Service) scanTransmitter(issuer string, row pgx.Row) (*Transmitter, error) {
	var t Transmitter
	var jwks, actions []byte
	if err := row.Scan(&t.ID, &t.Name, &t.Issuer, &t.JWKSURI, &jwks, &t.secretDigest, &t.ProviderID, &t.AllowEmailSubjects, &actions,
		&t.MaxEventAgeSeconds, &t.State, &t.Version, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if len(jwks) > 0 && string(jwks) != "null" {
		t.JWKS = jwks
	}
	_ = json.Unmarshal(actions, &t.Actions)
	if t.Actions == nil {
		t.Actions = map[string]string{}
	}
	t.PushEndpoint = issuer + "/ssf/receivers/" + t.ID + "/events"
	t.Audience = t.PushEndpoint
	return &t, nil
}

func (s *Service) validateTransmitter(ctx context.Context, q storage.Querier, realmID string, in *TransmitterInput) error {
	if in.Name == "" || len(in.Name) > 100 {
		return problem.ErrValidation.WithField("name", "1 to 100 characters")
	}
	if !strings.HasPrefix(in.Issuer, "https://") && !strings.HasPrefix(in.Issuer, "urn:") || len(in.Issuer) > 512 {
		return problem.ErrValidation.WithField("issuer", "the transmitter's issuer (https URL or URN)")
	}
	switch {
	case in.JWKSURI == "" && len(in.JWKS) == 0:
		return problem.ErrValidation.WithField("jwks_uri", "jwks_uri or jwks is required")
	case in.JWKSURI != "" && len(in.JWKS) > 0:
		return problem.ErrValidation.WithField("jwks", "give jwks_uri or jwks, not both")
	case in.JWKSURI != "":
		if err := s.Egress.ValidateURL(in.JWKSURI); err != nil {
			return problem.ErrValidation.WithField("jwks_uri", "a URL the delivery egress policy allows")
		}
	default:
		var set jose.JSONWebKeySet
		if err := json.Unmarshal(in.JWKS, &set); err != nil || len(set.Keys) == 0 || len(in.JWKS) > 64<<10 {
			return problem.ErrValidation.WithField("jwks", "a JSON Web Key Set with public keys")
		}
		for _, k := range set.Keys {
			if !k.IsPublic() {
				return problem.ErrValidation.WithField("jwks", "public keys only")
			}
		}
	}
	if in.ProviderID != "" {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM identity_providers WHERE realm_id=$1 AND id=$2`, realmID, in.ProviderID).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return problem.ErrValidation.WithField("provider_id", "a federation connection of this realm")
		}
	}
	if in.Actions == nil {
		in.Actions = map[string]string{}
	}
	for typ, action := range in.Actions {
		allowed, known := AllowedActions[typ]
		if !known {
			return problem.ErrValidation.WithField("actions", "unsupported event type "+typ)
		}
		if !slices.Contains(allowed, action) {
			return problem.ErrValidation.WithField("actions", fmt.Sprintf("%s allows %s", typ, strings.Join(allowed, ", ")))
		}
	}
	if in.MaxEventAgeSeconds == 0 {
		in.MaxEventAgeSeconds = int(defaultMaxEventAge.Seconds())
	}
	if in.MaxEventAgeSeconds < 60 || in.MaxEventAgeSeconds > 7*86400 {
		return problem.ErrValidation.WithField("max_event_age_seconds", "60 to 604800")
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	return nil
}

// RegisterTransmitter registers a transmitter and returns its push secret
// once.
func (s *Service) RegisterTransmitter(ctx context.Context, realmID, issuer string, in TransmitterInput, actor audit.Ref) (*Transmitter, string, error) {
	id := ids.New(transmitterIDPrefix)
	plain := secret.Token(pushSecretPrefix)
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.validateTransmitter(ctx, tx, realmID, &in); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM ssf_transmitters WHERE realm_id=$1`, realmID).Scan(&n); err != nil {
			return err
		}
		if n >= maxTransmittersPerRealm {
			return problem.ErrConflict.WithDetail("too many transmitters")
		}
		actions, _ := json.Marshal(in.Actions)
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO ssf_transmitters (id, realm_id, name, issuer, jwks_uri, jwks, push_secret_digest, provider_id,
			allow_email_subjects, actions, max_event_age_seconds, state, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`,
			id, realmID, in.Name, in.Issuer, nilIfEmpty(in.JWKSURI), nilJSON(in.JWKS), secret.Digest(plain), nilIfEmpty(in.ProviderID),
			in.AllowEmailSubjects, actions, in.MaxEventAgeSeconds, in.State, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("a transmitter with this name or issuer is registered")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.transmitter.registered", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "ssf_transmitter", ID: id}, Category: "security",
			Metadata: map[string]any{"issuer": in.Issuer, "actions": in.Actions, "allow_email_subjects": in.AllowEmailSubjects}})
		return err
	})
	if err != nil {
		return nil, "", err
	}
	t, err := s.Transmitter(ctx, realmID, issuer, id)
	return t, plain, err
}

// UpdateTransmitter replaces a transmitter's settings; rotate issues a new
// push secret (returned once).
func (s *Service) UpdateTransmitter(ctx context.Context, realmID, issuer, id string, expectedVersion int64, in TransmitterInput, rotate bool, actor audit.Ref) (*Transmitter, string, error) {
	plain := ""
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := s.scanTransmitter(issuer, tx.QueryRow(ctx, `SELECT `+transmitterCols+` FROM ssf_transmitters WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		digest := cur.secretDigest
		if rotate {
			plain = secret.Token(pushSecretPrefix)
			digest = secret.Digest(plain)
			in = TransmitterInput{Name: cur.Name, Issuer: cur.Issuer, JWKSURI: cur.JWKSURI, JWKS: cur.JWKS, ProviderID: cur.ProviderID,
				AllowEmailSubjects: cur.AllowEmailSubjects, Actions: cur.Actions, MaxEventAgeSeconds: cur.MaxEventAgeSeconds, State: cur.State}
		}
		if err := s.validateTransmitter(ctx, tx, realmID, &in); err != nil {
			return err
		}
		actions, _ := json.Marshal(in.Actions)
		if _, err := tx.Exec(ctx, `UPDATE ssf_transmitters SET name=$2, issuer=$3, jwks_uri=$4, jwks=$5, push_secret_digest=$6, provider_id=$7,
			allow_email_subjects=$8, actions=$9, max_event_age_seconds=$10, state=$11, version=version+1, updated_at=$12 WHERE id=$1`,
			id, in.Name, in.Issuer, nilIfEmpty(in.JWKSURI), nilJSON(in.JWKS), digest, nilIfEmpty(in.ProviderID), in.AllowEmailSubjects, actions,
			in.MaxEventAgeSeconds, in.State, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("a transmitter with this name or issuer is registered")
			}
			return err
		}
		s.jwks.ForgetPrefix(id + "|")
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.transmitter.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "ssf_transmitter", ID: id}, Category: "security",
			Metadata: map[string]any{"actions": in.Actions, "state": in.State, "secret_rotated": rotate}})
		return err
	})
	if err != nil {
		return nil, "", err
	}
	t, err := s.Transmitter(ctx, realmID, issuer, id)
	return t, plain, err
}

// DeleteTransmitter removes a transmitter and its received-event records.
func (s *Service) DeleteTransmitter(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM ssf_transmitters WHERE realm_id=$1 AND id=$2`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		s.jwks.ForgetPrefix(id + "|")
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.transmitter.deleted", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "ssf_transmitter", ID: id}, Category: "security"})
		return err
	})
}

// Transmitter returns one transmitter.
func (s *Service) Transmitter(ctx context.Context, realmID, issuer, id string) (*Transmitter, error) {
	return s.scanTransmitter(issuer, s.d.DB.Pool.QueryRow(ctx, `SELECT `+transmitterCols+` FROM ssf_transmitters WHERE realm_id=$1 AND id=$2`, realmID, id))
}

// Transmitters lists the realm's transmitters.
func (s *Service) Transmitters(ctx context.Context, realmID, issuer string) ([]*Transmitter, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+transmitterCols+` FROM ssf_transmitters WHERE realm_id=$1 ORDER BY name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Transmitter{}
	for rows.Next() {
		t, err := s.scanTransmitter(issuer, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ReceivedEvent is the minimal record kept for a received event.
type ReceivedEvent struct {
	JTI           string    `json:"jti"`
	EventType     string    `json:"event_type"`
	SubjectFormat string    `json:"subject_format,omitempty"`
	UserID        string    `json:"user_id,omitempty"`
	Action        string    `json:"action"`
	Outcome       string    `json:"outcome"`
	ReceivedAt    time.Time `json:"received_at"`
}

// ReceivedEvents lists a transmitter's recent events.
func (s *Service) ReceivedEvents(ctx context.Context, realmID, id string) ([]ReceivedEvent, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT jti, event_type, coalesce(subject_format,''), coalesce(user_id,''), action, outcome, received_at
		FROM ssf_received_events WHERE realm_id=$1 AND transmitter_id=$2 ORDER BY received_at DESC LIMIT 500`, realmID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReceivedEvent{}
	for rows.Next() {
		var e ReceivedEvent
		if err := rows.Scan(&e.JTI, &e.EventType, &e.SubjectFormat, &e.UserID, &e.Action, &e.Outcome, &e.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PushError is an RFC 8935 error answer.
type PushError struct {
	Status      int    `json:"-"`
	Err         string `json:"err"`
	Description string `json:"description"`
}

func (e *PushError) Error() string { return e.Err + ": " + e.Description }

func pushErr(status int, code, desc string) *PushError {
	return &PushError{Status: status, Err: code, Description: desc}
}

type jwksCache = egress.FetchCache[jose.JSONWebKeySet]

func (s *Service) keysFor(ctx context.Context, t *Transmitter, refresh bool) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if len(t.JWKS) > 0 {
		err := json.Unmarshal(t.JWKS, &set)
		return set, err
	}
	return s.jwks.Load(ctx, t.ID+"|"+t.JWKSURI, egress.FetchOptions[jose.JSONWebKeySet]{
		TTL: jwksCacheTTL, RetryAfter: time.Minute, Timeout: s.Egress.Timeout, Now: s.d.Now,
		Usable: func(jose.JSONWebKeySet) bool { return !refresh },
		Fetch:  func(ctx context.Context) (jose.JSONWebKeySet, error) { return s.fetchKeys(ctx, t.JWKSURI) },
	})
}

func (s *Service) fetchKeys(ctx context.Context, uri string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return set, err
	}
	client := s.Egress.Client()
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return set, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return set, fmt.Errorf("jwks: status %d", res.StatusCode)
	}
	body, err := s.Egress.ReadLimited(res.Body)
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return set, err
	}
	return set, nil
}

var setAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA}

// Receive handles one pushed SET (RFC 8935): it authenticates the
// transmitter (push secret and signature), validates issuer, audience and
// age, drops replays, maps the subject, and applies the configured action
// for each event. Unknown subjects are recorded without action and answered
// like any accepted event, so the transmitter learns nothing about
// accounts.
func (s *Service) Receive(ctx context.Context, realmID, issuer, id, bearer string, body []byte, local LocalActions) error {
	t, err := s.Transmitter(ctx, realmID, issuer, id)
	if err != nil || t.State != "active" || bearer == "" || !secret.Equal(secret.Digest(bearer), t.secretDigest) {
		return pushErr(http.StatusUnauthorized, "authentication_failed", "the push credentials are not valid")
	}
	if len(body) == 0 || len(body) > maxSETBytes {
		return pushErr(http.StatusBadRequest, "invalid_request", "the body must be one security event token")
	}
	sig, err := jose.ParseSigned(strings.TrimSpace(string(body)), setAlgorithms)
	if err != nil || len(sig.Signatures) != 1 {
		return pushErr(http.StatusBadRequest, "invalid_request", "the token is not a signed JWT")
	}
	if typ, _ := sig.Signatures[0].Header.ExtraHeaders["typ"].(string); typ != "" && !strings.EqualFold(typ, TypeSET) && !strings.EqualFold(typ, "JWT") {
		return pushErr(http.StatusBadRequest, "invalid_request", "the token type must be secevent+jwt")
	}
	var payload []byte
	for attempt := 0; attempt < 2 && payload == nil; attempt++ {
		set, err := s.keysFor(ctx, t, attempt == 1)
		if err != nil {
			return pushErr(http.StatusBadRequest, "invalid_key", "the transmitter's keys are unavailable")
		}
		keys := set.Key(sig.Signatures[0].Header.KeyID)
		if sig.Signatures[0].Header.KeyID == "" {
			keys = set.Keys
		}
		for _, k := range keys {
			if p, err := sig.Verify(k); err == nil {
				payload = p
				break
			}
		}
	}
	if payload == nil {
		return pushErr(http.StatusBadRequest, "invalid_key", "the signature does not verify with the transmitter's keys")
	}
	var claims struct {
		Iss    string                     `json:"iss"`
		Aud    any                        `json:"aud"`
		Iat    int64                      `json:"iat"`
		JTI    string                     `json:"jti"`
		SubID  map[string]any             `json:"sub_id"`
		Sub    string                     `json:"sub"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return pushErr(http.StatusBadRequest, "invalid_request", "the token claims are malformed")
	}
	if claims.Iss != t.Issuer {
		return pushErr(http.StatusBadRequest, "invalid_issuer", "unexpected issuer")
	}
	if !audienceHas(claims.Aud, t.Audience) {
		return pushErr(http.StatusBadRequest, "invalid_audience", "the token is not addressed to this receiver")
	}
	now := s.d.Now()
	iat := time.Unix(claims.Iat, 0)
	if claims.JTI == "" || len(claims.JTI) > 256 || claims.Iat == 0 || iat.After(now.Add(maxFutureSkew)) ||
		now.Sub(iat) > time.Duration(t.MaxEventAgeSeconds)*time.Second {
		return pushErr(http.StatusBadRequest, "invalid_request", "jti and a recent iat are required")
	}
	if len(claims.Events) == 0 || len(claims.Events) > 10 {
		return pushErr(http.StatusBadRequest, "invalid_request", "the token must carry events")
	}
	format, userID := "", ""
	subject := claims.SubID
	if subject == nil && claims.Sub != "" {
		subject = map[string]any{"format": "iss_sub", "iss": claims.Iss, "sub": claims.Sub}
	}
	if subject != nil {
		format, _ = subject["format"].(string)
		if userID, err = s.mapSubject(ctx, realmID, t, subject); err != nil {
			return err
		}
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// Replay defence: one record per (transmitter, jti); a replay is
		// accepted without effect.
		var types []string
		for typ := range claims.Events {
			types = append(types, typ)
		}
		slices.Sort(types)
		primary := types[0]
		tag, err := tx.Exec(ctx, `INSERT INTO ssf_received_events (transmitter_id, jti, realm_id, event_type, subject_format, user_id, action, outcome, received_at)
			VALUES ($1,$2,$3,$4,$5,$6,'pending','pending',$7) ON CONFLICT DO NOTHING`, t.ID, claims.JTI, realmID, primary, nilIfEmpty(format), nilIfEmpty(userID), now)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "ssf.event.replayed", RealmID: realmID, Outcome: audit.Denied,
				Actor: audit.Ref{Type: "ssf_transmitter", ID: t.ID}, Category: "security", Metadata: map[string]any{"jti": claims.JTI}})
			return err
		}
		actionTaken, outcome := ActionRecord, "recorded"
		for _, typ := range types {
			action := t.Actions[typ]
			if action == "" {
				action = ActionRecord
			}
			if _, known := AllowedActions[typ]; !known && typ != EventVerification {
				outcome = "unsupported_event"
				continue
			}
			if typ == EventVerification {
				outcome = "verified"
				continue
			}
			if userID == "" {
				if subject != nil {
					outcome = "subject_unknown"
				} else {
					outcome = "no_subject"
				}
				continue
			}
			if action == ActionRecord {
				continue
			}
			res, err := s.applyAction(ctx, tx, realmID, t, userID, typ, action, local)
			if err != nil {
				return err
			}
			actionTaken, outcome = action, res
		}
		if _, err := tx.Exec(ctx, `UPDATE ssf_received_events SET action=$3, outcome=$4 WHERE transmitter_id=$1 AND jti=$2`,
			t.ID, claims.JTI, actionTaken, outcome); err != nil {
			return err
		}
		ev := audit.Event{Type: "ssf.event.received", RealmID: realmID, Actor: audit.Ref{Type: "ssf_transmitter", ID: t.ID}, Category: "security",
			Metadata: map[string]any{"jti": claims.JTI, "event_types": types, "action": actionTaken, "outcome": outcome}}
		if userID != "" {
			ev.Subject = &audit.Ref{Type: "user", ID: userID}
		}
		_, err = s.d.Audit.Record(ctx, tx, ev)
		return err
	})
}

func (s *Service) applyAction(ctx context.Context, tx pgx.Tx, realmID string, t *Transmitter, userID, typ, action string, local LocalActions) (string, error) {
	var protected bool
	var state string
	if err := tx.QueryRow(ctx, `SELECT protected, state FROM users WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, userID).Scan(&protected, &state); err != nil {
		if storage.IsNoRows(err) {
			return "subject_unknown", nil
		}
		return "", err
	}
	reason := "ssf:" + t.Name
	actor := audit.Ref{Type: "ssf_transmitter", ID: t.ID}
	switch action {
	case ActionRevokeSessions:
		return "applied", local.RevokeUserTx(ctx, tx, realmID, userID, reason, false)
	case ActionRevokeAll:
		return "applied", local.RevokeUserTx(ctx, tx, realmID, userID, reason, true)
	case ActionSuspend:
		// Protected accounts (platform administrators, break-glass) are
		// never suspended by an outside signal; their sessions end instead.
		if protected {
			if err := local.RevokeUserTx(ctx, tx, realmID, userID, reason, true); err != nil {
				return "", err
			}
			return "protected_account_sessions_revoked", nil
		}
		if state != identity.StateActive {
			return "already_" + state, nil
		}
		return "applied", local.SuspendUserTx(ctx, tx, realmID, userID, actor, reason)
	case ActionMarkCompromised:
		// Marking compromised runs its own transaction; revoke here so the
		// effect is in this one too, then mark after commit.
		if err := local.RevokeUserTx(ctx, tx, realmID, userID, reason, true); err != nil {
			return "", err
		}
		mark := local.MarkCompromised
		storage.AfterCommit(tx, func() { _ = mark(context.WithoutCancel(ctx), realmID, userID, actor, reason) })
		return "applied", nil
	}
	return "recorded", nil
}

// mapSubject resolves a subject identifier to a local user: iss_sub through
// the transmitter's federation connection, email (verified) only when
// allowed, complex through its user member.
func (s *Service) mapSubject(ctx context.Context, realmID string, t *Transmitter, subj map[string]any) (string, error) {
	str := func(k string) string { v, _ := subj[k].(string); return v }
	var userID string
	var err error
	switch str("format") {
	case "complex":
		user, _ := subj["user"].(map[string]any)
		if user == nil {
			return "", nil
		}
		return s.mapSubject(ctx, realmID, t, user)
	case "iss_sub":
		if t.ProviderID == "" || str("sub") == "" {
			return "", nil
		}
		err = s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM external_identities WHERE realm_id=$1 AND provider_id=$2 AND upstream_issuer=$3 AND upstream_subject=$4`,
			realmID, t.ProviderID, str("iss"), str("sub")).Scan(&userID)
	case "email":
		if !t.AllowEmailSubjects {
			return "", nil
		}
		typ, canon, ok := identity.CanonicalizeLogin(str("email"))
		if !ok || typ != "email" {
			return "", nil
		}
		err = s.d.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2
			AND verified_at IS NOT NULL`, realmID, canon).Scan(&userID)
	default:
		return "", nil
	}
	if err != nil && !storage.IsNoRows(err) {
		return "", err
	}
	return userID, nil
}

func audienceHas(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func nilJSON(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

// PruneReceived removes received-event records past their retention.
func (s *Service) PruneReceived(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM ssf_received_events WHERE received_at < $1`, s.d.Now().Add(-receivedRetention))
	return tag.RowsAffected(), err
}
