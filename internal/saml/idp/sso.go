package idp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authentication"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/saml"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/storage"
)

const requestIDPrefix = "sir"

// Message is an inbound protocol message from either binding.
type Message struct {
	Binding string
	// Encoded is the SAMLRequest or SAMLResponse parameter (HTTP-POST).
	Encoded    string
	RelayState string
	// RawQuery is the HTTP-Redirect query; its detached signature is
	// verified over the parameters exactly as received.
	RawQuery string
}

// Delivery is what the HTTP layer sends to the browser.
type Delivery struct {
	// Form is an auto-submitting HTTP-POST binding form.
	Form *saml.PostForm
	// RedirectURL is an HTTP-Redirect binding message or the login UI.
	RedirectURL       string
	TransactionCookie string
	TransactionID     string
	SessionCookie     string
	// SessionID is the IdP session a silent completion used.
	SessionID string
	// SessionTransient asks for a browser-session cookie (SES-020).
	SessionTransient bool
	// ClearSession ends the browser's session cookie (logout).
	ClearSession bool
}

// Received is an accepted AuthnRequest waiting for the browser to continue.
type Received struct {
	Ref           string
	BindingCookie string
}

// requestOptions are what the AuthnRequest asked for.
type requestOptions struct {
	RequestedFormat string   `json:"requested_format,omitempty"`
	RequiredRank    int      `json:"required_rank,omitempty"`
	ClassRefs       []string `json:"class_refs,omitempty"`
	Comparison      string   `json:"comparison,omitempty"`
	Passive         bool     `json:"passive,omitempty"`
	ForceAuthn      bool     `json:"force_authn,omitempty"`
	Unsolicited     bool     `json:"unsolicited,omitempty"`
}

// pending is a stored request.
type pending struct {
	ID            string
	AppID         string
	RequestID     string
	ACS           string
	RelayState    string
	TransactionID string
	Verifier      string
	Options       requestOptions
	Expires       time.Time
	Consumed      bool
	BindingDigest string
}

// Errors returned to the browser locally (never to an unvalidated ACS).
var (
	errUnknownSP    = problem.ErrBadRequest.WithDetail("the service provider is not registered").WithExtension("reason", "saml_unknown_service_provider")
	errBadRequest   = problem.ErrBadRequest.WithDetail("the SAML request is not acceptable").WithExtension("reason", "saml_invalid_request")
	errBadSignature = problem.ErrBadRequest.WithDetail("the SAML request signature is missing or invalid").WithExtension("reason", "saml_signature")
	errBadACS       = problem.ErrBadRequest.WithDetail("the assertion consumer service is not registered for this service provider").
			WithExtension("reason", "saml_unregistered_acs")
	errReplay        = problem.ErrBadRequest.WithDetail("the SAML request was already used").WithExtension("reason", "saml_request_replay")
	errNoPending     = problem.ErrTransactionInvalid.WithDetail("the SAML sign-in cannot continue in this browser").WithExtension("reason", "saml_request_invalid")
	errUnsolicited   = problem.ErrForbidden.WithDetail("IdP-initiated sign-in is disabled for this service provider").WithExtension("reason", "saml_unsolicited_disabled")
	errNoInteraction = problem.ErrUnavailable.WithDetail("no interaction surface is configured for this realm or application")
)

// classRanks are the AuthnContextClassRef values understood without
// configuration, by local assurance rank (session.ACRRank).
var classRanks = map[string]int{
	saml.ClassUnspecified: 1, saml.ClassPassword: 1, saml.ClassPasswordProtected: 1,
	saml.ClassMobileTwoFactor: 3, saml.ClassTimeSyncToken: 3, saml.ClassMicrosoftMultipleAuth: 3, saml.ClassREFEDSMFA: 3,
	"urn:proudauth:acr:single_factor": 1, "urn:proudauth:acr:federated": 1, "urn:proudauth:acr:mfa": 3,
	session.ACRPhishingResistant: 4,
}

func (a *App) classRank(ref string) int {
	if acr, ok := a.AuthnContextMap[ref]; ok {
		return session.ACRRank(acr)
	}
	return classRanks[ref]
}

func (a *App) skew() time.Duration { return time.Duration(a.ClockSkewSeconds) * time.Second }

func (s *Service) reject(ctx context.Context, rlm *realm.Realm, app *App, reason string) {
	meta := map[string]any{"reason": reason}
	ev := audit.Event{Type: "saml.request.rejected", RealmID: rlm.ID, Actor: audit.Ref{Type: "anonymous", ID: "saml"}, Outcome: audit.Failure,
		ReasonCode: reason, Category: "security", Metadata: meta}
	if app != nil {
		ev.Target = &audit.Ref{Type: "saml_application", ID: app.ID}
		ev.ClientID = app.ClientID
		meta["entity_id"] = app.EntityID
	}
	_ = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := s.d.Audit.Record(ctx, tx, ev)
		return err
	})
}

// decode reads a message from its binding and parses it safely. For
// HTTP-Redirect the detached signature, if any, is returned for checking.
func (s *Service) decode(m Message, param string) (*etree.Element, string, *saml.RedirectSignature, error) {
	var raw []byte
	relay := m.RelayState
	var sig *saml.RedirectSignature
	switch m.Binding {
	case saml.BindingRedirect:
		msg, rs, rsig, err := saml.ParseRedirect(m.RawQuery, param)
		if err != nil {
			return nil, "", nil, err
		}
		if raw, err = saml.DecodeRedirect(msg, s.Limits.MaxBytes); err != nil {
			return nil, "", nil, err
		}
		relay, sig = rs, rsig
	case saml.BindingPOST:
		if len(relay) > saml.MaxRelayState {
			return nil, "", nil, saml.ErrTooLarge
		}
		var err error
		if raw, err = saml.DecodePOST(m.Encoded, s.Limits.MaxBytes); err != nil {
			return nil, "", nil, err
		}
	default:
		return nil, "", nil, saml.ErrMalformed
	}
	root, err := saml.Parse(raw, s.Limits)
	if err != nil {
		return nil, "", nil, err
	}
	return root, relay, sig, nil
}

// issuerOf returns the Issuer value of a protocol message.
func issuerOf(el *etree.Element) string {
	iss, err := saml.Child(el, saml.NSAssertion, "Issuer")
	if err != nil || iss == nil {
		return ""
	}
	v, err := saml.Text(iss)
	if err != nil {
		return ""
	}
	return v
}

// authenticate checks a request's signature per the application's policy
// and returns the element to read from: for HTTP-POST the verified element,
// for HTTP-Redirect the parsed message (the detached signature covers all of
// it). A present signature is always checked when the service provider has
// registered keys; one that fails is never ignored.
func (s *Service) authenticate(app *App, root *etree.Element, sig *saml.RedirectSignature) (*etree.Element, bool, error) {
	certs := app.certificates()
	now := s.d.Now()
	switch {
	case sig != nil && len(certs) > 0:
		if err := sig.Verify(certs, now); err != nil {
			return nil, false, err
		}
		return root, true, nil
	case saml.Signed(root) && len(certs) > 0:
		v, err := saml.Verify(root, certs, now)
		if err != nil {
			return nil, false, err
		}
		return v, true, nil
	case app.RequireSignedRequests:
		return nil, false, saml.ErrNoSignature
	}
	return root, false, nil
}

// inWindow accepts an IssueInstant no later than now plus skew and no older
// than ten minutes plus skew.
func inWindow(v string, now time.Time, skew time.Duration) bool {
	t, err := saml.ParseTime(v)
	if err != nil {
		return false
	}
	return !t.After(now.Add(skew)) && !t.Before(now.Add(-10*time.Minute-skew))
}

// Receive validates an AuthnRequest (SAML-003..SAML-005) and records it.
// Until the assertion consumer service is validated against the registry,
// failures are local errors: nothing is ever sent to an unregistered URL.
// After that, a request the identity provider cannot honor is answered with
// a SAML error response to the validated ACS (returned as Delivery).
func (s *Service) Receive(ctx context.Context, rlm *realm.Realm, m Message, bindingCookie string) (*Received, *Delivery, error) {
	root, relay, sig, err := s.decode(m, "SAMLRequest")
	if err != nil {
		s.reject(ctx, rlm, nil, "decode:"+reasonOf(err))
		return nil, nil, errBadRequest
	}
	if !saml.Is(root, saml.NSProtocol, "AuthnRequest") {
		s.reject(ctx, rlm, nil, "not_an_authn_request")
		return nil, nil, errBadRequest
	}
	app, err := s.ByEntityID(ctx, nil, rlm, issuerOf(root))
	if err != nil {
		s.reject(ctx, rlm, nil, "unknown_service_provider")
		return nil, nil, errUnknownSP
	}
	if app.State != "active" {
		s.reject(ctx, rlm, app, "application_inactive")
		return nil, nil, errUnknownSP
	}
	req, signed, err := s.authenticate(app, root, sig)
	if err != nil {
		s.reject(ctx, rlm, app, "signature:"+reasonOf(err))
		return nil, nil, errBadSignature
	}
	now := s.d.Now()
	id := saml.Attr(req, "ID")
	if saml.Attr(req, "Version") != "2.0" || !saml.ValidID(id) || issuerOf(req) != app.EntityID {
		s.reject(ctx, rlm, app, "malformed")
		return nil, nil, errBadRequest
	}
	if !inWindow(saml.Attr(req, "IssueInstant"), now, app.skew()) {
		s.reject(ctx, rlm, app, "issue_instant")
		return nil, nil, errBadRequest
	}
	// Destination is required on signed POST messages (bindings §3.5.5.2)
	// and must name this endpoint whenever present.
	dest := saml.Attr(req, "Destination")
	if (dest != "" && dest != s.IdPEndpoints(rlm).SSOURL) || (dest == "" && signed && m.Binding == saml.BindingPOST) {
		s.reject(ctx, rlm, app, "destination")
		return nil, nil, errBadRequest
	}
	acs, ok := app.resolveACS(saml.Attr(req, "AssertionConsumerServiceURL"), saml.Attr(req, "AssertionConsumerServiceIndex"), saml.Attr(req, "ProtocolBinding"))
	if !ok {
		s.reject(ctx, rlm, app, "unregistered_acs")
		return nil, nil, errBadACS
	}
	// From here on the destination is trusted: refusals are SAML responses.
	refuse := func(status, reason string) (*Received, *Delivery, error) {
		s.reject(ctx, rlm, app, reason)
		d, err := s.errorResponse(ctx, rlm, app, id, acs, relay, status)
		return nil, d, err
	}
	opts := requestOptions{ForceAuthn: saml.Attr(req, "ForceAuthn") == "true", Passive: saml.Attr(req, "IsPassive") == "true"}
	if sub, _ := saml.Child(req, saml.NSAssertion, "Subject"); sub != nil {
		return refuse(saml.StatusRequestUnsupported, "subject_requested")
	}
	if policy, err := saml.Child(req, saml.NSProtocol, "NameIDPolicy"); err != nil {
		return refuse(saml.StatusInvalidNameIDPolicy, "name_id_policy")
	} else if policy != nil {
		f := saml.Attr(policy, "Format")
		if f != "" && f != saml.NameIDUnspecified && f != app.NameIDFormat {
			return refuse(saml.StatusInvalidNameIDPolicy, "name_id_format")
		}
		if q := saml.Attr(policy, "SPNameQualifier"); q != "" && q != app.EntityID && !slices.Contains(app.AdditionalAudiences, q) {
			return refuse(saml.StatusInvalidNameIDPolicy, "sp_name_qualifier")
		}
		opts.RequestedFormat = f
	}
	if rac, err := saml.Child(req, saml.NSProtocol, "RequestedAuthnContext"); err != nil {
		return refuse(saml.StatusNoAuthnContext, "requested_authn_context")
	} else if rac != nil {
		if len(saml.Children(rac, saml.NSAssertion, "AuthnContextDeclRef")) > 0 {
			return refuse(saml.StatusNoAuthnContext, "authn_context_decl_unsupported")
		}
		opts.Comparison = saml.Attr(rac, "Comparison")
		minRank, maxRank := 0, 0
		for _, cr := range saml.Children(rac, saml.NSAssertion, "AuthnContextClassRef") {
			v, err := saml.Text(cr)
			if err != nil {
				return refuse(saml.StatusNoAuthnContext, "requested_authn_context")
			}
			r := app.classRank(v)
			if r == 0 {
				continue // an unknown context cannot be stated truthfully
			}
			opts.ClassRefs = append(opts.ClassRefs, v)
			if minRank == 0 || r < minRank {
				minRank = r
			}
			if r > maxRank {
				maxRank = r
			}
		}
		if len(opts.ClassRefs) == 0 {
			return refuse(saml.StatusNoAuthnContext, "unknown_authn_context")
		}
		switch opts.Comparison {
		case "", "exact", "minimum", "maximum":
			opts.RequiredRank = minRank
		case "better":
			opts.RequiredRank = maxRank + 1
			if opts.RequiredRank > 4 {
				return refuse(saml.StatusNoAuthnContext, "unsatisfiable_authn_context")
			}
		default:
			return refuse(saml.StatusNoAuthnContext, "comparison")
		}
	}
	if opts.Passive && opts.ForceAuthn {
		return refuse(saml.StatusNoPassive, "passive_and_force_authn")
	}
	ref, cookie, err := s.record(ctx, rlm, app, id, acs, relay, opts, bindingCookie)
	if err != nil {
		if errors.Is(err, errReplay) {
			s.reject(ctx, rlm, app, "request_replay")
		}
		return nil, nil, err
	}
	return &Received{Ref: ref, BindingCookie: cookie}, nil, nil
}

// resolveACS picks the assertion consumer service: an exactly registered
// URL, a registered index, or the default. HTTP-POST only.
func (a *App) resolveACS(acsURL, index, binding string) (string, bool) {
	if binding != "" && binding != saml.BindingPOST {
		return "", false
	}
	switch {
	case acsURL != "" && index != "":
		return "", false // mutually exclusive (core §3.4.1)
	case acsURL != "":
		for _, ep := range a.ACS {
			if ep.URL == acsURL {
				return ep.URL, true
			}
		}
		return "", false
	case index != "":
		n, err := strconv.Atoi(index)
		if err != nil {
			return "", false
		}
		for _, ep := range a.ACS {
			if ep.Index == n {
				return ep.URL, true
			}
		}
		return "", false
	}
	return a.defaultACS().URL, true
}

// record stores an accepted request. The browser that sent it gets a
// binding secret (cookie); only that browser can continue the sign-in and
// receive the assertion, so a leaked continuation URL is useless elsewhere.
func (s *Service) record(ctx context.Context, rlm *realm.Realm, app *App, requestID, acs, relay string, opts requestOptions, bindingCookie string) (string, string, error) {
	cookie := ""
	if len(bindingCookie) != 43 {
		bindingCookie = secret.Token("")
		cookie = bindingCookie
	}
	id := ids.New(requestIDPrefix)
	oj, _ := json.Marshal(opts)
	now := s.d.Now()
	_, err := s.d.DB.Pool.Exec(ctx, `INSERT INTO saml_idp_requests (id, realm_id, app_id, request_id, acs_url, relay_state, state_digest, binding_digest,
		verifier_ciphertext, key_version, options, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'\x'::bytea,0,$9,$10,$11)`,
		id, rlm.ID, app.ID, nilIfEmpty(requestID), acs, nilIfEmpty(relay), secret.Digest(secret.Token("")), secret.Digest(bindingCookie), oj,
		now.Add(s.d.Cfg.Tokens.TransactionTTL), now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return "", "", errReplay
		}
		return "", "", err
	}
	return id, cookie, nil
}

func (s *Service) loadPending(ctx context.Context, q storage.Querier, where string, arg any, lock bool) (*pending, error) {
	sql := `SELECT id, app_id, coalesce(request_id,''), acs_url, coalesce(relay_state,''), coalesce(transaction_id,''), verifier_ciphertext,
		options, expires_at, consumed_at IS NOT NULL, binding_digest FROM saml_idp_requests WHERE ` + where
	if lock {
		sql += ` FOR UPDATE`
	}
	p := &pending{}
	var ct, oj []byte
	err := q.QueryRow(ctx, sql, arg).Scan(&p.ID, &p.AppID, &p.RequestID, &p.ACS, &p.RelayState, &p.TransactionID, &ct, &oj, &p.Expires, &p.Consumed,
		&p.BindingDigest)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, errNoPending
		}
		return nil, err
	}
	_ = json.Unmarshal(oj, &p.Options)
	if len(ct) > 0 {
		v, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("saml-idp-verifier:"+p.ID))
		if err != nil {
			return nil, err
		}
		p.Verifier = string(v)
	}
	return p, nil
}

// StartInput carries the browser context for starting sign-in.
type StartInput struct {
	Ref           string
	BindingCookie string
	SessionCookie string
	ClientIP      string
	UserAgent     string
}

// Start begins (or silently completes) sign-in for a recorded request. It
// runs the ordinary authentication transaction for the application's
// backing client: an SSO session is reused when policy allows (SES-014),
// ForceAuthn becomes prompt=login, IsPassive never shows a login page, and
// requested assurance becomes the transaction's ACR requirement (step-up).
func (s *Service) Start(ctx context.Context, rlm *realm.Realm, in StartInput) (*Delivery, error) {
	if !ids.Valid(in.Ref) {
		return nil, errNoPending
	}
	p, err := s.loadPending(ctx, s.d.DB.Pool, `id=$1`, in.Ref, false)
	if err != nil {
		return nil, err
	}
	if p.Consumed || p.TransactionID != "" || !s.d.Now().Before(p.Expires) || in.BindingCookie == "" ||
		!secret.Equal(secret.Digest(in.BindingCookie), p.BindingDigest) {
		return nil, errNoPending
	}
	app, err := s.Get(ctx, nil, rlm, p.AppID)
	if err != nil {
		return nil, err
	}
	if !rlm.Active() || app.State != "active" || rlm.GrantDisabled("authorization_code") {
		// The emergency switch for interactive grants covers SAML sign-in,
		// whose assertion is issued from an internal authorization code.
		return s.errorResponse(ctx, rlm, app, p.RequestID, p.ACS, p.RelayState, saml.StatusRequestDenied)
	}
	var reuse *session.Session
	if in.SessionCookie != "" {
		if sess, err := s.Sessions.ByCookie(ctx, rlm.ID, in.SessionCookie); err == nil {
			reuse = sess
		}
	}
	var prompt, acr []string
	if p.Options.ForceAuthn {
		prompt = []string{"login"}
	}
	switch {
	case p.Options.RequiredRank >= 4:
		acr = []string{session.ACRPhishingResistant}
	case p.Options.RequiredRank == 3:
		acr = []string{"urn:proudauth:acr:mfa"}
	}
	state := secret.Token("")
	verifier := secret.Token("") + secret.Token("")
	sum := sha256.Sum256([]byte(verifier))
	started, err := s.Auth.Start(ctx, authentication.StartInput{RealmID: rlm.ID, Client: app.client, Mode: "browser", Intent: "login",
		RedirectURI: s.continueURL(rlm), Scopes: app.scopes(), State: state, CodeChallenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		ChallengeMethod: "S256", Prompt: prompt, ACRValues: acr, OrgID: app.OrganizationID, ClientIP: in.ClientIP, UserAgent: in.UserAgent,
		ReuseSession: reuse})
	if err != nil {
		return nil, err
	}
	ct, kv, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(verifier), []byte("saml-idp-verifier:"+p.ID))
	if err != nil {
		return nil, err
	}
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE saml_idp_requests SET transaction_id=$2, state_digest=$3, verifier_ciphertext=$4, key_version=$5
		WHERE id=$1 AND transaction_id IS NULL AND consumed_at IS NULL`, p.ID, started.Transaction.ID, secret.Digest(state), ct, kv)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() != 1 {
		return nil, errNoPending
	}
	proof := authentication.Proof{Continuation: started.Continuation}
	if started.Transaction.UserID != "" {
		st, err := s.Auth.Resume(ctx, rlm.ID, started.Transaction.ID, proof)
		if err == nil && st.RedirectTo != "" {
			u, err := url.Parse(st.RedirectTo)
			if err != nil {
				return nil, err
			}
			d, err := s.Continue(ctx, rlm, u.Query(), in.BindingCookie)
			if err != nil {
				return nil, err
			}
			d.SessionCookie = st.SessionCookie
			if st.Completion != nil {
				d.SessionTransient, d.SessionID = st.Completion.Transient, st.Completion.SessionID
			}
			return d, nil
		}
	}
	if p.Options.Passive {
		// IsPassive: no interaction is allowed, so an incomplete sign-in ends
		// here with NoPassive (core §3.4.1).
		_, _ = s.Auth.Cancel(ctx, rlm.ID, started.Transaction.ID, proof)
		return s.finishWithError(ctx, rlm, app, p.ID, saml.StatusNoPassive)
	}
	ui := app.LoginUIURL
	if ui == "" {
		ui = rlm.Policy.Interaction.LoginUIURL
	}
	if ui == "" {
		_, _ = s.Auth.Cancel(ctx, rlm.ID, started.Transaction.ID, proof)
		return nil, errNoInteraction
	}
	return &Delivery{RedirectURL: authentication.BuildRedirect(ui, map[string]string{"transaction_id": started.Transaction.ID, "realm": rlm.Name}),
		TransactionCookie: started.Continuation, TransactionID: started.Transaction.ID}, nil
}

// finishWithError consumes a request and answers it with an error status.
func (s *Service) finishWithError(ctx context.Context, rlm *realm.Realm, app *App, ref, status string) (*Delivery, error) {
	var p *pending
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		if p, err = s.loadPending(ctx, tx, `id=$1`, ref, true); err != nil {
			return err
		}
		if p.Consumed {
			return errNoPending
		}
		_, err = tx.Exec(ctx, `UPDATE saml_idp_requests SET consumed_at=$2 WHERE id=$1`, p.ID, s.d.Now())
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.errorResponse(ctx, rlm, app, p.RequestID, p.ACS, p.RelayState, status)
}

// Continue completes sign-in when the browser comes back from the login
// interface (or right away for a reused session). The query is the
// transaction's authorization response, addressed to this endpoint: an
// internal authorization code and the state, or an error. The request is
// consumed once, only by the browser holding its binding secret; the code is
// redeemed here with the server-held PKCE verifier and must belong to this
// request's transaction, client and redirect.
func (s *Service) Continue(ctx context.Context, rlm *realm.Realm, q url.Values, bindingCookie string) (*Delivery, error) {
	state := q.Get("state")
	if state == "" || len(state) > 128 || bindingCookie == "" {
		return nil, errNoPending
	}
	var d *Delivery
	var app *App
	var refusal string
	var p *pending
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		p, err = s.loadPending(ctx, tx, `state_digest=$1`, secret.Digest(state), true)
		if err != nil {
			return err
		}
		if p.Consumed || !s.d.Now().Before(p.Expires) || !secret.Equal(secret.Digest(bindingCookie), p.BindingDigest) {
			return errNoPending
		}
		if _, err := tx.Exec(ctx, `UPDATE saml_idp_requests SET consumed_at=$2 WHERE id=$1`, p.ID, s.d.Now()); err != nil {
			return err
		}
		if app, err = s.Get(ctx, tx, rlm, p.AppID); err != nil {
			return err
		}
		if e := q.Get("error"); e != "" {
			refusal = statusForError(e)
			return nil
		}
		d, refusal, err = s.issue(ctx, tx, rlm, app, p, q.Get("code"))
		return err
	})
	if err != nil {
		return nil, err
	}
	if refusal != "" {
		s.reject(ctx, rlm, app, "sign_in_not_completed:"+refusal)
		return s.errorResponse(ctx, rlm, app, p.RequestID, p.ACS, p.RelayState, refusal)
	}
	return d, nil
}

func statusForError(e string) string {
	switch e {
	case "access_denied":
		return saml.StatusRequestDenied
	case "login_required", "interaction_required", "consent_required":
		return saml.StatusNoPassive
	}
	return saml.StatusAuthnFailed
}

// issue redeems the code and builds the assertion. It returns a second-level
// status instead when the sign-in cannot be asserted as requested.
func (s *Service) issue(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, app *App, p *pending, code string) (*Delivery, string, error) {
	c, err := s.Sessions.ConsumeCodeTx(ctx, tx, rlm.ID, code)
	if err != nil {
		return nil, "", problem.ErrInvalidProof
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	if p.Verifier == "" || c.ClientRef != app.ClientRef || c.TransactionID != p.TransactionID || c.RedirectURI != s.continueURL(rlm) ||
		c.Method != "S256" || !secret.Equal(c.Challenge, base64.RawURLEncoding.EncodeToString(sum[:])) {
		return nil, "", problem.ErrInvalidProof
	}
	g, err := s.Sessions.GrantTx(ctx, tx, c.GrantID)
	if err != nil {
		return nil, "", err
	}
	if g.State != "active" || g.SubjectType != "user" || g.SessionID == "" {
		return nil, saml.StatusAuthnFailed, nil
	}
	sess, err := s.Sessions.Active(ctx, tx, rlm.ID, g.SessionID)
	if err != nil {
		return nil, saml.StatusAuthnFailed, nil
	}
	u, err := s.Users.User(ctx, tx, rlm.ID, g.SubjectID)
	if err != nil {
		return nil, "", err
	}
	if !u.CanAuthenticate(s.d.Now()) {
		return nil, saml.StatusAuthnFailed, nil
	}
	if app.OrganizationID != "" {
		// An organization's application admits only that organization's
		// active members (TEN-005); its policies applied to the sign-in.
		if _, err := s.Orgs.ActiveMembership(ctx, tx, rlm.ID, app.OrganizationID, u.ID); err != nil {
			return nil, saml.StatusRequestDenied, nil
		}
	}
	if session.ACRRank(g.ACR) < p.Options.RequiredRank {
		return nil, saml.StatusNoAuthnContext, nil
	}
	format := app.NameIDFormat
	nameID, err := s.nameID(ctx, tx, rlm, app, u, format)
	if err != nil {
		if errors.Is(err, errNoNameID) {
			return nil, saml.StatusInvalidNameIDPolicy, nil
		}
		return nil, "", err
	}
	var sessionIndex string
	if err := tx.QueryRow(ctx, `INSERT INTO saml_idp_sessions (id, realm_id, app_id, session_id, user_id, session_index, name_id_digest, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (app_id, session_id) DO UPDATE SET name_id_digest=EXCLUDED.name_id_digest,
		expires_at=EXCLUDED.expires_at, ended_at=NULL RETURNING session_index`, ids.New("sps"), rlm.ID, app.ID, sess.ID, u.ID, saml.NewID(),
		nameIDDigest(format, nameID), sess.AbsoluteExpiresAt).Scan(&sessionIndex); err != nil {
		return nil, "", err
	}
	data := assertionData{user: u, nameID: nameID, format: format, sessionIndex: sessionIndex, authTime: sess.AuthTime,
		sessionEnd: sess.AbsoluteExpiresAt, classRef: app.classRefFor(p.Options, g.ACR, g.AMR)}
	if g.AuthTime != nil {
		data.authTime = *g.AuthTime
	}
	xml, err := s.response(ctx, rlm, app, p.RequestID, p.ACS, saml.StatusSuccess, "", &data)
	if err != nil {
		return nil, "", err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.assertion.issued", RealmID: rlm.ID, OrgID: app.OrganizationID,
		Actor: audit.Ref{Type: "user", ID: u.ID, SessionID: sess.ID}, Subject: &audit.Ref{Type: "user", ID: u.ID},
		Target: &audit.Ref{Type: "saml_application", ID: app.ID}, ClientID: app.ClientID, SessionID: sess.ID, GrantID: g.ID, Category: "token",
		Metadata: map[string]any{"entity_id": app.EntityID, "acs": p.ACS, "name_id_format": format, "authn_context": data.classRef,
			"unsolicited": p.Options.Unsolicited, "attributes": len(app.Attributes)}}); err != nil {
		return nil, "", err
	}
	return &Delivery{Form: &saml.PostForm{Action: p.ACS, Param: "SAMLResponse", Value: base64.StdEncoding.EncodeToString(xml),
		RelayState: p.RelayState}}, "", nil
}

// classRefFor states the authentication context: a requested context the
// session satisfies, otherwise the one that describes the session.
func (a *App) classRefFor(o requestOptions, acr string, amr []string) string {
	rank := session.ACRRank(acr)
	if o.Comparison != "better" {
		// The strongest requested context the session meets. ("better" asks
		// for more than any listed context, so the session describes itself.)
		best, bestRank := "", 0
		for _, ref := range o.ClassRefs {
			if r := a.classRank(ref); r > 0 && r <= rank && r > bestRank {
				best, bestRank = ref, r
			}
		}
		if best != "" {
			return best
		}
	}
	keys := make([]string, 0, len(a.AuthnContextMap))
	for k, v := range a.AuthnContextMap {
		if v == acr {
			keys = append(keys, k)
		}
	}
	if len(keys) > 0 {
		sort.Strings(keys)
		return keys[0]
	}
	switch acr {
	case session.ACRPhishingResistant, "urn:proudauth:acr:mfa":
		return acr
	case "urn:proudauth:acr:single_factor":
		if slices.Contains(amr, "pwd") {
			return saml.ClassPasswordProtected
		}
	}
	return saml.ClassUnspecified
}

var errNoNameID = errors.New("saml: no name identifier of the configured format")

func nameIDDigest(format, value string) string { return secret.Digest(format + "|" + value) }

// nameID derives the subject identifier (SAML-006):
//   - persistent: an opaque value per application, derived once with the
//     realm secret and stored, so it is stable for the account, differs per
//     service provider (no correlation between them) and goes with the account;
//   - emailAddress: the account's verified email only, never an unverified one;
//   - unspecified: the account's immutable public identifier;
//   - transient: a new random value for every assertion.
func (s *Service) nameID(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, app *App, u *identity.User, format string) (string, error) {
	switch format {
	case saml.NameIDPersistent:
		sector := "saml:" + app.ID
		var sub string
		if err := tx.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3`, rlm.ID, sector, u.ID).Scan(&sub); err == nil {
			return sub, nil
		} else if !storage.IsNoRows(err) {
			return "", err
		}
		b := s.d.Keys.DeriveBytes(keys.PurposePairwise, sector, u.ID)
		sub = "sps_" + base64.RawURLEncoding.EncodeToString(b[:20])
		if _, err := tx.Exec(ctx, `INSERT INTO pairwise_subjects (realm_id, sector, user_id, subject) VALUES ($1,$2,$3,$4)
			ON CONFLICT (realm_id, sector, user_id) DO NOTHING`, rlm.ID, sector, u.ID, sub); err != nil {
			return "", err
		}
		err := tx.QueryRow(ctx, `SELECT subject FROM pairwise_subjects WHERE realm_id=$1 AND sector=$2 AND user_id=$3`, rlm.ID, sector, u.ID).Scan(&sub)
		return sub, err
	case saml.NameIDEmail:
		if e := verifiedEmail(u); e != "" {
			return e, nil
		}
		return "", errNoNameID
	case saml.NameIDUnspecified:
		return u.ID, nil
	case saml.NameIDTransient:
		return saml.NewID(), nil
	}
	return "", errNoNameID
}

func verifiedEmail(u *identity.User) string {
	if e := u.PrimaryEmail(); e != nil && e.Verified() {
		return e.Value
	}
	for _, i := range u.Identifiers {
		if i.Type == "email" && i.Verified() {
			return i.Value
		}
	}
	return ""
}

func verifiedPhone(u *identity.User) string {
	for _, i := range u.Identifiers {
		if i.Type == "phone" && i.Verified() {
			return i.Value
		}
	}
	return ""
}

func (a *App) attributeValue(m AttributeMapping, d *assertionData) string {
	u := d.user
	switch m.Source {
	case "email":
		return verifiedEmail(u)
	case "email_verified":
		if verifiedEmail(u) != "" {
			return "true"
		}
	case "name":
		return u.DisplayName
	case "given_name":
		return u.GivenName
	case "family_name":
		return u.FamilyName
	case "preferred_username":
		return u.Username()
	case "locale":
		return u.Locale
	case "zoneinfo":
		return u.Zoneinfo
	case "phone_number":
		return verifiedPhone(u)
	case "user_id":
		return u.ID
	case "subject":
		return d.nameID
	case "organization_id":
		return a.OrganizationID
	case "static":
		return m.Value
	}
	return ""
}

// assertionData is what an assertion states.
type assertionData struct {
	user         *identity.User
	nameID       string
	format       string
	sessionIndex string
	authTime     time.Time
	sessionEnd   time.Time
	classRef     string
}

// response builds and signs a Response: Issuer, Status and, for success,
// one assertion with a bearer subject confirmation bound to the ACS and the
// request, audience restriction, authentication statement and the mapped
// attributes. The assertion is signed first, then the response, as the
// application asks; at least one of them always is.
func (s *Service) response(ctx context.Context, rlm *realm.Realm, app *App, inResponseTo, acs, status, subStatus string, d *assertionData) ([]byte, error) {
	key, err := s.Keys.Active(ctx, rlm.ID)
	if err != nil {
		return nil, err
	}
	now := s.d.Now()
	issuer := s.IdPEndpoints(rlm).EntityID
	resp := saml.NewElement("samlp", "Response")
	resp.CreateAttr("xmlns:samlp", saml.NSProtocol)
	resp.CreateAttr("xmlns:saml", saml.NSAssertion)
	resp.CreateAttr("ID", saml.NewID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", saml.Time(now))
	resp.CreateAttr("Destination", acs)
	if inResponseTo != "" {
		resp.CreateAttr("InResponseTo", inResponseTo)
	}
	saml.AddChild(resp, "saml", "Issuer").SetText(issuer)
	st := saml.AddChild(resp, "samlp", "Status")
	code := saml.AddChild(st, "samlp", "StatusCode")
	code.CreateAttr("Value", status)
	if subStatus != "" {
		saml.AddChild(code, "samlp", "StatusCode").CreateAttr("Value", subStatus)
	}
	if d != nil {
		a := s.assertion(rlm, app, issuer, inResponseTo, acs, now, d)
		if app.SignAssertion {
			if err := saml.Sign(a, key.Signer, key.CertDER, app.SignatureAlgorithm); err != nil {
				return nil, err
			}
		}
		if app.EncryptAssertions {
			// Sign, then encrypt: the service provider verifies the
			// assertion's signature after decrypting it.
			cert, err := saml.ParseCertificate(app.Settings.EncryptionCertificate)
			if err != nil {
				return nil, err
			}
			if a, err = saml.EncryptAssertion(a, cert, app.DataEncryptionAlgorithm, app.KeyTransportAlgorithm); err != nil {
				return nil, err
			}
		}
		resp.AddChild(a)
	}
	if app.SignResponse || d == nil {
		if err := saml.Sign(resp, key.Signer, key.CertDER, app.SignatureAlgorithm); err != nil {
			return nil, err
		}
	}
	return saml.Serialize(resp)
}

func (s *Service) assertion(rlm *realm.Realm, app *App, issuer, inResponseTo, acs string, now time.Time, d *assertionData) *etree.Element {
	life := time.Duration(app.AssertionLifetimeSeconds) * time.Second
	a := saml.NewElement("saml", "Assertion")
	a.CreateAttr("xmlns:saml", saml.NSAssertion)
	a.CreateAttr("ID", saml.NewID())
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", saml.Time(now))
	saml.AddChild(a, "saml", "Issuer").SetText(issuer)
	subject := saml.AddChild(a, "saml", "Subject")
	nid := saml.AddChild(subject, "saml", "NameID")
	nid.CreateAttr("Format", d.format)
	if d.format == saml.NameIDPersistent || d.format == saml.NameIDTransient {
		nid.CreateAttr("NameQualifier", issuer)
		nid.CreateAttr("SPNameQualifier", app.EntityID)
	}
	nid.SetText(d.nameID)
	sc := saml.AddChild(subject, "saml", "SubjectConfirmation")
	sc.CreateAttr("Method", saml.ConfirmationMethodBearer)
	scd := saml.AddChild(sc, "saml", "SubjectConfirmationData")
	if inResponseTo != "" {
		scd.CreateAttr("InResponseTo", inResponseTo)
	}
	scd.CreateAttr("NotOnOrAfter", saml.Time(now.Add(life)))
	scd.CreateAttr("Recipient", acs)
	conds := saml.AddChild(a, "saml", "Conditions")
	conds.CreateAttr("NotBefore", saml.Time(now.Add(-app.skew())))
	conds.CreateAttr("NotOnOrAfter", saml.Time(now.Add(life)))
	ar := saml.AddChild(conds, "saml", "AudienceRestriction")
	saml.AddChild(ar, "saml", "Audience").SetText(app.EntityID)
	for _, extra := range app.AdditionalAudiences {
		saml.AddChild(ar, "saml", "Audience").SetText(extra)
	}
	as := saml.AddChild(a, "saml", "AuthnStatement")
	as.CreateAttr("AuthnInstant", saml.Time(d.authTime))
	as.CreateAttr("SessionIndex", d.sessionIndex)
	if !d.sessionEnd.IsZero() {
		as.CreateAttr("SessionNotOnOrAfter", saml.Time(d.sessionEnd))
	}
	ac := saml.AddChild(as, "saml", "AuthnContext")
	saml.AddChild(ac, "saml", "AuthnContextClassRef").SetText(d.classRef)
	var stmt *etree.Element
	for _, m := range app.Attributes {
		v := app.attributeValue(m, d)
		if v == "" {
			continue // nothing to release, or not verified
		}
		if stmt == nil {
			stmt = saml.AddChild(a, "saml", "AttributeStatement")
		}
		at := saml.AddChild(stmt, "saml", "Attribute")
		at.CreateAttr("Name", m.Name)
		at.CreateAttr("NameFormat", m.NameFormat)
		if m.FriendlyName != "" {
			at.CreateAttr("FriendlyName", m.FriendlyName)
		}
		saml.AddChild(at, "saml", "AttributeValue").SetText(v)
	}
	return a
}

// errorResponse answers a request with an error status at its validated
// ACS. Error responses are always signed.
func (s *Service) errorResponse(ctx context.Context, rlm *realm.Realm, app *App, inResponseTo, acs, relay, subStatus string) (*Delivery, error) {
	top := saml.StatusResponder
	if subStatus == saml.StatusRequestUnsupported || subStatus == saml.StatusInvalidNameIDPolicy || subStatus == saml.StatusUnsupportedBinding {
		top = saml.StatusRequester
	}
	xml, err := s.response(ctx, rlm, app, inResponseTo, acs, top, subStatus, nil)
	if err != nil {
		return nil, err
	}
	return &Delivery{Form: &saml.PostForm{Action: acs, Param: "SAMLResponse", Value: base64.StdEncoding.EncodeToString(xml), RelayState: relay}}, nil
}

// IdPInitiated starts an unsolicited sign-in to a service provider
// (SAML-007). It is refused unless the application explicitly allows it.
// The policy that makes it acceptable: the destination is always the
// application's registered default ACS, the RelayState is only the
// registered one (never taken from the request, so this endpoint is no
// redirector), the response carries no InResponseTo, the assertion is
// still bound to the browser that asked, and each use is audited.
func (s *Service) IdPInitiated(ctx context.Context, rlm *realm.Realm, spRef, bindingCookie string) (*Received, error) {
	app, err := s.ByEntityID(ctx, nil, rlm, spRef)
	if err != nil {
		if app, err = s.Get(ctx, nil, rlm, spRef); err != nil || !ids.Valid(spRef) {
			s.reject(ctx, rlm, nil, "unknown_service_provider")
			return nil, errUnknownSP
		}
	}
	if !app.AllowIdPInitiated {
		s.reject(ctx, rlm, app, "unsolicited_disabled")
		return nil, errUnsolicited
	}
	if app.State != "active" {
		s.reject(ctx, rlm, app, "application_inactive")
		return nil, errUnknownSP
	}
	ref, cookie, err := s.record(ctx, rlm, app, "", app.defaultACS().URL, app.IdPInitiatedRelayState, requestOptions{Unsolicited: true}, bindingCookie)
	if err != nil {
		return nil, err
	}
	return &Received{Ref: ref, BindingCookie: cookie}, nil
}

// Metadata renders the realm's identity provider metadata: the HTTP-Redirect
// and HTTP-POST single sign-on and logout endpoints, the supported NameID
// formats, and every published signing certificate (the next key before it
// signs, the previous one while it retires).
func (s *Service) Metadata(ctx context.Context, rlm *realm.Realm) ([]byte, error) {
	certs, err := s.Keys.Published(ctx, rlm.ID)
	if err != nil {
		return nil, err
	}
	ep := s.IdPEndpoints(rlm)
	return saml.IdPMetadata(saml.IdPDescriptor{EntityID: ep.EntityID, SigningCerts: certs, NameIDFormats: saml.NameIDFormats,
		SSO: []saml.Endpoint{{Binding: saml.BindingRedirect, URL: ep.SSOURL}, {Binding: saml.BindingPOST, URL: ep.SSOURL}},
		SLO: []saml.Endpoint{{Binding: saml.BindingRedirect, URL: ep.SLOURL}, {Binding: saml.BindingPOST, URL: ep.SLOURL}}})
}

// Cleanup removes expired requests and ended or expired session records.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	now := s.d.Now()
	t1, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM saml_idp_requests WHERE expires_at < $1`, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	t2, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM saml_idp_sessions WHERE expires_at < $1 OR ended_at < $1`, now.Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	return t1.RowsAffected() + t2.RowsAffected(), nil
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, saml.ErrUnsafeXML):
		return "unsafe_xml"
	case errors.Is(err, saml.ErrTooLarge):
		return "too_large"
	case errors.Is(err, saml.ErrDuplicateID):
		return "duplicate_id"
	case errors.Is(err, saml.ErrWeakAlgorithm):
		return "weak_algorithm"
	case errors.Is(err, saml.ErrNoSignature):
		return "unsigned"
	case errors.Is(err, saml.ErrAmbiguousSignature):
		return "ambiguous_signature"
	case errors.Is(err, saml.ErrSignature):
		return "invalid"
	}
	return "malformed"
}
