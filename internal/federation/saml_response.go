package federation

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/beevik/etree"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/saml"
	"github.com/proudbase/proudauth/internal/storage"
)

// SAMLResult is a consumed SAML response: the request it answered and
// either the validated identity or a failure code for the transaction.
type SAMLResult struct {
	Request  *Request
	Provider *Provider
	Upstream *Upstream
	// Failure is the transaction-visible code (upstream_invalid_response,
	// upstream_denied); the detailed reason is in the audit evidence only.
	Failure string
}

// ErrSAMLResponse is returned when a response cannot be tied to a pending
// request of the connection (unsolicited, unknown, replayed, expired or
// unparseable). There is no transaction to report it to, so it is a local
// error; the reason is recorded as audit evidence.
var ErrSAMLResponse = problem.ErrInvalidProof.WithDetail("the SAML response could not be accepted")

// maxSAMLAttributes bounds the attributes kept from one assertion.
const maxSAMLAttributes = 100

// Consume validates a response posted to a connection's assertion consumer
// service (HTTP-POST binding) and consumes the request it answers.
//
// Unsolicited responses (no InResponseTo) are always refused: the broker
// accepts only answers to its own requests (SAML-007). The request is found
// by InResponseTo and the RelayState secret together and consumed before the
// rest of the validation, exactly once; whatever the validation finds is
// then reported to that request's transaction, as for OIDC callbacks.
func (b *SAMLBroker) Consume(ctx context.Context, realmID, realmName, alias, samlResponse, relayState string) (*SAMLResult, error) {
	p, set, err := b.connection(ctx, nil, realmID, alias)
	if err != nil {
		return nil, err
	}
	if p.State != "active" {
		return nil, problem.ErrFeatureDisabled.WithDetail("this sign-in connection is disabled")
	}
	reject := func(reason string) (*SAMLResult, error) {
		b.recordRejection(ctx, realmID, p, reason, "")
		return nil, ErrSAMLResponse
	}
	raw, err := saml.DecodePOST(samlResponse, b.limits.MaxBytes)
	if err != nil {
		return reject("decode")
	}
	root, err := saml.Parse(raw, b.limits)
	if err != nil {
		return reject(parseReason(err))
	}
	if !saml.Is(root, saml.NSProtocol, "Response") {
		return reject("not_a_response")
	}
	inResponseTo := saml.Attr(root, "InResponseTo")
	if inResponseTo == "" {
		return reject("unsolicited")
	}
	if relayState == "" || len(relayState) > saml.MaxRelayState || !saml.ValidID(inResponseTo) {
		return reject("unknown_request")
	}
	req := &Request{ID: inResponseTo, ProviderID: p.ID}
	err = b.fed.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var tid, uid, sid *string
		var expires time.Time
		err := tx.QueryRow(ctx, `UPDATE saml_broker_requests SET consumed_at=$5 WHERE id=$1 AND realm_id=$2 AND provider_id=$3 AND relay_digest=$4
			AND consumed_at IS NULL RETURNING purpose, transaction_id, user_id, session_id, expires_at`, inResponseTo, realmID, p.ID,
			secret.Digest(relayState), b.fed.d.Now()).Scan(&req.Purpose, &tid, &uid, &sid, &expires)
		if err != nil {
			return err
		}
		if !b.fed.d.Now().Before(expires) {
			return errExpiredRequest
		}
		if tid != nil {
			req.TransactionID = *tid
		}
		if uid != nil {
			req.UserID = *uid
		}
		if sid != nil {
			req.SessionID = *sid
		}
		return nil
	})
	switch {
	case storage.IsNoRows(err):
		return reject("unknown_request")
	case errors.Is(err, errExpiredRequest):
		return reject("expired_request")
	case err != nil:
		return nil, err
	}
	res := &SAMLResult{Request: req, Provider: p}
	sp := b.ServiceProvider(realmName, p, set)
	up, assertionID, expires, failure, reason := b.validateResponse(root, p, set, sp, inResponseTo)
	if reason == "" {
		// Replay protection: an assertion is accepted once per connection,
		// recorded until it expires (SAML-003).
		tag, err := b.fed.d.DB.Pool.Exec(ctx, `INSERT INTO saml_assertion_ids (provider_id, assertion_id, realm_id, expires_at) VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`, p.ID, assertionID, realmID, expires)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			failure, reason = "upstream_invalid_response", "assertion_replay"
		}
	}
	if reason != "" {
		b.recordRejection(ctx, realmID, p, reason, req.TransactionID)
		res.Failure = failure
		return res, nil
	}
	res.Upstream = up
	return res, nil
}

var errExpiredRequest = errors.New("saml: request expired")

func parseReason(err error) string {
	switch {
	case errors.Is(err, saml.ErrUnsafeXML):
		return "unsafe_xml"
	case errors.Is(err, saml.ErrTooLarge):
		return "too_large"
	case errors.Is(err, saml.ErrDuplicateID):
		return "duplicate_id"
	}
	return "malformed"
}

func (b *SAMLBroker) recordRejection(ctx context.Context, realmID string, p *Provider, reason, transactionID string) {
	meta := map[string]any{"provider": p.Alias, "reason": reason}
	if transactionID != "" {
		meta["transaction_id"] = transactionID
	}
	_ = b.fed.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := b.fed.d.Audit.Record(ctx, tx, audit.Event{Type: "saml.response.rejected", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: p.ID},
			Outcome: audit.Failure, ReasonCode: reason, Category: "security", Metadata: meta})
		return err
	})
}

// validateResponse applies the assertion rules of SAML-003 to a parsed response.
// It returns the identity, the assertion ID and its expiry, or a failure
// code and a reason. Every value relied on is read from an element whose
// signature was verified; the unverified document is used only to find
// those elements and to refuse ambiguous shapes (SAML-004).
func (b *SAMLBroker) validateResponse(root *etree.Element, p *Provider, set *SAMLSettings, sp SAMLServiceProviderURL, requestID string) (*Upstream, string, time.Time, string, string) {
	invalid := func(reason string) (*Upstream, string, time.Time, string, string) {
		return nil, "", time.Time{}, "upstream_invalid_response", reason
	}
	now := b.fed.d.Now()
	skew := set.skew()
	if saml.Attr(root, "Version") != "2.0" {
		return invalid("version")
	}
	// An error status carries no assertion; it is reported, not trusted. A
	// missing status code is not a success.
	st, err := saml.Child(root, saml.NSProtocol, "Status")
	if err != nil || st == nil {
		return invalid("status_missing")
	}
	code, err := saml.Child(st, saml.NSProtocol, "StatusCode")
	if err != nil || code == nil {
		return invalid("status_missing")
	}
	if saml.Attr(code, "Value") != saml.StatusSuccess {
		return nil, "", time.Time{}, "upstream_denied", "status"
	}
	if len(saml.Descendants(root, saml.NSAssertion, "EncryptedAssertion")) > 0 {
		return invalid("encrypted_assertion_unsupported")
	}
	// Exactly one assertion, as a direct child of the response: an assertion
	// anywhere else (Extensions, inside another element) is a wrapping shape.
	direct := saml.Children(root, saml.NSAssertion, "Assertion")
	if len(direct) != 1 || len(saml.Descendants(root, saml.NSAssertion, "Assertion")) != 1 {
		return invalid("assertion_count")
	}
	certs := set.certificates()
	var resp, assertion *etree.Element
	if saml.Signed(root) {
		v, err := saml.Verify(root, certs, now)
		if err != nil {
			return invalid("response_signature:" + signatureReason(err))
		}
		resp = v
	}
	if saml.Signed(direct[0]) {
		v, err := saml.Verify(direct[0], certs, now)
		if err != nil {
			return invalid("assertion_signature:" + signatureReason(err))
		}
		assertion = v
	}
	switch {
	case assertion == nil && (resp == nil || set.RequireSignedAssertions):
		// Unsigned assertions are never accepted (§18.2).
		return invalid("unsigned")
	case assertion == nil:
		// The response signature covers the assertion: read it from there.
		as := saml.Children(resp, saml.NSAssertion, "Assertion")
		if len(as) != 1 {
			return invalid("assertion_count")
		}
		assertion = as[0]
	}
	// Response-level destination and correlation. From the verified response
	// when it is signed; otherwise the assertion's signed subject
	// confirmation below carries the same binding.
	r := root
	if resp != nil {
		r = resp
	}
	if saml.Attr(r, "Destination") != sp.ACSURL {
		return invalid("destination")
	}
	if saml.Attr(r, "InResponseTo") != requestID {
		return invalid("in_response_to")
	}
	if iss, err := saml.Child(r, saml.NSAssertion, "Issuer"); err != nil {
		return invalid("issuer")
	} else if iss != nil {
		if v, err := saml.Text(iss); err != nil || v != set.IdPEntityID {
			return invalid("issuer")
		}
	}
	if !inWindow(saml.Attr(r, "IssueInstant"), now, skew) {
		return invalid("issue_instant")
	}
	// Assertion (verified).
	a := assertion
	if saml.Attr(a, "Version") != "2.0" || !saml.ValidID(saml.Attr(a, "ID")) {
		return invalid("assertion_malformed")
	}
	if !inWindow(saml.Attr(a, "IssueInstant"), now, skew) {
		return invalid("issue_instant")
	}
	iss, err := saml.RequiredChild(a, saml.NSAssertion, "Issuer")
	if err != nil {
		return invalid("issuer")
	}
	if v, err := saml.Text(iss); err != nil || v != set.IdPEntityID {
		return invalid("issuer")
	}
	if f := saml.Attr(iss, "Format"); f != "" && f != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
		return invalid("issuer")
	}
	subject, err := saml.RequiredChild(a, saml.NSAssertion, "Subject")
	if err != nil {
		return invalid("subject")
	}
	nid, err := saml.RequiredChild(subject, saml.NSAssertion, "NameID")
	if err != nil {
		return invalid("subject")
	}
	nameID, err := saml.Text(nid)
	if err != nil || nameID == "" || len(nameID) > 1024 {
		return invalid("subject")
	}
	nameIDFormat := saml.Attr(nid, "Format")
	notOnOrAfter, ok := bearerConfirmed(subject, sp.ACSURL, requestID, now, skew)
	if !ok {
		return invalid("subject_confirmation")
	}
	expires := notOnOrAfter
	conds, err := saml.RequiredChild(a, saml.NSAssertion, "Conditions")
	if err != nil {
		return invalid("conditions")
	}
	if v := saml.Attr(conds, "NotBefore"); v != "" {
		t, err := saml.ParseTime(v)
		if err != nil || t.After(now.Add(skew)) {
			return invalid("not_yet_valid")
		}
	}
	if v := saml.Attr(conds, "NotOnOrAfter"); v != "" {
		t, err := saml.ParseTime(v)
		if err != nil || !now.Before(t.Add(skew)) {
			return invalid("expired")
		}
		if t.Before(expires) {
			expires = t
		}
	}
	restrictions := 0
	for _, c := range conds.ChildElements() {
		switch {
		case saml.Is(c, saml.NSAssertion, "AudienceRestriction"):
			restrictions++
			found := false
			for _, aud := range saml.Children(c, saml.NSAssertion, "Audience") {
				if v, err := saml.Text(aud); err == nil && v == sp.EntityID {
					found = true
				}
			}
			// Several restrictions must all be satisfied (core §2.5.1.4).
			if !found {
				return invalid("audience")
			}
		case saml.Is(c, saml.NSAssertion, "OneTimeUse"), saml.Is(c, saml.NSAssertion, "ProxyRestriction"):
			// One-time use is enforced for every assertion; assertions are
			// never passed on, so proxy restrictions hold trivially.
		default:
			// A condition that cannot be evaluated makes the assertion invalid.
			return invalid("unknown_condition")
		}
	}
	if restrictions == 0 {
		return invalid("audience")
	}
	statements := saml.Children(a, saml.NSAssertion, "AuthnStatement")
	if len(statements) == 0 {
		return invalid("authn_statement")
	}
	classRef := ""
	for _, st := range statements {
		if v := saml.Attr(st, "SessionNotOnOrAfter"); v != "" {
			t, err := saml.ParseTime(v)
			if err != nil || !now.Before(t) {
				return invalid("upstream_session_expired")
			}
		}
		if ac, _ := saml.Child(st, saml.NSAssertion, "AuthnContext"); ac != nil && classRef == "" {
			if cr, _ := saml.Child(ac, saml.NSAssertion, "AuthnContextClassRef"); cr != nil {
				classRef, _ = saml.Text(cr)
			}
		}
	}
	// Attribute elements that repeat a Name are one multi-valued attribute:
	// SAML Core does not require names to be unique, and identity providers
	// send one element per value (Keycloak's role list mapper does by
	// default, one "Role" element per role). The attributes that identify
	// the user, the connection's subject and email attributes, must appear
	// once: a repeated one is ambiguous and refuses the response.
	values := map[string][]string{}
	seen := map[string]bool{}
	for _, stmt := range saml.Children(a, saml.NSAssertion, "AttributeStatement") {
		for _, at := range saml.Children(stmt, saml.NSAssertion, "Attribute") {
			name := saml.Attr(at, "Name")
			if name == "" || len(name) > 256 {
				continue
			}
			if seen[name] {
				if name == set.SubjectAttribute || name == set.EmailAttribute {
					return invalid("duplicate_attribute")
				}
			} else {
				if len(seen) >= maxSAMLAttributes {
					continue
				}
				seen[name] = true
			}
			for _, av := range saml.Children(at, saml.NSAssertion, "AttributeValue") {
				v, err := saml.Text(av)
				if err != nil || len(v) > 1024 {
					return invalid("attribute_value")
				}
				values[name] = append(values[name], v)
			}
		}
	}
	attrs := map[string]any{}
	for name, vs := range values {
		if len(vs) == 1 {
			attrs[name] = vs[0]
		} else {
			attrs[name] = vs
		}
	}
	single := func(name string) (string, bool) {
		v, ok := attrs[name].(string)
		return v, ok
	}
	up := &Upstream{Issuer: set.IdPEntityID, Claims: attrs}
	switch {
	case set.SubjectAttribute != "":
		v, ok := single(set.SubjectAttribute)
		if !ok || v == "" {
			return invalid("subject_attribute")
		}
		up.Subject = v
	case nameIDFormat == saml.NameIDTransient:
		// A transient identifier changes every time: binding an account to it
		// would create a new account (or link) on every sign-in.
		return invalid("transient_subject")
	default:
		up.Subject = nameID
	}
	if len(up.Subject) > 255 {
		return invalid("subject")
	}
	switch {
	case set.EmailAttribute != "":
		up.Email, _ = single(set.EmailAttribute)
	case nameIDFormat == saml.NameIDEmail:
		up.Email = nameID
	}
	// SAML carries no verification flag: an asserted email counts as verified
	// only when the connection explicitly trusts this provider for it
	// (FED-004).
	up.EmailVerified = up.Email != "" && set.TrustEmailVerified
	if p.TrustUpstreamMFA && classRef != "" && slices.Contains(set.TrustedAuthnContexts, classRef) {
		up.MFA = true // FED-009: only configured semantics
	}
	return up, saml.Attr(a, "ID"), expires.Add(skew), "", ""
}

// bearerConfirmed checks for a bearer subject confirmation bound to this
// consumer and request, and returns its expiry (profiles §4.1.4.2).
func bearerConfirmed(subject *etree.Element, recipient, requestID string, now time.Time, skew time.Duration) (time.Time, bool) {
	for _, sc := range saml.Children(subject, saml.NSAssertion, "SubjectConfirmation") {
		if saml.Attr(sc, "Method") != saml.ConfirmationMethodBearer {
			continue
		}
		d, err := saml.Child(sc, saml.NSAssertion, "SubjectConfirmationData")
		if err != nil || d == nil {
			continue
		}
		if saml.Attr(d, "Recipient") != recipient || saml.Attr(d, "InResponseTo") != requestID {
			continue
		}
		t, err := saml.ParseTime(saml.Attr(d, "NotOnOrAfter"))
		if err != nil || !now.Before(t.Add(skew)) {
			continue
		}
		if v := saml.Attr(d, "NotBefore"); v != "" {
			nb, err := saml.ParseTime(v)
			if err != nil || nb.After(now.Add(skew)) {
				continue
			}
		}
		return t, true
	}
	return time.Time{}, false
}

// inWindow accepts an IssueInstant no later than now plus skew and no older
// than the request lifetime plus skew.
func inWindow(v string, now time.Time, skew time.Duration) bool {
	t, err := saml.ParseTime(v)
	if err != nil {
		return false
	}
	return !t.After(now.Add(skew)) && !t.Before(now.Add(-RequestTTL-skew))
}

func signatureReason(err error) string {
	switch {
	case errors.Is(err, saml.ErrWeakAlgorithm):
		return "weak_algorithm"
	case errors.Is(err, saml.ErrAmbiguousSignature):
		return "ambiguous"
	case errors.Is(err, saml.ErrMalformed):
		return "malformed"
	}
	return "invalid"
}
