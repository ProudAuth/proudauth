package authentication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/hooks"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// PurposeFlowChallenge is an emailed code that answers an authentication flow
// challenge (SEC-014's accessible alternative to a provider challenge).
const PurposeFlowChallenge = "flow_challenge"

// FlowDecision is the authentication flow outcome for one account and
// organization context in a transaction (AUT-012, AUT-014). It is computed
// once, when the account is known, so risk hooks are called once per
// sign-in, and it records why: the matching rule, the signals used and the
// signals that were missing.
type FlowDecision struct {
	UserID          string         `json:"user_id"`
	OrgID           string         `json:"org_id,omitempty"`
	Outcome         string         `json:"outcome"`
	Rule            string         `json:"rule,omitempty"`
	PolicyRevision  int64          `json:"policy_revision"`
	Signals         map[string]any `json:"signals,omitempty"`
	Missing         []string       `json:"missing,omitempty"`
	ChallengePassed bool           `json:"challenge_passed,omitempty"`
	ChallengeCode   string         `json:"challenge_code,omitempty"`
}

// flowSignals gathers each signal at most once, and only when a rule asks.
type flowSignals struct {
	s          *Service
	ctx        context.Context
	q          storage.Querier
	t          *Transaction
	client     *application.Client
	user       *identity.User
	privileged bool
	orgID      string

	device    *bool
	failures  *int
	risk      *hooks.RiskVerdict
	riskDone  bool
	riskError bool
	audiences []string
	used      map[string]any
}

func (f *flowSignals) knownDevice() bool {
	if f.device == nil {
		known := f.s.rememberedDevice(f.ctx, f.q, f.t.RealmID, f.user.ID, f.t.deviceToken) != ""
		f.device = &known
		f.used["known_device"] = known
	}
	return *f.device
}

func (f *flowSignals) failedAttempts() int {
	if f.failures == nil {
		n := 0
		_ = f.q.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND subject_id=$2 AND outcome='failure'
			AND type LIKE 'authentication.%' AND occurred_at > $3`, f.t.RealmID, f.user.ID, f.s.d.Now().Add(-time.Hour)).Scan(&n)
		f.failures = &n
		f.used["failed_attempts"] = n
	}
	return *f.failures
}

func (f *flowSignals) method() string {
	for _, fa := range f.t.Factors {
		if m := loginMethodOf(fa.Type); m != "" {
			return m
		}
	}
	return ""
}

func (f *flowSignals) riskLevel() (string, bool) {
	if !f.riskDone {
		f.riskDone = true
		if f.s.Hooks != nil {
			v, err := f.s.Hooks.Risk(f.ctx, f.t.RealmID, hooks.RiskInput{UserID: f.user.ID, ClientID: f.client.ClientID, OrganizationID: f.orgID,
				Method: f.method(), Network: reqctx.NetworkContext(f.t.ClientIP, false), KnownDevice: f.knownDevice(), FailedAttempts: f.failedAttempts()})
			f.risk, f.riskError = v, err != nil
		}
		switch {
		case f.risk != nil:
			f.used["risk"] = f.risk.Level
			if f.risk.Partial {
				f.used["risk"] = "at_least_" + f.risk.Level
			}
			if len(f.risk.Reasons) > 0 {
				f.used["risk_reasons"] = f.risk.Reasons
			}
		case f.riskError:
			f.used["risk"] = "unavailable"
		}
	}
	if f.risk == nil {
		return "", false
	}
	return f.risk.Level, true
}

// riskAtLeast reports whether the risk is known to reach want; known is false
// when the signal is missing or only a lower bound below want.
func (f *flowSignals) riskAtLeast(want string) (match, known bool) {
	level, ok := f.riskLevel()
	if !ok {
		return false, false
	}
	if riskRank[level] >= riskRank[want] {
		return true, true
	}
	return false, !f.risk.Partial
}

func (f *flowSignals) resourceAudiences() []string {
	if f.audiences == nil {
		f.audiences = []string{}
		for _, rid := range f.t.ResourceIDs {
			if res, err := f.s.Apps.Resource(f.ctx, f.q, f.t.RealmID, rid); err == nil {
				f.audiences = append(f.audiences, res.Audience)
			}
		}
	}
	return f.audiences
}

var riskRank = map[string]int{"low": 1, "medium": 2, "high": 3}

// flowSignals implements realm.FlowFacts for a live sign-in.
func (f *flowSignals) ClientID() string                      { return f.client.ClientID }
func (f *flowSignals) OrganizationID() string                { return f.orgID }
func (f *flowSignals) Method() string                        { return f.method() }
func (f *flowSignals) ResourceAudiences() []string           { return f.resourceAudiences() }
func (f *flowSignals) KnownDevice() bool                     { return f.knownDevice() }
func (f *flowSignals) FailedAttempts() int                   { return f.failedAttempts() }
func (f *flowSignals) Privileged() bool                      { return f.privileged }
func (f *flowSignals) RiskAtLeast(level string) (bool, bool) { return f.riskAtLeast(level) }

func (f *flowSignals) ClientAddr() (netip.Addr, bool) {
	ip, err := netip.ParseAddr(f.t.ClientIP)
	return ip, err == nil
}

func (f *flowSignals) AssuranceBelow(acr string) bool {
	return session.ACRRank(session.ACRFor(f.t.Factors)) < session.ACRRank(acr)
}

// decideFlow evaluates the realm's authentication flow for the account (AUT-012).
// The first matching rule decides. A rule with missing signals applies when
// its outcome is restrictive (unless it says skip) and never when it would
// allow, so a missing signal never satisfies a stricter policy (AUT-014).
func (s *Service) decideFlow(ctx context.Context, q storage.Querier, t *Transaction, rlm *realm.Realm, client *application.Client,
	u *identity.User, privileged bool, orgID string) *FlowDecision {
	d := &FlowDecision{UserID: u.ID, OrgID: orgID, Outcome: realm.FlowAllow, PolicyRevision: rlm.PolicyRevision}
	f := &flowSignals{s: s, ctx: ctx, q: q, t: t, client: client, user: u, privileged: privileged || u.Protected, orgID: orgID, used: map[string]any{}}
	res := realm.EvaluateFlow(rlm.Policy.AuthFlow, f)
	d.Outcome, d.Rule, d.Missing = res.Outcome, res.Rule, res.Missing
	d.Signals = f.used
	meta := map[string]any{"outcome": d.Outcome, "rule": d.Rule, "policy_revision": d.PolicyRevision, "signals": d.Signals,
		"missing_signals": d.Missing, "transaction_id": t.ID}
	outcome := audit.Success
	if d.Outcome == realm.FlowDeny {
		outcome = audit.Denied
	}
	_, _ = s.d.Audit.Record(ctx, q, audit.Event{Type: "authentication.flow.evaluated", RealmID: t.RealmID, OrgID: orgID, Actor: actorFor(t),
		Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: outcome, ClientID: client.ClientID, Category: "security", Metadata: meta})
	return d
}

// applyFlow folds the flow decision into the transaction requirements. It
// returns true when evaluation should stop (the login is blocked).
func (s *Service) applyFlow(t *Transaction, r *requirements) bool {
	d := t.Pending.Flow
	if d == nil {
		return false
	}
	switch d.Outcome {
	case realm.FlowDeny:
		r.blocked = "authentication_policy_denied"
		return true
	case realm.FlowRequireMFA:
		// A factor is needed in this transaction: a remembered device does not
		// stand in for one when the flow asks for it. A stronger requirement
		// already in force (phishing-resistant) is never weakened.
		_, mfa := session.AMRFromFactors(t.Factors)
		done := mfa != nil
		if r.phishingResistant {
			done = session.ACRFor(t.Factors) == session.ACRPhishingResistant
		}
		r.mfaRequired, r.mfaDone, r.deviceRemembered = true, done, ""
	case realm.FlowRequirePhishingResistant:
		if !r.passkeysEnabled {
			r.blocked = "authentication_policy_denied"
			return true
		}
		r.mfaRequired, r.phishingResistant, r.deviceRemembered = true, true, ""
		r.mfaDone = session.ACRFor(t.Factors) == session.ACRPhishingResistant
	case realm.FlowChallenge:
		r.flowChallenge = !d.ChallengePassed
		if r.flowChallenge && r.deviceRemembered != "" {
			// Only a factor used in this transaction answers a challenge.
			_, mfa := session.AMRFromFactors(t.Factors)
			r.mfaDone, r.deviceRemembered = mfa != nil, ""
		}
	}
	return false
}

// challengeOptions fills the ways a flow challenge can be answered: an
// enrolled factor, the realm's challenge provider, or an emailed code.
func (s *Service) challengeOptions(rlm *realm.Realm, r *requirements) {
	if name := rlm.Policy.AuthFlow.ChallengeProvider; name != "" {
		if p, ok := s.d.Cfg.ChallengeProvider(name); ok {
			r.challengeProvider = p
		}
	}
	if r.user != nil && rlm.Policy.AuthFlow.EmailAlternative() {
		// The code goes to the verified primary email (SendChallengeCode).
		e := r.user.PrimaryEmail()
		r.challengeEmail = e != nil && e.Verified()
	}
}

// ChallengeInput answers a flow challenge: a provider response token or an
// emailed code.
type ChallengeInput struct {
	ProviderResponse string `json:"provider_response"`
	Code             string `json:"code"`
}

// SendChallengeCode emails a challenge code to the account's verified primary
// email, the accessible alternative to a provider challenge (SEC-014).
func (s *Service) SendChallengeCode(ctx context.Context, realmID, id string, p Proof) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, u, err := s.challengeContext(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		e := u.PrimaryEmail()
		if !rlm.Policy.AuthFlow.EmailAlternative() || e == nil || !e.Verified() {
			return nil, problem.ErrUnexpectedStep
		}
		if err := s.sendBudget(ctx, t.RealmID, e.Canonical, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
			return nil, err
		}
		cid, code, err := s.IssueChallengeTx(ctx, tx, ChallengeSpec{RealmID: t.RealmID, Purpose: PurposeFlowChallenge, TransactionID: t.ID,
			UserID: u.ID, IdentifierType: "email", Identifier: e.Canonical})
		if err != nil {
			return nil, err
		}
		t.Pending.Flow.ChallengeCode = cid
		_, err = s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: t.RealmID, UserID: u.ID, Template: notification.TplLoginCode, Locale: t.UILocales,
			Recipient: e.Value, Mandatory: true, ReferenceType: "challenge", ReferenceID: cid, TTL: s.d.Cfg.Tokens.ChallengeTTL,
			Data: map[string]string{"code": code, "realm": rlm.DisplayName, "expires_minutes": minutes(s.d.Cfg.Tokens.ChallengeTTL)}})
		return nil, err
	})
}

// AnswerChallenge verifies a provider response or an emailed code for a
// pending flow challenge.
func (s *Service) AnswerChallenge(ctx context.Context, realmID, id string, p Proof, in ChallengeInput) (*State, error) {
	if (in.ProviderResponse == "") == (in.Code == "") {
		return nil, problem.ErrValidation.WithDetail("give exactly one of provider_response or code")
	}
	var passed *bool
	if in.ProviderResponse != "" {
		// The provider is called once, outside the step transaction: no
		// connection or row lock is held across the network call, and a
		// retried transaction never verifies a single-use response twice
		// (DB-014). The proof and the pending challenge are checked first.
		var prov *configuration.ChallengeProviderConfig
		var clientIP, unavailable string
		if err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			t, err := s.lockTx(ctx, tx, realmID, id, p)
			if err != nil {
				return err
			}
			rlm, u, err := s.challengeContext(ctx, tx, t)
			if err != nil {
				return err
			}
			pr, ok := s.d.Cfg.ChallengeProvider(rlm.Policy.AuthFlow.ChallengeProvider)
			if !ok {
				return problem.ErrUnexpectedStep
			}
			prov, clientIP = pr, t.ClientIP
			// The provider being down is not the user's failure; the
			// emailed code may remain available.
			unavailable = "the challenge provider is unavailable; try again later"
			if e := u.PrimaryEmail(); rlm.Policy.AuthFlow.EmailAlternative() && e != nil && e.Verified() {
				unavailable = "the challenge provider is unavailable; use the emailed code instead"
			}
			return nil
		}); err != nil {
			return nil, err
		}
		ok, err := s.verifyProvider(ctx, prov, in.ProviderResponse, clientIP)
		if err != nil {
			return nil, problem.ErrUnavailable.WithDetail(unavailable)
		}
		passed = &ok
	}
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, u, err := s.challengeContext(ctx, tx, t)
		if err != nil {
			return nil, err
		}
		method := "email_code"
		if passed != nil {
			method = "provider"
			if _, ok := s.d.Cfg.ChallengeProvider(rlm.Policy.AuthFlow.ChallengeProvider); !ok {
				return nil, problem.ErrUnexpectedStep
			}
			if !*passed {
				_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.challenge.failed", RealmID: t.RealmID, Actor: actorFor(t),
					Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: audit.Failure, Category: "security", Metadata: map[string]any{"method": method}})
				return nil, errProof(problem.ErrInvalidProof)
			}
		} else {
			if t.Pending.Flow.ChallengeCode == "" {
				return nil, problem.ErrUnexpectedStep
			}
			if err := s.verifyBudget(ctx, t.RealmID, u.ID, t.ClientIP, t.ClientRef, t.RequestedOrgID); err != nil {
				return nil, err
			}
			if _, err := s.ConsumeChallengeTx(ctx, tx, t.RealmID, t.Pending.Flow.ChallengeCode, PurposeFlowChallenge, strings.TrimSpace(in.Code)); err != nil {
				_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.challenge.failed", RealmID: t.RealmID, Actor: actorFor(t),
					Subject: &audit.Ref{Type: "user", ID: u.ID}, Outcome: audit.Failure, Category: "security", Metadata: map[string]any{"method": method}})
				return nil, err
			}
		}
		t.Pending.Flow.ChallengePassed = true
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.challenge.passed", RealmID: t.RealmID, Actor: actorFor(t),
			Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "security", Metadata: map[string]any{"method": method, "rule": t.Pending.Flow.Rule}})
		return nil, err
	})
}

func (s *Service) challengeContext(ctx context.Context, tx pgx.Tx, t *Transaction) (*realm.Realm, *identity.User, error) {
	if t.UserID == "" || t.Pending.Flow == nil || t.Pending.Flow.Outcome != realm.FlowChallenge || t.Pending.Flow.ChallengePassed {
		return nil, nil, problem.ErrUnexpectedStep
	}
	rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
	if err != nil {
		return nil, nil, err
	}
	u, err := s.Users.User(ctx, tx, t.RealmID, t.UserID)
	if err != nil {
		return nil, nil, err
	}
	return rlm, u, nil
}

// ChallengeHTTPClient, when set, replaces the egress-controlled client used
// to call challenge providers (tests).
var ChallengeHTTPClient *http.Client

// verifyProvider calls a siteverify-style endpoint: a form with secret and
// response (and remoteip only when configured) answered by JSON
// {"success": bool}.
func (s *Service) verifyProvider(ctx context.Context, p *configuration.ChallengeProviderConfig, response, clientIP string) (bool, error) {
	if len(response) > 4096 {
		return false, nil
	}
	secretValue, err := configuration.ResolveSecret(p.Secret)
	if err != nil {
		return false, err
	}
	form := url.Values{"secret": {secretValue}, "response": {response}}
	if p.SendRemoteIP && clientIP != "" {
		form.Set("remoteip", clientIP)
	}
	timeout := p.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.VerifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pol := egress.Policy{AllowPrivate: s.d.Cfg.Delivery.AllowPrivateWebhooks, AllowCIDRs: s.d.Cfg.Delivery.EgressAllowlist, Timeout: timeout, MaxBytes: 64 << 10,
		RequireHTTPS: s.d.Cfg.Mode == configuration.ModeProduction}
	client := ChallengeHTTPClient
	if client == nil {
		if err := pol.ValidateURL(p.VerifyURL); err != nil {
			return false, err
		}
		client = pol.Client()
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("challenge provider returned %d", resp.StatusCode)
	}
	body, err := pol.ReadLimited(resp.Body)
	if err != nil {
		return false, err
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return false, err
	}
	return out.Success, nil
}
