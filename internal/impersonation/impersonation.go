// Package impersonation implements controlled, attributable, time-limited support
// access to a customer's application experience (§16).
//
// Flow (§16.3): an administrator with a live MFA session requests access with a
// reason; policy validates actor, target, organization, resource and support
// scopes; optional independent approval; the grant, audit record and outbox entry
// commit together before any authority is returned (IMP-020); the support token is
// opaque, short-lived, refresh-less and validated online on every request.
package impersonation

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/oauth"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/session"
	"github.com/proudbase/proudauth/internal/token"
)

// Service manages support access.
type Service struct {
	d        *runtime.Deps
	Realms   *realm.Service
	Apps     *application.Service
	Authz    *authorization.Service
	Orgs     *organization.Service
	Sessions *session.Service
	OAuth    *oauth.Service
	Notify   *notification.Service
	// FailAudit is a test hook that simulates audit persistence failure (TEST-047).
	FailAudit func() error
}

// NewService returns the service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

// Actor is the authenticated administrator requesting access.
type Actor struct {
	UserID    string
	SessionID string
	TokenKind string
}

// RequestInput is an impersonation request.
type RequestInput struct {
	TargetUserID    string   `json:"target_user_id"`
	OrganizationID  string   `json:"organization_id"`
	ClientID        string   `json:"client_id"`
	Audience        string   `json:"audience"`
	Scopes          []string `json:"scopes"`
	Reason          string   `json:"reason"`
	TicketReference string   `json:"ticket_reference"`
	Mode            string   `json:"mode"`
	TTLSeconds      int      `json:"ttl_seconds"`
}

// Request is a stored request.
type Request struct {
	ID               string    `json:"id"`
	ActorUserID      string    `json:"actor_user_id"`
	TargetUserID     string    `json:"target_user_id"`
	OrganizationID   string    `json:"organization_id"`
	ResourceID       string    `json:"resource_id"`
	Scopes           []string  `json:"scopes"`
	Mode             string    `json:"mode"`
	ApprovalRequired string    `json:"approval_required"`
	State            string    `json:"state"`
	ApprovedBy       string    `json:"approved_by,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	CreatedAt        time.Time `json:"created_at"`
	TicketReference  string    `json:"ticket_reference,omitempty"`
}

// Grant is an issued support grant (no secrets).
type Grant struct {
	ID             string     `json:"id"`
	RequestID      string     `json:"request_id"`
	ActorUserID    string     `json:"actor_user_id"`
	TargetUserID   string     `json:"target_user_id"`
	OrganizationID string     `json:"organization_id"`
	ResourceID     string     `json:"resource_id"`
	ScopeCeiling   []string   `json:"scope_ceiling"`
	Mode           string     `json:"mode"`
	State          string     `json:"state"`
	ExpiresAt      time.Time  `json:"expires_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	RevokeReason   string     `json:"revoke_reason,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	// Reason and TicketReference come from the approved request (IMP-023).
	Reason          string `json:"reason,omitempty"`
	TicketReference string `json:"ticket_reference,omitempty"`
}

// Issued is returned once to the trusted support backend.
type Issued struct {
	Grant       Grant  `json:"grant"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// enabled checks the operator switch, the realm switch and that at least one
// resource implements the support contract (IMP-001).
func (s *Service) enabled(ctx context.Context, rlm *realm.Realm) error {
	if !s.d.Cfg.Impersonation.Enabled || !rlm.Policy.Impersonation.Enabled {
		return problem.ErrFeatureDisabled.WithDetail("support impersonation is disabled")
	}
	n, err := s.Apps.ImpersonationResources(ctx, rlm.ID)
	if err != nil {
		return err
	}
	if n == 0 {
		return problem.ErrFeatureDisabled.WithDetail("no resource has opted into the support-access contract")
	}
	return nil
}

func (s *Service) maxTTL(rlm *realm.Realm) time.Duration {
	ttl := s.d.Cfg.Impersonation.MaxTTL
	// Support tokens live as long as their grant, so the realm's token
	// lifetime limits bound the grant too (TOK-018).
	for _, p := range []int{rlm.Policy.Impersonation.MaxTTLSeconds, rlm.Policy.Tokens.ImpersonationAccessTokenTTLSeconds, rlm.Policy.Tokens.AccessTokenTTLSeconds} {
		if p > 0 && time.Duration(p)*time.Second < ttl {
			ttl = time.Duration(p) * time.Second
		}
	}
	return ttl
}

// checkActor enforces the dedicated permission scoped to the target organization
// and recent MFA on a live session (IMP-002, IMP-003, MFA-003).
func (s *Service) checkActor(ctx context.Context, q pgx.Tx, rlm *realm.Realm, a Actor, orgID, perm string) error {
	if a.TokenKind != token.KindUserAccess || a.SessionID == "" {
		return problem.ErrImpersonationDenied.WithDetail("support access requires an interactive administrator session")
	}
	sess, err := s.Sessions.Active(ctx, q, rlm.ID, a.SessionID)
	if err != nil || sess.UserID != a.UserID {
		return problem.ErrImpersonationDenied.WithDetail("administrator session is not active")
	}
	if sess.RecoveryRestricted || sess.MFATime == nil || s.d.Now().Sub(*sess.MFATime) > s.d.Cfg.Security.AdminMFAMaxAge {
		return problem.ErrStepUpRequired.WithExtension("obligations", []map[string]any{{"type": "reauthenticate", "required_profile": "mfa",
			"max_age_seconds": int(s.d.Cfg.Security.AdminMFAMaxAge.Seconds())}})
	}
	var state string
	if err := q.QueryRow(ctx, `SELECT state FROM users WHERE realm_id=$1 AND id=$2`, rlm.ID, a.UserID).Scan(&state); err != nil || state != "active" {
		return problem.ErrImpersonationDenied
	}
	if !s.Authz.Check(ctx, q, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: a.UserID}, perm,
		authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
		return problem.ErrImpersonationDenied.WithDetail("missing " + perm + " for this organization")
	}
	return nil
}

// RequestAccess validates and records a support-access request (IMP-004, IMP-005,
// IMP-015). When no approval is required it is immediately approved.
func (s *Service) RequestAccess(ctx context.Context, rlm *realm.Realm, a Actor, in RequestInput) (*Request, error) {
	if err := s.enabled(ctx, rlm); err != nil {
		return nil, err
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) < s.d.Cfg.Impersonation.MinReasonLength || len(reason) > 1000 {
		return nil, problem.ErrValidation.WithField("reason", "a meaningful support reason is required (IMP-005)")
	}
	if (s.d.Cfg.Impersonation.RequireTicket || rlm.Policy.Impersonation.RequireTicket) && strings.TrimSpace(in.TicketReference) == "" {
		return nil, problem.ErrValidation.WithField("ticket_reference", "a ticket reference is required by policy")
	}
	if in.Mode == "" {
		in.Mode = "read_only"
	}
	if in.Mode != "read_only" && in.Mode != "allowlisted_write" {
		return nil, problem.ErrValidation.WithField("mode", "read_only or allowlisted_write")
	}
	ttl := s.maxTTL(rlm)
	if in.TTLSeconds > 0 && time.Duration(in.TTLSeconds)*time.Second < ttl {
		ttl = time.Duration(in.TTLSeconds) * time.Second
	}
	var out *Request
	var denial *audit.Event
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		denial = nil
		// The denial is recorded after the transaction rolls back, so the
		// evidence survives the failed request (IMP-006).
		deny := func(reasonCode string, e error) error {
			denial = &audit.Event{Type: "support.impersonation.denied", RealmID: rlm.ID, OrgID: in.OrganizationID,
				Actor: audit.Ref{Type: "user", ID: a.UserID, SessionID: a.SessionID}, Subject: &audit.Ref{Type: "user", ID: in.TargetUserID},
				Outcome: audit.Denied, ReasonCode: reasonCode, Category: "support"}
			return e
		}
		if a.UserID == in.TargetUserID {
			return problem.ErrImpersonationDenied.WithDetail("operators cannot impersonate themselves")
		}
		client, err := s.Apps.ClientByClientID(ctx, tx, rlm.ID, in.ClientID)
		if err != nil || !client.Active() || client.Public() {
			return deny("CLIENT_NOT_ELIGIBLE", problem.ErrImpersonationDenied.WithDetail("support access is issued only to a confidential support client"))
		}
		res, err := s.Apps.ResourceByAudience(ctx, tx, rlm.ID, in.Audience)
		if err != nil || !res.ImpersonationEnabled || res.VerificationMode != application.ModeStrictOnline || res.State != "active" {
			return deny("RESOURCE_NOT_OPTED_IN", problem.ErrImpersonationDenied.WithDetail("the resource does not implement the support contract"))
		}
		if len(res.ImpersonationPolicy.SupportClientIDs) > 0 && !slices.Contains(res.ImpersonationPolicy.SupportClientIDs, client.ClientID) {
			return deny("CLIENT_NOT_ELIGIBLE", problem.ErrImpersonationDenied)
		}
		scopes := in.Scopes
		if len(scopes) == 0 {
			scopes = res.ImpersonationPolicy.AllowedScopes
		}
		if len(scopes) == 0 {
			return deny("NO_SUPPORT_SCOPES", problem.ErrImpersonationDenied.WithDetail("the resource allows no support scopes"))
		}
		for _, sc := range scopes {
			if !slices.Contains(res.ImpersonationPolicy.AllowedScopes, sc) && !(in.Mode == "allowlisted_write" && slices.Contains(res.ImpersonationPolicy.WriteScopes, sc)) {
				return deny("SCOPE_NOT_ALLOWED", problem.ErrImpersonationDenied.WithDetail("scope "+sc+" is not allowed for support access"))
			}
			if in.Mode == "read_only" && slices.Contains(res.ImpersonationPolicy.WriteScopes, sc) {
				return deny("SCOPE_NOT_ALLOWED", problem.ErrImpersonationDenied.WithDetail("read-only support access excludes write scopes (IMP-011)"))
			}
		}
		// The operator's support capabilities are evaluated for exactly this
		// use: organization, target category, resource, mode and scopes
		// (IMP-002, IMP-007).
		sctx := s.supportContext(ctx, tx, in.TargetUserID, in.OrganizationID, in.Mode, scopes, res)
		if err := s.checkActor(sctx, tx, rlm, a, in.OrganizationID, "support.impersonation.start"); err != nil {
			_ = deny("ACTOR_NOT_ELIGIBLE", err)
			return err
		}
		org, err := s.Orgs.LockActiveTx(ctx, tx, rlm.ID, in.OrganizationID)
		if err != nil {
			return deny("ORGANIZATION_NOT_ELIGIBLE", problem.ErrImpersonationDenied)
		}
		if org.Policy.SupportAccessOptOut {
			return deny("CUSTOMER_OPTED_OUT", problem.ErrImpersonationDenied.WithDetail("the organization opted out of support access"))
		}
		// Target restrictions (IMP-015, TEST-041).
		var targetState string
		var protected bool
		if err := tx.QueryRow(ctx, `SELECT state, protected FROM users WHERE realm_id=$1 AND id=$2`, rlm.ID, in.TargetUserID).Scan(&targetState, &protected); err != nil {
			return deny("TARGET_NOT_ELIGIBLE", problem.ErrImpersonationDenied)
		}
		if targetState != "active" || protected {
			return deny("TARGET_PROTECTED", problem.ErrImpersonationDenied)
		}
		if privileged, _ := s.Authz.HoldsPrivilegedRealmRole(ctx, tx, rlm.ID, in.TargetUserID); privileged {
			return deny("TARGET_PROTECTED", problem.ErrImpersonationDenied)
		}
		var optOut bool
		_ = tx.QueryRow(ctx, `SELECT coalesce((internal_metadata->>'support_access_opt_out')::boolean, false) FROM users WHERE id=$1`, in.TargetUserID).Scan(&optOut)
		if optOut && rlm.Policy.Impersonation.AllowCustomerOptOut {
			return deny("CUSTOMER_OPTED_OUT", problem.ErrImpersonationDenied.WithDetail("the customer opted out of support access"))
		}
		m, err := s.Orgs.ActiveMembership(ctx, tx, rlm.ID, in.OrganizationID, in.TargetUserID)
		if err != nil {
			return deny("TARGET_NOT_MEMBER", problem.ErrImpersonationDenied)
		}
		// Escalation guard: targets that administer the organization are excluded.
		teff, err := s.Authz.Effective(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: in.TargetUserID},
			authorization.Scope{Type: authorization.ScopeOrganization, ID: in.OrganizationID})
		if err != nil {
			return err
		}
		if teff.Has("org.roles.assign") || teff.Has("org.ownership.transfer") || teff.Has("org.members.write") {
			return deny("TARGET_IS_ADMINISTRATOR", problem.ErrImpersonationDenied.WithDetail("organization administrators cannot be impersonated"))
		}
		_ = m
		approval := rlm.Policy.Impersonation.Approval
		if org.Policy.ImpersonationApproval != "" && org.Policy.ImpersonationApproval != "none" {
			approval = org.Policy.ImpersonationApproval
		}
		if in.Mode == "allowlisted_write" && approval == "none" {
			approval = "second_operator" // writes always need an independent approver
		}
		now := s.d.Now()
		r := &Request{ID: ids.New(ids.ImpRequest), ActorUserID: a.UserID, TargetUserID: in.TargetUserID, OrganizationID: in.OrganizationID,
			ResourceID: res.ID, Scopes: scopes, Mode: in.Mode, ApprovalRequired: approval, State: "pending", ExpiresAt: now.Add(15 * time.Minute),
			CreatedAt: now, TicketReference: in.TicketReference}
		if approval == "none" {
			r.State = "approved"
		}
		if approval == "customer" && s.Notify != nil {
			// The customer learns about the request immediately and decides in
			// self-service (IMP-022).
			var email string
			_ = tx.QueryRow(ctx, `SELECT original_value FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL
				ORDER BY is_primary DESC LIMIT 1`, in.TargetUserID).Scan(&email)
			if email != "" {
				if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: rlm.ID, OrgID: in.OrganizationID, Template: notification.TplSupportApproval,
					Recipient: email, Mandatory: true, ReferenceType: "impersonation_request", ReferenceID: r.ID, UserID: in.TargetUserID,
					Data: map[string]string{"realm": rlm.DisplayName, "organization": org.DisplayName, "time": notification.Timestamp(now),
						"expires": notification.Timestamp(r.ExpiresAt), "state": strings.ReplaceAll(in.Mode, "_", " "), "reason": reason}}); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO impersonation_requests (id, realm_id, actor_user_id, actor_session_id, target_user_id, organization_id,
			client_ref, resource_id, scopes, mode, reason, ticket_reference, requested_ttl_seconds, approval_required, state, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, r.ID, rlm.ID, a.UserID, a.SessionID, in.TargetUserID, in.OrganizationID,
			client.Ref, res.ID, scopes, in.Mode, reason, nilIfEmpty(in.TicketReference), int(ttl.Seconds()), approval, r.State, r.ExpiresAt, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.requested", RealmID: rlm.ID, OrgID: in.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: a.UserID, SessionID: a.SessionID}, Subject: &audit.Ref{Type: "user", ID: in.TargetUserID},
			Target: &audit.Ref{Type: "impersonation_request", ID: r.ID}, Category: "support",
			Metadata: map[string]any{"ticket_reference": in.TicketReference, "audience": res.Audience, "scopes": scopes, "mode": in.Mode, "approval": approval}}); err != nil {
			return err
		}
		out = r
		return nil
	})
	if err != nil && denial != nil {
		_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, *denial)
	}
	return out, err
}

// Approve records an independent approval (IMP-022). The requester can never
// approve their own request.
func (s *Service) Approve(ctx context.Context, rlm *realm.Realm, approver Actor, requestID string) error {
	if err := s.enabled(ctx, rlm); err != nil {
		return err
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var actorID, orgID, targetID, approval, state string
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT actor_user_id, organization_id, target_user_id, approval_required, state, expires_at FROM impersonation_requests
			WHERE realm_id=$1 AND id=$2 FOR UPDATE`, rlm.ID, requestID).Scan(&actorID, &orgID, &targetID, &approval, &state, &expires); err != nil {
			return problem.ErrNotFound
		}
		if state != "pending" || !s.d.Now().Before(expires) {
			return problem.ErrConflict.WithDetail("request is not pending")
		}
		if approver.UserID == actorID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		switch approval {
		case "second_operator":
			if err := s.checkActor(ctx, tx, rlm, approver, orgID, "support.impersonation.approve"); err != nil {
				return err
			}
		case "organization_owner":
			if err := s.checkActor(ctx, tx, rlm, approver, orgID, "org.support_access.approve"); err != nil {
				return err
			}
		case "customer":
			if approver.UserID != targetID {
				return problem.ErrForbidden.WithDetail("only the customer can approve this request")
			}
		default:
			return problem.ErrConflict.WithDetail("no approval required")
		}
		if _, err := tx.Exec(ctx, `UPDATE impersonation_requests SET state='approved', approved_by_id=$2, approved_at=$3 WHERE id=$1`,
			requestID, approver.UserID, s.d.Now()); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.approved", RealmID: rlm.ID, OrgID: orgID,
			Actor: audit.Ref{Type: "user", ID: approver.UserID, SessionID: approver.SessionID}, Subject: &audit.Ref{Type: "user", ID: targetID},
			Target: &audit.Ref{Type: "impersonation_request", ID: requestID}, Category: "support", Metadata: map[string]any{"approval": approval}})
		return err
	})
}

// Issue re-validates everything with live state and issues the support grant and
// opaque token. The grant and its audit/outbox records commit before the token is
// returned; an audit failure prevents access (IMP-020, TEST-047).
func (s *Service) Issue(ctx context.Context, rlm *realm.Realm, a Actor, requestID string) (*Issued, error) {
	if err := s.enabled(ctx, rlm); err != nil {
		return nil, err
	}
	var out *Issued
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var r Request
		var clientRef, actorSession string
		var ttlSec int
		err := tx.QueryRow(ctx, `SELECT id, actor_user_id, actor_session_id, target_user_id, organization_id, client_ref, resource_id, scopes, mode,
			state, expires_at, requested_ttl_seconds, coalesce(ticket_reference,'') FROM impersonation_requests WHERE realm_id=$1 AND id=$2 FOR UPDATE`,
			rlm.ID, requestID).Scan(&r.ID, &r.ActorUserID, &actorSession, &r.TargetUserID, &r.OrganizationID, &clientRef, &r.ResourceID, &r.Scopes,
			&r.Mode, &r.State, &r.ExpiresAt, &ttlSec, &r.TicketReference)
		if err != nil {
			return problem.ErrNotFound
		}
		if r.ActorUserID != a.UserID {
			return problem.ErrForbidden.WithDetail("only the requesting operator can issue the grant")
		}
		if r.State != "approved" || !s.d.Now().Before(r.ExpiresAt) {
			return problem.ErrConflict.WithDetail("request is not approved or has expired")
		}
		if _, err := s.Orgs.LockActiveTx(ctx, tx, rlm.ID, r.OrganizationID); err != nil {
			return problem.ErrImpersonationDenied
		}
		m, err := s.Orgs.ActiveMembership(ctx, tx, rlm.ID, r.OrganizationID, r.TargetUserID)
		if err != nil {
			return problem.ErrImpersonationDenied.WithDetail("target membership is no longer active")
		}
		client, err := s.Apps.ClientByRef(ctx, tx, rlm.ID, clientRef)
		if err != nil || !client.Active() {
			return problem.ErrImpersonationDenied
		}
		res, err := s.Apps.Resource(ctx, tx, rlm.ID, r.ResourceID)
		if err != nil || !res.ImpersonationEnabled || res.VerificationMode != application.ModeStrictOnline {
			return problem.ErrImpersonationDenied
		}
		if err := s.checkActor(s.supportContext(ctx, tx, r.TargetUserID, r.OrganizationID, r.Mode, r.Scopes, res), tx, rlm, a,
			r.OrganizationID, "support.impersonation.start"); err != nil {
			return err
		}
		sess, err := s.Sessions.Active(ctx, tx, rlm.ID, a.SessionID)
		if err != nil {
			return problem.ErrImpersonationDenied
		}
		// Least privilege: support policy ∩ requested scopes. The token's subject is
		// the target, so every resource decision evaluates the target's own current
		// permissions; the operator's business permissions are never added (IMP-007,
		// IMP-008).
		scopes := []string{}
		for _, sc := range r.Scopes {
			if slices.Contains(res.ImpersonationPolicy.AllowedScopes, sc) || (r.Mode == "allowlisted_write" && slices.Contains(res.ImpersonationPolicy.WriteScopes, sc)) {
				scopes = append(scopes, sc)
			}
		}
		if len(scopes) == 0 {
			return problem.ErrImpersonationDenied
		}
		now := s.d.Now()
		ttl := time.Duration(ttlSec) * time.Second
		if max := s.maxTTL(rlm); ttl <= 0 || ttl > max {
			ttl = max
		}
		g := Grant{ID: ids.New(ids.ImpGrant), RequestID: r.ID, ActorUserID: a.UserID, TargetUserID: r.TargetUserID, OrganizationID: r.OrganizationID,
			ResourceID: res.ID, ScopeCeiling: scopes, Mode: r.Mode, State: "active", ExpiresAt: now.Add(ttl), CreatedAt: now}
		if _, err := tx.Exec(ctx, `INSERT INTO impersonation_grants (id, realm_id, request_id, actor_user_id, actor_session_id, actor_mfa_time,
			target_user_id, target_membership_id, organization_id, client_ref, resource_id, scope_ceiling, mode, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, g.ID, rlm.ID, r.ID, a.UserID, a.SessionID, sess.MFATime, r.TargetUserID,
			m.ID, r.OrganizationID, client.Ref, res.ID, scopes, r.Mode, g.ExpiresAt, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE impersonation_requests SET state='issued' WHERE id=$1`, r.ID); err != nil {
			return err
		}
		// Honest assurance: the target did not authenticate; actor assurance is recorded
		// separately and no target MFA evidence is copied (IMP-018).
		actor, _ := json.Marshal(token.Actor{Issuer: rlm.Issuer, Subject: a.UserID})
		plain, err := s.Sessions.IssueOpaqueTx(ctx, tx, secret.PrefixImpersonation, &session.OpaqueToken{RealmID: rlm.ID,
			Kind: token.KindImpersonationAccess, ClientRef: client.Ref, SubjectType: "user", SubjectID: r.TargetUserID, Actor: actor,
			OrgID: r.OrganizationID, ResourceID: res.ID, Scopes: scopes, ImpersonationGrantID: g.ID, ExpiresAt: g.ExpiresAt})
		if err != nil {
			return err
		}
		if s.FailAudit != nil {
			if err := s.FailAudit(); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.started", RealmID: rlm.ID, OrgID: r.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: a.UserID, SessionID: a.SessionID}, Subject: &audit.Ref{Type: "user", ID: r.TargetUserID},
			Target: &audit.Ref{Type: "impersonation_grant", ID: g.ID}, ImpersonationGrantID: g.ID, ReasonCode: "APPROVED_SUPPORT_REQUEST",
			Category: "support", Metadata: map[string]any{"ticket_reference": r.TicketReference, "audience": res.Audience,
				"expires_at": g.ExpiresAt, "scopes": scopes, "mode": r.Mode, "request_id": r.ID}}); err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "support.impersonation.started", RealmID: rlm.ID, OrgID: r.OrganizationID,
			AggregateType: "impersonation_grant", AggregateID: g.ID, Data: map[string]any{"grant_id": g.ID, "actor_user_id": a.UserID,
				"target_user_id": r.TargetUserID, "expires_at": g.ExpiresAt}}); err != nil {
			return err
		}
		if rlm.Policy.Impersonation.NotifyCustomer {
			var email, orgName string
			_ = tx.QueryRow(ctx, `SELECT original_value FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL ORDER BY is_primary DESC LIMIT 1`,
				r.TargetUserID).Scan(&email)
			_ = tx.QueryRow(ctx, `SELECT display_name FROM organizations WHERE id=$1`, r.OrganizationID).Scan(&orgName)
			if email != "" {
				if _, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: rlm.ID, OrgID: r.OrganizationID, Template: notification.TplSupportAccess,
					Recipient: email, Mandatory: true, ReferenceType: "impersonation_grant", ReferenceID: g.ID, UserID: r.TargetUserID,
					Data: map[string]string{"realm": rlm.DisplayName, "organization": orgName, "time": notification.Timestamp(now),
						"expires": notification.Timestamp(g.ExpiresAt), "state": strings.ReplaceAll(r.Mode, "_", "-")}}); err != nil {
					return err
				}
			}
		}
		out = &Issued{Grant: g, AccessToken: plain, TokenType: "Bearer", ExpiresIn: int(ttl.Seconds()), Scope: strings.Join(scopes, " ")}
		return nil
	})
	return out, err
}

// ValidateGrant is called on every introspection of a support token (IMP-010). It
// re-checks the grant, the actor (active, session live, still permitted) and the
// target (active, membership live), and returns actor-aware context (IMP-006).
func (s *Service) ValidateGrant(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, realmID, grantID string) (map[string]any, bool) {
	var actorID, actorSession, targetID, membershipID, orgID, mode, state string
	var expires time.Time
	err := q.QueryRow(ctx, `SELECT actor_user_id, actor_session_id, target_user_id, target_membership_id, organization_id, mode, state, expires_at
		FROM impersonation_grants WHERE realm_id=$1 AND id=$2`, realmID, grantID).Scan(&actorID, &actorSession, &targetID, &membershipID, &orgID, &mode, &state, &expires)
	if err != nil || state != "active" || !s.d.Now().Before(expires) {
		return nil, false
	}
	var ok bool
	err = q.QueryRow(ctx, `SELECT
		(SELECT state='active' FROM users WHERE id=$1) AND
		(SELECT state='active' FROM users WHERE id=$2) AND
		(SELECT state='active' AND (expires_at IS NULL OR expires_at > $5) FROM memberships WHERE id=$3) AND
		(SELECT state='active' FROM organizations WHERE id=$4) AND
		(SELECT state='active' AND idle_expires_at > $5 AND absolute_expires_at > $5 FROM sessions WHERE id=$6)`,
		actorID, targetID, membershipID, orgID, s.d.Now(), actorSession).Scan(&ok)
	if err != nil || !ok {
		return nil, false
	}
	var scopes []string
	var resourceID string
	if err := q.QueryRow(ctx, `SELECT scope_ceiling, resource_id FROM impersonation_grants WHERE id=$1`, grantID).Scan(&scopes, &resourceID); err != nil {
		return nil, false
	}
	res, err := s.Apps.Resource(ctx, s.d.DB.Pool, realmID, resourceID)
	if err != nil {
		return nil, false
	}
	// The operator's capability profile is re-evaluated on every use, so
	// narrowing it ends live grants that no longer fit (IMP-002, IMP-010).
	if !s.Authz.Check(s.supportContext(ctx, q, targetID, orgID, mode, scopes, res), s.d.DB.Pool, realmID,
		authorization.Subject{Type: authorization.SubjectUser, ID: actorID}, "support.impersonation.start",
		authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
		return nil, false
	}
	rlm, err := s.Realms.ByID(ctx, s.d.DB.Pool, realmID)
	if err != nil {
		return nil, false
	}
	// Every switch that allowed the grant is re-checked on each use, so turning
	// support access off (deployment, realm, resource, organization or customer
	// opt-out) ends live grants immediately (IMP-001, IMP-010).
	if !s.d.Cfg.Impersonation.Enabled || !rlm.Policy.Impersonation.Enabled {
		return nil, false
	}
	var resourceOK, orgOptOut, customerOptOut bool
	if err := q.QueryRow(ctx, `SELECT
		coalesce((SELECT r.impersonation_enabled AND r.verification_mode='strict_online' AND r.state='active'
			FROM api_resources r JOIN impersonation_grants g ON g.resource_id=r.id WHERE g.id=$1), false),
		coalesce((SELECT (policy->>'support_access_opt_out')::boolean FROM organizations WHERE id=$2), false),
		coalesce((SELECT (internal_metadata->>'support_access_opt_out')::boolean FROM users WHERE id=$3), false)`,
		grantID, orgID, targetID).Scan(&resourceOK, &orgOptOut, &customerOptOut); err != nil {
		return nil, false
	}
	if !resourceOK || orgOptOut || (customerOptOut && rlm.Policy.Impersonation.AllowCustomerOptOut) {
		return nil, false
	}
	return map[string]any{"act": map[string]any{"iss": rlm.Issuer, "sub": actorID}, "support_mode": mode}, true
}

// Revoke ends a grant (IMP-016). Allowed for the actor, holders of
// support.impersonation.revoke, and the target customer.
func (s *Service) Revoke(ctx context.Context, rlm *realm.Realm, by Actor, grantID, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var actorID, targetID, orgID, state string
		if err := tx.QueryRow(ctx, `SELECT actor_user_id, target_user_id, organization_id, state FROM impersonation_grants WHERE realm_id=$1 AND id=$2 FOR UPDATE`,
			rlm.ID, grantID).Scan(&actorID, &targetID, &orgID, &state); err != nil {
			return problem.ErrNotFound
		}
		who := ""
		switch {
		case by.UserID == actorID:
			who = "actor"
		case by.UserID == targetID:
			who = "target"
		case s.Authz.Check(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: by.UserID}, "support.impersonation.revoke",
			authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}):
			who = "administrator"
		default:
			return problem.ErrNotFound
		}
		if state != "active" {
			return nil
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$2, revoked_by_type=$3, revoked_by_id=$4, revoke_reason=$5 WHERE id=$1`,
			grantID, now, who, by.UserID, nilIfEmpty(reason)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE impersonation_grant_id=$1 AND revoked_at IS NULL`, grantID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE impersonation_handoffs SET consumed_at=$2 WHERE grant_id=$1 AND consumed_at IS NULL`, grantID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.revoked", RealmID: rlm.ID, OrgID: orgID,
			Actor: audit.Ref{Type: "user", ID: by.UserID, SessionID: by.SessionID}, Subject: &audit.Ref{Type: "user", ID: targetID},
			Target: &audit.Ref{Type: "impersonation_grant", ID: grantID}, ImpersonationGrantID: grantID, Category: "support",
			Metadata: map[string]any{"revoked_by": who}}); err != nil {
			return err
		}
		_, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "support.impersonation.ended", RealmID: rlm.ID, OrgID: orgID,
			AggregateType: "impersonation_grant", AggregateID: grantID, Data: map[string]any{"grant_id": grantID, "reason": "revoked"}})
		return err
	})
}

// CreateHandoff issues a single-use, destination-bound entry code valid for at most
// 30 seconds, so no reusable token appears in a browser URL (§16.3, TEST-046).
func (s *Service) CreateHandoff(ctx context.Context, rlm *realm.Realm, a Actor, grantID, destinationClientID string) (string, time.Time, error) {
	var code string
	var exp time.Time
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var actorID, state, resourceID string
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT actor_user_id, state, expires_at, resource_id FROM impersonation_grants WHERE realm_id=$1 AND id=$2`,
			rlm.ID, grantID).Scan(&actorID, &state, &expires, &resourceID); err != nil || actorID != a.UserID {
			return problem.ErrNotFound
		}
		if state != "active" || !s.d.Now().Before(expires) {
			return problem.ErrConflict.WithDetail("grant is not active")
		}
		dest, err := s.Apps.ClientByClientID(ctx, tx, rlm.ID, destinationClientID)
		if err != nil || !dest.Active() || dest.Public() {
			return problem.ErrValidation.WithField("destination_client_id", "must be an active confidential application backend")
		}
		res, err := s.Apps.Resource(ctx, tx, rlm.ID, resourceID)
		if err != nil {
			return err
		}
		if len(res.ImpersonationPolicy.SupportClientIDs) > 0 && !slices.Contains(res.ImpersonationPolicy.SupportClientIDs, dest.ClientID) {
			return problem.ErrValidation.WithField("destination_client_id", "destination is not approved for this resource")
		}
		code = secret.Token(secret.PrefixHandoff)
		exp = s.d.Now().Add(s.d.Cfg.Impersonation.HandoffTTL)
		if exp.After(expires) {
			exp = expires
		}
		if _, err := tx.Exec(ctx, `INSERT INTO impersonation_handoffs (id, realm_id, grant_id, code_digest, destination_client_ref, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, ids.New(ids.ImpHandoff), rlm.ID, grantID, secret.Digest(code), dest.Ref, exp, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.handoff.created", RealmID: rlm.ID, Actor: audit.Ref{Type: "user", ID: a.UserID, SessionID: a.SessionID},
			ImpersonationGrantID: grantID, Category: "support", Metadata: map[string]any{"destination": dest.ClientID}})
		return err
	})
	return code, exp, err
}

// RedeemHandoff exchanges a handoff code at the destination's authenticated backend
// for a fresh support token bound to the same grant (one use, right destination).
func (s *Service) RedeemHandoff(ctx context.Context, rlm *realm.Realm, destination *application.Client, code string) (*Issued, error) {
	if !secret.HasPrefix(code, secret.PrefixHandoff) {
		return nil, problem.ErrInvalidProof
	}
	var out *Issued
	var rejected *audit.Event
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rejected = nil
		var id, grantID, destRef string
		var exp time.Time
		var consumed *time.Time
		if err := tx.QueryRow(ctx, `SELECT id, grant_id, destination_client_ref, expires_at, consumed_at FROM impersonation_handoffs
			WHERE realm_id=$1 AND code_digest=$2 FOR UPDATE`, rlm.ID, secret.Digest(code)).Scan(&id, &grantID, &destRef, &exp, &consumed); err != nil {
			return problem.ErrInvalidProof
		}
		if consumed != nil || !s.d.Now().Before(exp) || destRef != destination.Ref {
			rejected = &audit.Event{Type: "support.handoff.rejected", RealmID: rlm.ID, Actor: audit.Ref{Type: "client", ID: destination.Ref},
				ImpersonationGrantID: grantID, Outcome: audit.Denied, Category: "support"}
			return problem.ErrInvalidProof
		}
		if _, err := tx.Exec(ctx, `UPDATE impersonation_handoffs SET consumed_at=$2 WHERE id=$1`, id, s.d.Now()); err != nil {
			return err
		}
		extra, ok := s.ValidateGrant(ctx, tx, rlm.ID, grantID)
		if !ok {
			return problem.ErrInvalidProof
		}
		var g Grant
		var actorSession string
		if err := tx.QueryRow(ctx, `SELECT id, request_id, actor_user_id, actor_session_id, target_user_id, organization_id, resource_id, scope_ceiling, mode, state, expires_at, created_at
			FROM impersonation_grants WHERE id=$1`, grantID).Scan(&g.ID, &g.RequestID, &g.ActorUserID, &actorSession, &g.TargetUserID, &g.OrganizationID,
			&g.ResourceID, &g.ScopeCeiling, &g.Mode, &g.State, &g.ExpiresAt, &g.CreatedAt); err != nil {
			return err
		}
		actor, _ := json.Marshal(token.Actor{Issuer: rlm.Issuer, Subject: g.ActorUserID})
		plain, err := s.Sessions.IssueOpaqueTx(ctx, tx, secret.PrefixImpersonation, &session.OpaqueToken{RealmID: rlm.ID, Kind: token.KindImpersonationAccess,
			ClientRef: destination.Ref, SubjectType: "user", SubjectID: g.TargetUserID, Actor: actor, OrgID: g.OrganizationID,
			ResourceID: g.ResourceID, Scopes: g.ScopeCeiling, ImpersonationGrantID: g.ID, ExpiresAt: g.ExpiresAt})
		if err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.handoff.redeemed", RealmID: rlm.ID, Actor: audit.Ref{Type: "user", ID: g.ActorUserID},
			Subject: &audit.Ref{Type: "user", ID: g.TargetUserID}, ImpersonationGrantID: g.ID, Category: "support",
			Metadata: map[string]any{"destination": destination.ClientID}}); err != nil {
			return err
		}
		_ = extra
		out = &Issued{Grant: g, AccessToken: plain, TokenType: "Bearer", ExpiresIn: int(g.ExpiresAt.Sub(s.d.Now()).Seconds()), Scope: strings.Join(g.ScopeCeiling, " ")}
		return nil
	})
	if err != nil && rejected != nil {
		_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, *rejected)
	}
	return out, err
}

// List lists grants visible to the caller (IMP-023).
func (s *Service) List(ctx context.Context, realmID, actorID, targetID, orgID, state string, ticket ...string) ([]Grant, error) {
	tk := ""
	if len(ticket) > 0 {
		tk = ticket[0]
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT g.id, g.request_id, g.actor_user_id, g.target_user_id, g.organization_id, g.resource_id, g.scope_ceiling,
		g.mode, g.state, g.expires_at, g.revoked_at, coalesce(g.revoke_reason,''), g.created_at, coalesce(r.reason,''), coalesce(r.ticket_reference,'')
		FROM impersonation_grants g LEFT JOIN impersonation_requests r ON r.id=g.request_id WHERE g.realm_id=$1 AND ($2='' OR g.actor_user_id=$2)
		AND ($3='' OR g.target_user_id=$3) AND ($4='' OR g.organization_id=$4) AND ($5='' OR g.state=$5) AND ($6='' OR r.ticket_reference=$6)
		ORDER BY g.created_at DESC LIMIT 500`, realmID, actorID, targetID, orgID, state, tk)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.RequestID, &g.ActorUserID, &g.TargetUserID, &g.OrganizationID, &g.ResourceID, &g.ScopeCeiling, &g.Mode,
			&g.State, &g.ExpiresAt, &g.RevokedAt, &g.RevokeReason, &g.CreatedAt, &g.Reason, &g.TicketReference); err != nil {
			return nil, err
		}
		if g.State == "active" && !s.d.Now().Before(g.ExpiresAt) {
			g.State = "expired"
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetCustomerOptOut records a customer's support-access preference (TEST-071).
// Opting out also revokes active grants targeting the customer.
func (s *Service) SetCustomerOptOut(ctx context.Context, rlm *realm.Realm, userID string, optOut bool) error {
	if !rlm.Policy.Impersonation.AllowCustomerOptOut {
		return problem.ErrForbidden.WithDetail("the realm does not permit opting out of support access")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET internal_metadata = internal_metadata || jsonb_build_object('support_access_opt_out', $2::boolean) WHERE id=$1`,
			userID, optOut); err != nil {
			return err
		}
		if optOut {
			if _, err := tx.Exec(ctx, `UPDATE impersonation_grants SET state='revoked', revoked_at=$2, revoked_by_type='target', revoked_by_id=$1,
				revoke_reason='customer_opt_out' WHERE target_user_id=$1 AND state='active'`, userID, s.d.Now()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE opaque_access_tokens SET revoked_at=$2 WHERE subject_id=$1 AND token_kind='impersonation_access' AND revoked_at IS NULL`,
				userID, s.d.Now()); err != nil {
				return err
			}
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.customer_preference.changed", RealmID: rlm.ID, Actor: audit.Ref{Type: "user", ID: userID},
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "support", Metadata: map[string]any{"opt_out": optOut}})
		return err
	})
}

// ExpireGrants marks expired grants.
func (s *Service) ExpireGrants(ctx context.Context) (int64, error) {
	var n int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE impersonation_grants SET state='expired' WHERE id IN (SELECT id FROM impersonation_grants
			WHERE state='active' AND expires_at <= $1 LIMIT 500 FOR UPDATE SKIP LOCKED)
			RETURNING id, realm_id, organization_id, actor_user_id, target_user_id`, s.d.Now())
		if err != nil {
			return err
		}
		type g struct{ id, realm, org, actor, target string }
		var list []g
		for rows.Next() {
			var x g
			if err := rows.Scan(&x.id, &x.realm, &x.org, &x.actor, &x.target); err != nil {
				rows.Close()
				return err
			}
			list = append(list, x)
		}
		rows.Close()
		for _, x := range list {
			// Expiry is part of the grant's evidence trail (IMP-024).
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.expired", RealmID: x.realm, OrgID: x.org,
				Actor: audit.System, Subject: &audit.Ref{Type: "user", ID: x.target}, Target: &audit.Ref{Type: "impersonation_grant", ID: x.id},
				ImpersonationGrantID: x.id, Category: "support", Metadata: map[string]any{"actor_user_id": x.actor}}); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	return n, err
}

// PendingRequest is a support-access request awaiting a decision.
type PendingRequest struct {
	ID              string    `json:"id"`
	OrganizationID  string    `json:"organization_id"`
	Mode            string    `json:"mode"`
	Scopes          []string  `json:"scopes"`
	Reason          string    `json:"reason"`
	TicketReference string    `json:"ticket_reference,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// PendingForCustomer lists requests that await the customer's own approval
// (IMP-022). The operator is not identified beyond the role.
func (s *Service) PendingForCustomer(ctx context.Context, realmID, userID string) ([]PendingRequest, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, organization_id, mode, scopes, reason, coalesce(ticket_reference,''), created_at, expires_at
		FROM impersonation_requests WHERE realm_id=$1 AND target_user_id=$2 AND state='pending' AND approval_required='customer' AND expires_at > $3
		ORDER BY created_at DESC LIMIT 50`, realmID, userID, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingRequest{}
	for rows.Next() {
		var p PendingRequest
		if err := rows.Scan(&p.ID, &p.OrganizationID, &p.Mode, &p.Scopes, &p.Reason, &p.TicketReference, &p.CreatedAt, &p.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Deny refuses a pending request. The same parties that may approve may deny;
// the requester may withdraw.
func (s *Service) Deny(ctx context.Context, rlm *realm.Realm, by Actor, requestID, reason string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var actorID, orgID, targetID, approval, state string
		if err := tx.QueryRow(ctx, `SELECT actor_user_id, organization_id, target_user_id, approval_required, state FROM impersonation_requests
			WHERE realm_id=$1 AND id=$2 FOR UPDATE`, rlm.ID, requestID).Scan(&actorID, &orgID, &targetID, &approval, &state); err != nil {
			return problem.ErrNotFound
		}
		allowed := by.UserID == actorID
		switch approval {
		case "customer":
			allowed = allowed || by.UserID == targetID
		case "second_operator":
			allowed = allowed || s.Authz.Check(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: by.UserID},
				"support.impersonation.approve", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID})
		case "organization_owner":
			allowed = allowed || s.Authz.Check(ctx, tx, rlm.ID, authorization.Subject{Type: authorization.SubjectUser, ID: by.UserID},
				"org.support_access.approve", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID})
		}
		if !allowed {
			return problem.ErrNotFound // unrelated callers learn nothing about the request
		}
		if state != "pending" && state != "approved" {
			return problem.ErrConflict.WithDetail("request is no longer open")
		}
		if _, err := tx.Exec(ctx, `UPDATE impersonation_requests SET state='denied' WHERE id=$1`, requestID); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "support.impersonation.request_denied", RealmID: rlm.ID, OrgID: orgID,
			Actor: audit.Ref{Type: "user", ID: by.UserID, SessionID: by.SessionID}, Subject: &audit.Ref{Type: "user", ID: targetID},
			Target: &audit.Ref{Type: "impersonation_request", ID: requestID}, Category: "support", Metadata: map[string]any{"reason": reason}})
		return err
	})
}

// supportContext attaches the trusted support decision context derived from
// stored state (request or grant), never from the caller's assertions
// (IMP-002, IMP-007, AZ-016).
func (s *Service) supportContext(ctx context.Context, q interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}, targetID, orgID, mode string, scopes []string, res *application.Resource) context.Context {
	category := "member"
	var guest bool
	if err := q.QueryRow(ctx, `SELECT is_guest FROM users WHERE id=$1`, targetID).Scan(&guest); err != nil {
		category = "" // unknown targets satisfy no category condition
	} else if guest {
		category = "guest"
	}
	dc, _ := authorization.DecisionContextFrom(ctx)
	dc.Resources = []string{res.ID, res.Audience}
	dc.Support = &authorization.SupportContext{OrganizationID: orgID, SubjectCategory: category, Mode: mode, Scopes: scopes}
	return authorization.WithDecisionContext(ctx, dc)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
