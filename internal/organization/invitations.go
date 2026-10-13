package organization

import (
	"context"
	"fmt"
	"github.com/proudbase/proudauth/internal/keys"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/events"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/ratelimit"
	"github.com/proudbase/proudauth/internal/storage"
)

// Invitation is the administrator-visible invitation record. The secret is never
// included (INV-003).
type Invitation struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	Purpose         string     `json:"purpose"`
	ProjectID       string     `json:"project_id,omitempty"`
	TargetEmail     string     `json:"target_email,omitempty"`
	TargetUserID    string     `json:"target_user_id,omitempty"`
	RoleIDs         []string   `json:"role_ids"`
	InviterType     string     `json:"inviter_type"`
	InviterID       string     `json:"inviter_id"`
	SecretVersion   int        `json:"secret_version"`
	State           string     `json:"state"`
	DeliveryState   string     `json:"delivery_state"`
	SendCount       int        `json:"send_count"`
	MaxUses         int        `json:"max_uses"`
	UseCount        int        `json:"use_count"`
	AllowedDomains  []string   `json:"allowed_domains,omitempty"`
	ExpiresAt       time.Time  `json:"expires_at"`
	AcceptedBy      string     `json:"accepted_by_user_id,omitempty"`
	AcceptedAt      *time.Time `json:"accepted_at,omitempty"`
	MembershipID    string     `json:"membership_id,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Version         int64      `json:"version"`
	BatchID         string     `json:"batch_id,omitempty"`
	SupersededBy    string     `json:"superseded_by,omitempty"`
	targetCanonical string
	boundUserID     string
}

const invCols = `id, organization_id, purpose, coalesce(project_id,''), coalesce(target_email_display,''), coalesce(target_email_canonical,''),
	coalesce(target_user_id,''), role_ids, inviter_type, inviter_id, secret_version, state, delivery_state, send_count, max_uses, use_count,
	allowed_domains, expires_at, coalesce(accepted_by_user_id,''), accepted_at, coalesce(membership_id,''), created_at, version,
	coalesce(batch_id,''), coalesce(superseded_by,''), coalesce(bound_user_id,'')`

func scanInvitation(row pgx.Row) (*Invitation, error) {
	var i Invitation
	err := row.Scan(&i.ID, &i.OrganizationID, &i.Purpose, &i.ProjectID, &i.TargetEmail, &i.targetCanonical, &i.TargetUserID, &i.RoleIDs,
		&i.InviterType, &i.InviterID, &i.SecretVersion, &i.State, &i.DeliveryState, &i.SendCount, &i.MaxUses, &i.UseCount, &i.AllowedDomains,
		&i.ExpiresAt, &i.AcceptedBy, &i.AcceptedAt, &i.MembershipID, &i.CreatedAt, &i.Version, &i.BatchID, &i.SupersededBy, &i.boundUserID)
	return &i, err
}

// InviteInput creates an invitation (INV-002).
type InviteInput struct {
	Email          string   `json:"email"`
	UserID         string   `json:"user_id"`
	RoleIDs        []string `json:"role_ids"`
	Purpose        string   `json:"purpose"`
	ProjectID      string   `json:"project_id"`
	MaxUses        int      `json:"max_uses"`
	AllowedDomains []string `json:"allowed_domains"`
	TTLHours       int      `json:"ttl_hours"`
	Message        string   `json:"message"`
	Locale         string   `json:"locale"`
	batchID        string
}

// InviteContext supplies presentation data for delivery.
type InviteContext struct {
	RealmName   string
	OrgName     string
	InviterName string
	LinkBase    string // trusted, configured URL; the secret is placed in the fragment
	DefaultTTL  time.Duration
}

// CreateInvitation creates an invitation within the inviter's delegation ceiling and
// enqueues delivery in the same transaction. It returns the secret once.
func (s *Service) CreateInvitation(ctx context.Context, realmID, orgID string, in InviteInput, actor authorization.Subject, auditActor audit.Ref, ic InviteContext) (*Invitation, string, error) {
	var out *Invitation
	var plain string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, plain, err = s.createInvitationTx(ctx, tx, realmID, orgID, in, actor, auditActor, ic)
		return err
	})
	return out, plain, err
}

func (s *Service) createInvitationTx(ctx context.Context, tx pgx.Tx, realmID, orgID string, in InviteInput, actor authorization.Subject, auditActor audit.Ref, ic InviteContext) (*Invitation, string, error) {
	var out *Invitation
	var plain string
	err := func() error {
		org, err := s.LockActiveTx(ctx, tx, realmID, orgID)
		if err != nil {
			return err
		}
		if org.Policy.InvitationsEnabled != nil && !*org.Policy.InvitationsEnabled {
			return problem.ErrForbidden.WithDetail("invitations are disabled for this organization")
		}
		scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.invites.create", scope) {
			return problem.ErrForbidden
		}
		if in.Purpose == "" {
			in.Purpose = "organization_membership"
		}
		if in.Purpose != "organization_membership" && in.Purpose != "project_access" && in.Purpose != "shared_link" {
			return problem.ErrValidation.WithField("purpose", "unsupported purpose")
		}
		if in.Purpose == "project_access" {
			// Application invitations grant project roles, not membership (INV-012).
			if in.ProjectID == "" || len(in.RoleIDs) == 0 || len(in.RoleIDs) > 10 {
				return problem.ErrValidation.WithField("role_ids", "project invitations require a project_id and 1..10 project roles")
			}
			for _, rid := range in.RoleIDs {
				if _, err := s.projectRoleBasis(ctx, tx, realmID, orgID, in.ProjectID, actor, rid); err != nil {
					return err
				}
			}
		} else if len(in.RoleIDs) == 0 {
			member, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgMember)
			if err != nil {
				return err
			}
			in.RoleIDs = []string{member.ID}
		}
		if len(in.RoleIDs) > 10 {
			return problem.ErrValidation.WithField("role_ids", "at most 10 roles")
		}
		for _, rid := range in.RoleIDs {
			if in.Purpose == "project_access" {
				break
			}
			role, err := s.Authz.Role(ctx, tx, realmID, rid)
			if err != nil {
				return problem.ErrValidation.WithField("role_ids", "unknown role")
			}
			if role.Boundary != "organization" || (role.OrganizationID != "" && role.OrganizationID != orgID) {
				return problem.ErrValidation.WithField("role_ids", "role does not belong to this organization")
			}
			// INV-007: the inviter may only grant delegable roles.
			if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, role, scope); err != nil {
				if problem.Is(err, problem.ErrForbidden) {
					// An inviter without role-assignment authority may still invite plain members.
					if role.Name == authorization.RoleOrgMember && role.BuiltIn {
						continue
					}
				}
				return err
			}
			if in.Purpose == "shared_link" && (role.IsOwnerRole || role.Name == authorization.RoleOrgAdmin) {
				return problem.ErrValidation.WithField("role_ids", "shared links cannot grant owner or admin roles (INV-015)")
			}
		}
		// A negative lifetime is refused rather than read as "the default":
		// the default can exceed a shared link's maximum lifetime.
		if in.TTLHours < 0 {
			return problem.ErrValidation.WithField("ttl_hours", "must be positive (omit it for the default)")
		}
		var canon, display, bound string
		switch in.Purpose {
		case "shared_link":
			if maxUses := s.d.Cfg.Limits.SharedInvitationMaxUses; in.MaxUses <= 0 || in.MaxUses > maxUses {
				return problem.ErrValidation.WithField("max_uses", fmt.Sprintf("shared links require 1..%d uses", maxUses))
			}
			if len(in.AllowedDomains) == 0 {
				return problem.ErrValidation.WithField("allowed_domains", "shared links require an explicit domain policy")
			}
			for i, d := range in.AllowedDomains {
				cd, err := canonical.Domain(d)
				if err != nil {
					return problem.ErrValidation.WithField("allowed_domains", "invalid domain")
				}
				in.AllowedDomains[i] = cd
			}
			if maxTTL := int(s.d.Cfg.Limits.SharedInvitationMaxTTL.Hours()); in.TTLHours == 0 || in.TTLHours > maxTTL {
				in.TTLHours = min(24, maxTTL)
			}
		default:
			in.MaxUses = 1
			if in.Email == "" && in.UserID == "" {
				return problem.ErrValidation.WithField("email", "an email or user_id is required")
			}
			if in.Email != "" {
				c, d, err := canonical.Email(in.Email)
				if err != nil {
					return problem.ErrValidation.WithField("email", "invalid email")
				}
				canon, display = c, d
				if len(org.Policy.AllowedEmailDomains) > 0 && !slices.Contains(org.Policy.AllowedEmailDomains, canonical.EmailDomain(c)) {
					return problem.ErrValidation.WithField("email", "domain not allowed by organization policy")
				}
				// Bind the invitation to the account that holds the address now, so a
				// later change or recycling of the address cannot redirect it (INV-014, USR-021).
				if err := tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2
					AND verified_at IS NOT NULL LIMIT 1`, realmID, c).Scan(&bound); err != nil && !storage.IsNoRows(err) {
					return err
				}
			}
		}
		if in.Purpose == "project_access" && in.ProjectID == "" {
			return problem.ErrValidation.WithField("project_id", "required for project invitations")
		}
		ttl := ic.DefaultTTL
		if in.TTLHours > 0 {
			ttl = time.Duration(min(in.TTLHours, 24*30)) * time.Hour
		}
		if len(in.Message) > 500 {
			return problem.ErrValidation.WithField("message", "too long")
		}
		if err := s.inviteBudget(ctx, realmID, orgID, canon); err != nil {
			return err
		}
		now := s.d.Now()
		plain = secret.Token(secret.PrefixInvitation)
		id := ids.New(ids.Invitation)
		state := "pending_delivery"
		delivery := "queued"
		if canon == "" {
			state, delivery = "pending_acceptance", "not_applicable"
		}
		_, err = tx.Exec(ctx, `INSERT INTO invitations (id, realm_id, organization_id, purpose, project_id, target_email_canonical, target_email_display,
			target_user_id, role_ids, inviter_type, inviter_id, secret_digest, state, delivery_state, max_uses, allowed_domains, expires_at, message,
			created_at, updated_at, bound_user_id, batch_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$19,$20,$21)`, id, realmID, orgID, in.Purpose,
			nilIfEmpty(in.ProjectID), nilIfEmpty(canon), nilIfEmpty(display), nilIfEmpty(in.UserID), in.RoleIDs, actor.Type, actor.ID,
			secret.Digest(plain), state, delivery, in.MaxUses, nonNilStrings(in.AllowedDomains), now.Add(ttl), nilIfEmpty(in.Message), now,
			nilIfEmpty(bound), nilIfEmpty(in.batchID))
		if err != nil {
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrValidation.WithDetail("unknown organization or project")
			}
			return err
		}
		if canon != "" {
			if err := s.enqueueInvite(ctx, tx, realmID, orgID, id, display, plain, ic, ttl, in.Locale); err != nil {
				return err
			}
		}
		// An inviter who named an existing account (user_id) creates an
		// "invited" membership (TEN-003): visible to administrators, granting
		// nothing until acceptance. Address-only invitations never reveal whether
		// an account exists, so they create none (DOM-008).
		if in.UserID != "" && in.Purpose == "organization_membership" {
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired'))`,
				orgID, in.UserID).Scan(&live); err != nil {
				return err
			}
			if !live {
				if _, err := s.createMembershipTx(ctx, tx, realmID, orgID, in.UserID, "invitation", id, "invited"); err != nil {
					return err
				}
			}
		}
		// The recipient is identifiable in the evidence (INV-016): an
		// account invitation names the user; an email invitation keeps a
		// keyed digest of the canonical address next to the masked display,
		// so investigators can match it without the log holding the address.
		ev := audit.Event{Type: "invitation.created", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation", ID: id}, Metadata: map[string]any{"recipient": maskEmail(display), "role_ids": in.RoleIDs,
				"purpose": in.Purpose, "expires_at": now.Add(ttl), "max_uses": in.MaxUses}}
		if in.UserID != "" {
			ev.Subject = &audit.Ref{Type: "user", ID: in.UserID}
		}
		if canon != "" {
			// Keyed, so the digest of a guessable address cannot be reversed
			// by hashing candidate addresses.
			mac, ver := s.d.Keys.MAC(keys.PurposeLookup, "invitation-recipient", realmID, canon)
			ev.Metadata["recipient_digest"], ev.Metadata["recipient_digest_key_version"] = mac, ver
		}
		if bound != "" && ev.Subject == nil {
			ev.Subject = &audit.Ref{Type: "user", ID: bound}
		}
		if _, err := s.d.Audit.Record(ctx, tx, ev); err != nil {
			return err
		}
		if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.invitation.created", RealmID: realmID, OrgID: orgID,
			AggregateType: "invitation", AggregateID: id, Data: map[string]any{"invitation_id": id}}); err != nil {
			return err
		}
		out, err = s.Invitation(ctx, tx, orgID, id)
		return err
	}()
	return out, plain, err
}

// inviteBudget applies aggregate invitation budgets per organization and per
// recipient (INV-009). Budgets fail closed.
func (s *Service) inviteBudget(ctx context.Context, realmID, orgID, recipient string) error {
	if s.Limiter == nil {
		return nil
	}
	rl := s.d.Cfg.Security.RateLimits
	budgets := []ratelimit.Budget{{Key: "invite-org:" + orgID, Limit: rl.InvitationsPerOrganization, Window: rl.InvitationWindow}}
	if recipient != "" {
		budgets = append(budgets, ratelimit.Budget{Key: "invite-to:" + realmID + ":" + recipient, Limit: rl.InvitationsPerRecipient, Window: rl.InvitationWindow})
	}
	d, err := s.Limiter.Hit(ctx, budgets...)
	if err != nil {
		return err
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter).WithDetail("invitation budget exhausted")
	}
	return nil
}

func (s *Service) enqueueInvite(ctx context.Context, tx pgx.Tx, realmID, orgID, invID, recipient, plain string, ic InviteContext, ttl time.Duration, locale string) error {
	link := ""
	if ic.LinkBase != "" {
		// The secret travels in the fragment so it is not sent to servers or logged on GET (INV-010).
		link = ic.LinkBase + "#invitation=" + plain
	}
	_, err := s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: realmID, OrgID: orgID, Template: notification.TplInvitation,
		Locale: locale, Recipient: recipient, Mandatory: true, ReferenceType: "invitation", ReferenceID: invID, TTL: ttl,
		Data: map[string]string{"organization": ic.OrgName, "inviter": ic.InviterName, "link": link, "code": plain, "realm": ic.RealmName,
			"expires_hours": fmt.Sprint(int(ttl.Hours()))}})
	return err
}

func maskEmail(e string) string {
	if e == "" {
		return ""
	}
	at := strings.LastIndexByte(e, '@')
	if at <= 0 {
		return "***"
	}
	return e[:1] + "***" + e[at:]
}

// Invitation loads an invitation scoped to its organization.
func (s *Service) Invitation(ctx context.Context, q storage.Querier, orgID, id string) (*Invitation, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	i, err := scanInvitation(q.QueryRow(ctx, `SELECT `+invCols+` FROM invitations WHERE organization_id=$1 AND id=$2`, orgID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	return i, nil
}

// ListInvitations lists invitations of an organization.
func (s *Service) ListInvitations(ctx context.Context, orgID, state, after string, limit int) ([]*Invitation, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+invCols+` FROM invitations WHERE organization_id=$1 AND ($2='' OR state=$2) AND ($3='' OR id > $3)
		ORDER BY id LIMIT $4`, orgID, state, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Invitation{}
	for rows.Next() {
		i, err := scanInvitation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// ResendInvitation rotates the secret (the previous secret becomes invalid) and
// enqueues a new delivery, consuming from a send budget that is never reset (INV-009).
func (s *Service) ResendInvitation(ctx context.Context, realmID, orgID, id string, actor authorization.Subject, auditActor audit.Ref, ic InviteContext) (string, error) {
	var plain string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.LockActiveTx(ctx, tx, realmID, orgID); err != nil {
			return err
		}
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.invites.create", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
			return problem.ErrForbidden
		}
		inv, err := scanInvitation(tx.QueryRow(ctx, `SELECT `+invCols+` FROM invitations WHERE organization_id=$1 AND id=$2 FOR UPDATE`, orgID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if inv.State != "pending_delivery" && inv.State != "pending_acceptance" && inv.State != "created" {
			return problem.ErrConflict.WithDetail("invitation is no longer pending")
		}
		if inv.TargetEmail == "" {
			return problem.ErrConflict.WithDetail("this invitation has no delivery address")
		}
		// send_count includes the first send; limits.invitation_resends
		// counts the sends after it.
		if inv.SendCount-1 >= s.d.Cfg.Limits.InvitationResends {
			return problem.ErrRateLimited.WithDetail("resend limit reached for this invitation")
		}
		if err := s.inviteBudget(ctx, realmID, orgID, inv.targetCanonical); err != nil {
			return err
		}
		now := s.d.Now()
		if !now.Before(inv.ExpiresAt) {
			return problem.ErrConflict.WithDetail("invitation expired; create a new one")
		}
		plain = secret.Token(secret.PrefixInvitation)
		if _, err := tx.Exec(ctx, `UPDATE invitations SET secret_digest=$2, secret_version=secret_version+1, send_count=send_count+1,
			state='pending_delivery', delivery_state='queued', version=version+1, updated_at=$3 WHERE id=$1`, id, secret.Digest(plain), now); err != nil {
			return err
		}
		if err := s.enqueueInvite(ctx, tx, realmID, orgID, id, inv.TargetEmail, plain, ic, inv.ExpiresAt.Sub(now), ""); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.resent", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation", ID: id}, Metadata: map[string]any{"secret_version": inv.SecretVersion + 1}})
		return err
	})
	return plain, err
}

// RevokeInvitation revokes a pending invitation.
func (s *Service) RevokeInvitation(ctx context.Context, realmID, orgID, id string, actor authorization.Subject, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if !s.Authz.Check(ctx, tx, realmID, actor, "org.invites.revoke", authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}) {
			return problem.ErrForbidden
		}
		tag, err := tx.Exec(ctx, `UPDATE invitations SET state='revoked', version=version+1, updated_at=$3 WHERE organization_id=$1 AND id=$2
			AND state IN ('created','pending_delivery','pending_acceptance')`, orgID, id, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if err := s.releasePendingMembershipTx(ctx, tx, orgID, "invited", id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.revoked", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation", ID: id}})
		return err
	})
}

// InspectResult is the minimal context shown before acceptance. It does not reveal
// the target address or member lists (DOM-008).
type InspectResult struct {
	OrganizationID   string    `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	Purpose          string    `json:"purpose"`
	ExpiresAt        time.Time `json:"expires_at"`
	RequiresAccount  bool      `json:"requires_account"`
}

// Inspect looks up an invitation by secret without consuming or changing it
// (INV-010, TEST-018). Invalid, expired and used invitations all return the same error.
func (s *Service) Inspect(ctx context.Context, realmID, plain string) (*InspectResult, error) {
	if !secret.HasPrefix(plain, secret.PrefixInvitation) || len(plain) > 100 {
		return nil, problem.ErrInvitationInvalid
	}
	var r InspectResult
	var state string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT i.organization_id, o.display_name, i.purpose, i.expires_at, i.state FROM invitations i
		JOIN organizations o ON o.id=i.organization_id WHERE i.realm_id=$1 AND i.secret_digest=$2 AND o.state='active'`,
		realmID, secret.Digest(plain)).Scan(&r.OrganizationID, &r.OrganizationName, &r.Purpose, &r.ExpiresAt, &state)
	if err != nil || (state != "pending_acceptance" && state != "pending_delivery") || !s.d.Now().Before(r.ExpiresAt) {
		return nil, problem.ErrInvitationInvalid
	}
	r.RequiresAccount = true
	return &r, nil
}

// AcceptResult describes a completed acceptance.
type AcceptResult struct {
	InvitationID   string   `json:"invitation_id"`
	OrganizationID string   `json:"organization_id"`
	MembershipID   string   `json:"membership_id,omitempty"`
	ProjectID      string   `json:"project_id,omitempty"`
	AssignmentIDs  []string `json:"assignment_ids,omitempty"`
}

// AcceptTx accepts an invitation for an authenticated user in one transaction
// (INV-004). It locks the invitation, requires proof that the user controls the
// invited identifier (INV-005), re-checks organization and user eligibility
// (INV-008) and re-validates the inviter's current authority against current role
// definitions (INV-007, TEST-017). Concurrent acceptance yields at most one grant.
func (s *Service) AcceptTx(ctx context.Context, tx pgx.Tx, realmID, plain, userID string, auditActor audit.Ref) (*AcceptResult, error) {
	if !secret.HasPrefix(plain, secret.PrefixInvitation) || len(plain) > 100 {
		return nil, problem.ErrInvitationInvalid
	}
	inv, err := scanInvitation(tx.QueryRow(ctx, `SELECT `+invCols+` FROM invitations WHERE realm_id=$1 AND secret_digest=$2 FOR UPDATE`,
		realmID, secret.Digest(plain)))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrInvitationInvalid
		}
		return nil, err
	}
	now := s.d.Now()
	deny := func(reason string) (*AcceptResult, error) {
		_, _ = s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.acceptance.denied", RealmID: realmID, OrgID: inv.OrganizationID,
			Actor: auditActor, Target: &audit.Ref{Type: "invitation", ID: inv.ID}, Outcome: audit.Denied, ReasonCode: reason})
		return nil, problem.ErrInvitationInvalid.WithExtension("reason_code", reason)
	}
	if inv.State != "pending_acceptance" && inv.State != "pending_delivery" {
		return nil, problem.ErrInvitationInvalid
	}
	if !now.Before(inv.ExpiresAt) {
		if _, err := tx.Exec(ctx, `UPDATE invitations SET state='expired', updated_at=$2 WHERE id=$1`, inv.ID, now); err != nil {
			return nil, err
		}
		if err := s.releasePendingMembershipTx(ctx, tx, inv.OrganizationID, "invited", inv.ID); err != nil {
			return nil, err
		}
		return nil, problem.ErrInvitationInvalid
	}
	org, err := s.LockActiveTx(ctx, tx, realmID, inv.OrganizationID)
	if err != nil {
		return deny("ORGANIZATION_INACTIVE")
	}
	// The organization's current invitation policy applies at acceptance, not
	// only at creation (INV-008).
	if org.Policy.InvitationsEnabled != nil && !*org.Policy.InvitationsEnabled {
		return deny("INVITATIONS_DISABLED")
	}
	if inv.targetCanonical != "" && len(org.Policy.AllowedEmailDomains) > 0 &&
		!slices.Contains(org.Policy.AllowedEmailDomains, canonical.EmailDomain(inv.targetCanonical)) {
		return deny("DOMAIN_NOT_ALLOWED")
	}
	var userState string
	if err := tx.QueryRow(ctx, `SELECT state FROM users WHERE realm_id=$1 AND id=$2 FOR SHARE`, realmID, userID).Scan(&userState); err != nil {
		return nil, problem.ErrInvitationInvalid
	}
	if userState != "active" {
		return deny("SUBJECT_INELIGIBLE")
	}
	// Identity proof.
	switch {
	case inv.Purpose == "shared_link":
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE user_id=$1 AND type='email' AND verified_at IS NOT NULL
			AND split_part(canonical_value, '@', 2) = ANY($2))`, userID, inv.AllowedDomains).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return deny("IDENTIFIER_MISMATCH")
		}
	case inv.TargetUserID != "":
		if inv.TargetUserID != userID {
			return deny("IDENTIFIER_MISMATCH")
		}
	default:
		// The address belonged to an account when the invitation was made; it
		// stays bound to that account even if the address moves (INV-014, USR-021).
		if inv.boundUserID != "" && inv.boundUserID != userID {
			return deny("IDENTIFIER_REASSIGNED")
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE user_id=$1 AND type='email' AND canonical_value=$2
			AND verified_at IS NOT NULL)`, userID, inv.targetCanonical).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return deny("IDENTIFIER_MISMATCH") // TEST-015: no data about the invited user is disclosed
		}
	}
	// Re-validate the inviter's authority and the current role definitions.
	scope := authorization.Scope{Type: authorization.ScopeOrganization, ID: inv.OrganizationID}
	inviter := authorization.Subject{Type: inv.InviterType, ID: inv.InviterID}
	if inviter.Type == authorization.SubjectUser {
		var st string
		if err := tx.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, inviter.ID).Scan(&st); err != nil || st != "active" {
			return deny("INVITER_INELIGIBLE")
		}
	}
	if !s.Authz.Check(ctx, tx, realmID, inviter, "org.invites.create", scope) {
		return deny("INVITER_INELIGIBLE")
	}
	if inv.Purpose == "project_access" {
		return s.acceptProjectTx(ctx, tx, realmID, inv, userID, auditActor, deny)
	}
	for _, rid := range inv.RoleIDs {
		role, err := s.Authz.Role(ctx, tx, realmID, rid)
		if err != nil {
			return deny("ROLE_UNAVAILABLE")
		}
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, inviter, role, scope); err != nil {
			if problem.Is(err, problem.ErrForbidden) && role.Name == authorization.RoleOrgMember && role.BuiltIn {
				continue
			}
			return deny("ROLE_CEILING_EXCEEDED")
		}
	}
	// Membership: create or extend without duplicating or silently accumulating roles.
	var mid, mstate string
	err = tx.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired') FOR UPDATE`,
		inv.OrganizationID, userID).Scan(&mid, &mstate)
	switch {
	case storage.IsNoRows(err):
		m, err := s.createMembershipTx(ctx, tx, realmID, inv.OrganizationID, userID, "invitation", inv.ID, "active")
		if err != nil {
			return nil, err
		}
		mid = m.ID
	case err != nil:
		return nil, err
	case mstate == "suspended":
		return deny("MEMBERSHIP_SUSPENDED")
	case mstate == "invited" || mstate == "pending_approval":
		if _, err := tx.Exec(ctx, `UPDATE memberships SET state='active', joined_at=$2, source='invitation', source_reference=$3, revision=revision+1 WHERE id=$1`,
			mid, now, inv.ID); err != nil {
			return nil, err
		}
	}
	for _, rid := range inv.RoleIDs {
		var exists bool
		_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments WHERE role_id=$1 AND membership_id=$2)`, rid, mid).Scan(&exists)
		if exists {
			continue
		}
		if _, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: rid,
			Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID}, Scope: scope, Source: "invitation",
			Reason: inv.ID, SkipCeiling: true}, auditActor); err != nil {
			return nil, err
		}
	}
	newUse := inv.UseCount + 1
	newState := "accepted"
	if inv.Purpose == "shared_link" && newUse < inv.MaxUses {
		newState = inv.State
	}
	if _, err := tx.Exec(ctx, `UPDATE invitations SET state=$2, use_count=$3, accepted_by_user_id=$4, accepted_at=$5, membership_id=$6,
		version=version+1, updated_at=$5 WHERE id=$1`, inv.ID, newState, newUse, userID, now, mid); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.accepted", RealmID: realmID, OrgID: inv.OrganizationID, Actor: auditActor,
		Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "invitation", ID: inv.ID},
		Metadata: map[string]any{"membership_id": mid, "role_ids": inv.RoleIDs, "inviter_id": inv.InviterID}}); err != nil {
		return nil, err
	}
	if _, err := s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.membership.added", RealmID: realmID, OrgID: inv.OrganizationID,
		AggregateType: "membership", AggregateID: mid, Data: map[string]any{"user_id": userID, "membership_id": mid, "source": "invitation"}}); err != nil {
		return nil, err
	}
	return &AcceptResult{InvitationID: inv.ID, OrganizationID: inv.OrganizationID, MembershipID: mid}, nil
}

// Accept wraps AcceptTx in its own transaction.
func (s *Service) Accept(ctx context.Context, realmID, plain, userID string, auditActor audit.Ref) (*AcceptResult, error) {
	var out *AcceptResult
	var denied error
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.AcceptTx(ctx, tx, realmID, plain, userID, auditActor)
		if err != nil && problem.Is(err, problem.ErrInvitationInvalid) {
			denied = err
			return nil // commit the denial audit record
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if denied != nil {
		return nil, denied
	}
	return out, nil
}

// Decline declines an invitation addressed to the authenticated user. An
// expired invitation can no longer be declined, just as it can no longer be
// accepted: it is marked expired and the same invitation_invalid error
// returned.
func (s *Service) Decline(ctx context.Context, realmID, plain, userID string, auditActor audit.Ref) error {
	expired := false
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		expired = false
		inv, err := scanInvitation(tx.QueryRow(ctx, `SELECT `+invCols+` FROM invitations WHERE realm_id=$1 AND secret_digest=$2 FOR UPDATE`,
			realmID, secret.Digest(plain)))
		if err != nil {
			return problem.ErrInvitationInvalid
		}
		if inv.State != "pending_acceptance" && inv.State != "pending_delivery" || inv.Purpose == "shared_link" {
			return problem.ErrInvitationInvalid
		}
		if now := s.d.Now(); !now.Before(inv.ExpiresAt) {
			// Committed like AcceptTx commits it, then refused.
			if _, err := tx.Exec(ctx, `UPDATE invitations SET state='expired', updated_at=$2 WHERE id=$1`, inv.ID, now); err != nil {
				return err
			}
			if err := s.releasePendingMembershipTx(ctx, tx, inv.OrganizationID, "invited", inv.ID); err != nil {
				return err
			}
			expired = true
			return nil
		}
		if (inv.TargetUserID != "" && inv.TargetUserID != userID) || (inv.boundUserID != "" && inv.boundUserID != userID) {
			return problem.ErrInvitationInvalid
		}
		if inv.targetCanonical != "" {
			var ok bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE user_id=$1 AND type='email' AND canonical_value=$2 AND verified_at IS NOT NULL)`,
				userID, inv.targetCanonical).Scan(&ok)
			if !ok {
				return problem.ErrInvitationInvalid
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE invitations SET state='declined', decided_at=$2, version=version+1, updated_at=$2 WHERE id=$1`, inv.ID, s.d.Now()); err != nil {
			return err
		}
		if err := s.releasePendingMembershipTx(ctx, tx, inv.OrganizationID, "invited", inv.ID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.declined", RealmID: realmID, OrgID: inv.OrganizationID, Actor: auditActor,
			Target: &audit.Ref{Type: "invitation", ID: inv.ID}})
		return err
	})
	if err == nil && expired {
		return problem.ErrInvitationInvalid
	}
	return err
}

// InvitationTargetForSecret returns the inviting organization and the invited
// email for the registration flow (INV-006), so a new account must verify that
// exact address before activation.
func (s *Service) InvitationTargetForSecret(ctx context.Context, realmID, plain string) (string, string, error) {
	var orgID, canon string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT organization_id, coalesce(target_email_canonical,'') FROM invitations WHERE realm_id=$1 AND secret_digest=$2
		AND state IN ('pending_delivery','pending_acceptance') AND expires_at > $3`, realmID, secret.Digest(plain), s.d.Now()).Scan(&orgID, &canon)
	if err != nil {
		return "", "", problem.ErrInvitationInvalid
	}
	return orgID, canon, nil
}

// MarkDelivery updates delivery state from the notification worker. Delivery is not
// acceptance authority.
func (s *Service) MarkDelivery(ctx context.Context, invitationID, deliveryState string) error {
	_, err := s.d.DB.Pool.Exec(ctx, `UPDATE invitations SET delivery_state=$2,
		state=CASE WHEN state='pending_delivery' AND $2='accepted_by_provider' THEN 'pending_acceptance' ELSE state END, updated_at=$3
		WHERE id=$1`, invitationID, deliveryState, s.d.Now())
	return err
}

// SyncDeliveryStates copies notification job outcomes into invitation delivery
// state and audits each delivery outcome (INV-016). Provider acceptance is not
// acceptance authority.
func (s *Service) SyncDeliveryStates(ctx context.Context) (int64, error) {
	var n int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE invitations i SET delivery_state = CASE j.state WHEN 'accepted' THEN 'accepted_by_provider'
			WHEN 'failed' THEN 'failed' ELSE 'attempted' END,
			state = CASE WHEN i.state='pending_delivery' AND j.state='accepted' THEN 'pending_acceptance' ELSE i.state END, updated_at=$1
			FROM notification_jobs j WHERE j.reference_type='invitation' AND j.reference_id=i.id AND j.state IN ('accepted','failed','attempted')
			AND i.state='pending_delivery' AND j.created_at = (SELECT max(created_at) FROM notification_jobs WHERE reference_id=i.id)
			RETURNING i.id, i.realm_id, i.organization_id, i.delivery_state, i.send_count`, s.d.Now())
		if err != nil {
			return err
		}
		type upd struct {
			id, realm, org, state string
			sends                 int
		}
		var list []upd
		for rows.Next() {
			var u upd
			if err := rows.Scan(&u.id, &u.realm, &u.org, &u.state, &u.sends); err != nil {
				rows.Close()
				return err
			}
			list = append(list, u)
		}
		rows.Close()
		for _, u := range list {
			outcome := audit.Success
			if u.state == "failed" {
				outcome = audit.Failure
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.delivery." + u.state, RealmID: u.realm, OrgID: u.org, Actor: audit.System,
				Target: &audit.Ref{Type: "invitation", ID: u.id}, Outcome: outcome, Metadata: map[string]any{"send_count": u.sends}}); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	return n, err
}

// ExpireInvitations marks expired invitations (REG-011) and audits each
// transition (INV-016). Work is bounded per run.
func (s *Service) ExpireInvitations(ctx context.Context) (int64, error) {
	var n int64
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE invitations SET state='expired', updated_at=$1 WHERE id IN (SELECT id FROM invitations
			WHERE state IN ('created','pending_delivery','pending_acceptance') AND expires_at <= $1 ORDER BY expires_at LIMIT 500 FOR UPDATE SKIP LOCKED)
			RETURNING id, realm_id, organization_id`, s.d.Now())
		if err != nil {
			return err
		}
		type exp struct{ id, realm, org string }
		var list []exp
		for rows.Next() {
			var e exp
			if err := rows.Scan(&e.id, &e.realm, &e.org); err != nil {
				rows.Close()
				return err
			}
			list = append(list, e)
		}
		rows.Close()
		for _, e := range list {
			if err := s.releasePendingMembershipTx(ctx, tx, e.org, "invited", e.id); err != nil {
				return err
			}
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "invitation.expired", RealmID: e.realm, OrgID: e.org, Actor: audit.System,
				Target: &audit.Ref{Type: "invitation", ID: e.id}}); err != nil {
				return err
			}
		}
		n = int64(len(list))
		return nil
	})
	return n, err
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
