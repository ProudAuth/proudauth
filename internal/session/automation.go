package session

import (
	"cmp"
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
)

// Reasons of the account-wide revocations that also end the user's own
// automation credentials (CRED-008, MCH-007). Each is the reason the flow
// passes to RevokeUserTx, so it names the flow's user-level token_revocations
// record too.
const (
	ReasonPasswordReset         = "password_reset"
	ReasonCredentialCompromised = "credential_compromised"
	ReasonAssistedRecovery      = "assisted_recovery"
)

// CredentialRevocationReasons are the user-level revocation reasons that end
// the user's personal access tokens and user-owned API keys. Machine
// introspection treats a user-owned credential created before a user-level
// token_revocations record with one of these reasons as inactive, whatever its
// row says (defence in depth).
//
// The other account-wide revocations ("log out everywhere", an
// administrator's revoke-sessions, bulk revocation, a received shared signal)
// end sessions, grants and the tokens issued from them, which is session
// authority (SES-005). Personal access tokens are separate credentials the
// owner minted on purpose and revokes one by one, so those revocations leave
// them alone; suspension, locking and pending deletion make them inactive
// through the owner's state instead.
var CredentialRevocationReasons = []string{ReasonPasswordReset, ReasonCredentialCompromised, ReasonAssistedRecovery}

// RevokedCredential names an automation credential a revocation ended. It
// carries safe metadata only, never the secret (MCH-008).
type RevokedCredential struct {
	ID             string
	Kind           string // personal_token | api_key
	Name           string
	DisplayPrefix  string
	OrganizationID string
}

// RevokeUserCredentialsTx revokes the user's live automation credentials
// (personal access tokens and API keys the user owns) with reason as their
// revoke_reason and audits each as automation_credential.revoked (CRED-008,
// MCH-007). It runs in the transaction of the password reset, compromise
// marking or assisted recovery it belongs to, next to RevokeUserTx, and
// returns what it revoked, ordered by name, for the owner's notice. Expired
// credentials are already inactive and are left as they are.
func (s *Service) RevokeUserCredentialsTx(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, actor audit.Ref) ([]RevokedCredential, error) {
	now := s.d.Now()
	rows, err := tx.Query(ctx, `UPDATE automation_credentials SET state='revoked', revoked_at=$3, revoke_reason=$4
		WHERE realm_id=$1 AND owner_type='user' AND owner_id=$2 AND state='active' AND expires_at > $3
		RETURNING id, kind, name, display_prefix, coalesce(organization_id,'')`, realmID, userID, now, reason)
	if err != nil {
		return nil, err
	}
	var out []RevokedCredential
	for rows.Next() {
		var c RevokedCredential
		if err := rows.Scan(&c.ID, &c.Kind, &c.Name, &c.DisplayPrefix, &c.OrganizationID); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b RevokedCredential) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	for _, c := range out {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "automation_credential.revoked", RealmID: realmID, OrgID: c.OrganizationID,
			Actor: actor, Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "automation_credential", ID: c.ID},
			ReasonCode: reason, Metadata: map[string]any{"kind": c.Kind, "display_prefix": c.DisplayPrefix}}); err != nil {
			return nil, err
		}
	}
	return out, nil
}
