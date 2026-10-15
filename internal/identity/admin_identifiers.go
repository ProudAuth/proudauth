package identity

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// AdminAddEmailTx adds an email address to an account on an administrator's
// behalf, for the lost contact address path of account recovery (MFA-008).
// Like every changed identifier the address starts unverified and not primary
// (USR-004): only the separate, audited verification override proves it
// (USR-005), and only a verified identifier can become primary. An address
// another account has verified is refused, so the administrative path never
// claims someone else's sign-in identifier.
func (s *Service) AdminAddEmailTx(ctx context.Context, tx pgx.Tx, realmID, userID, raw string) (*Identifier, error) {
	c, _, err := canonical.Email(raw)
	if err != nil {
		return nil, problem.ErrValidation.WithField("value", "invalid email")
	}
	owner, err := s.VerifiedEmailOwner(ctx, tx, realmID, c)
	if err != nil {
		return nil, err
	}
	if owner != "" && owner != userID {
		return nil, problem.ErrConflict.WithDetail("the address is verified by another account").WithField("value", "already in use")
	}
	out, err := s.AddIdentifierTx(ctx, tx, realmID, userID, "email", raw, false)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_identifiers SET source='admin' WHERE id=$1`, out.ID); err != nil {
		return nil, err
	}
	out.Source = "admin"
	return out, nil
}
