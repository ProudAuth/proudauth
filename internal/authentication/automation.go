package authentication

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/session"
)

// maxNamedCredentials bounds how many revoked credentials one notice names;
// the rest are counted.
const maxNamedCredentials = 20

// revokeUserCredentialsTx revokes the user's personal access tokens and
// user-owned API keys in tx, as part of a password reset, password-compromise
// marking or assisted recovery (CRED-008, MCH-007), and names them in a
// mandatory credentials_revoked notice. change completes "revoked ... after"
// in that notice. Nothing is sent when the user had no live credential.
func (s *Service) revokeUserCredentialsTx(ctx context.Context, tx pgx.Tx, realmID, userID, reason string, actor audit.Ref, change string) error {
	revoked, err := s.Sessions.RevokeUserCredentialsTx(ctx, tx, realmID, userID, reason, actor)
	if err != nil || len(revoked) == 0 {
		return err
	}
	return s.notifySecurityWith(ctx, tx, realmID, userID, notification.TplCredentialsRevoked,
		map[string]string{"change": change, "credentials": describeCredentials(revoked)})
}

// describeCredentials lists revoked credentials by name and display prefix,
// the two things their owner sees in GET /me/personal-tokens; never a secret
// (MCH-008).
func describeCredentials(revoked []session.RevokedCredential) string {
	parts := make([]string, 0, min(len(revoked), maxNamedCredentials)+1)
	for i, c := range revoked {
		if i == maxNamedCredentials {
			parts = append(parts, fmt.Sprintf("and %d more", len(revoked)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", c.Name, c.DisplayPrefix))
	}
	return strings.Join(parts, ", ")
}
