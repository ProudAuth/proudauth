package authentication

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/storage"
)

// DirectoryLogin is implemented by the directory module (internal/directory).
//
// VerifyPassword reports handled=false for accounts no directory sources;
// for directory-sourced accounts it is the only password check: the local
// credential is never consulted, and an unreachable directory returns an
// upstream_unavailable error instead of falling back to it (PROV-011,
// PROV-014, FED-012).
//
// ProvisionOnLogin imports an account at its first sign-in from a directory
// that enables it, after a successful bind; it returns nil when no directory
// knows the identifier (FED-015).
//
// SignsIn reports whether a password check in the realm may ask a directory
// (an active LDAP connector exists and the module is enabled).
type DirectoryLogin interface {
	VerifyPassword(ctx context.Context, q storage.Querier, userID, password string) (handled, ok bool, err error)
	ProvisionOnLogin(ctx context.Context, tx pgx.Tx, realmID, identifier, password string) (*identity.User, error)
	SignsIn(ctx context.Context, realmID string) (bool, error)
}

// directoryOnce marks a password step that may ask a directory as not
// retried (DB-014): a deadlock retry of the step would repeat the LDAP
// search and bind, an external effect (failed binds count toward the
// directory's own lockout policy).
func (s *Service) directoryOnce(ctx context.Context, realmID string) (context.Context, error) {
	if s.Directory == nil {
		return ctx, nil
	}
	uses, err := s.Directory.SignsIn(ctx, realmID)
	if err != nil {
		return ctx, err
	}
	if uses {
		ctx = storage.NoRetry(ctx)
	}
	return ctx, nil
}
