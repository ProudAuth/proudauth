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
type DirectoryLogin interface {
	VerifyPassword(ctx context.Context, q storage.Querier, userID, password string) (handled, ok bool, err error)
	ProvisionOnLogin(ctx context.Context, tx pgx.Tx, realmID, identifier, password string) (*identity.User, error)
}
