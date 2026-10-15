package authentication

import (
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// errUnverifiedRecoveryContact refuses an assisted recovery whose setup link
// would go to an address nobody proved control of (MFA-008, USR-004).
var errUnverifiedRecoveryContact = problem.ErrConflict.WithDetail("the account's primary email address is not verified; verify it " +
	"(POST /users/{user}/verification-overrides) or make a verified address primary (POST /users/{user}/identifiers/{id}/primary) first")

// recoveryContactUnverified reports whether assisted recovery must not run
// because the primary email address, which receives the setup link, is not
// verified. An administrator can add an address to an account, but recovery
// is never redirected to it before it is verified and made primary. An
// account without any email address has no such contact: its setup token is
// handed to the operator instead.
func recoveryContactUnverified(u *identity.User) bool {
	e := u.PrimaryEmail()
	return e != nil && !e.Verified()
}
