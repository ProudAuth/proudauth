package storage

import (
	"context"
	"errors"
	"regexp"

	"github.com/jackc/pgx/v5"
)

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// GrantRuntime gives the runtime database role the data privileges it needs
// on every table and sequence, and nothing more (OPS-013): no DDL, no
// ownership. Migrations then run as a separate owner role, so the service's
// own credentials cannot alter the schema or drop the audit guards.
//
// It also revokes CREATE on schema public from PUBLIC, which changes the
// database for every role, not only the runtime role: on PostgreSQL 14 and
// earlier PUBLIC holds CREATE on public by default and every role inherits
// it, so revoking it from the runtime role alone leaves the runtime role able
// to create objects. PostgreSQL 15 and later already ship without that grant.
// The schema owner (and a superuser) keeps CREATE; when the migrating role is
// neither, PostgreSQL only warns and the revocation has no effect, which the
// role report (create_in_schema) then shows.
func (db *DB) GrantRuntime(ctx context.Context, role string) error {
	if !ValidRoleName(role) {
		return errors.New("storage: runtime_role must be a lowercase PostgreSQL role name")
	}
	r := pgx.Identifier{role}.Sanitize()
	for _, q := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + r,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + r,
		`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ` + r,
		// No DDL: a direct grant is revoked from the role, and the default
		// grant every role inherits through PUBLIC (PostgreSQL 14 and earlier)
		// is revoked from PUBLIC.
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`REVOKE CREATE ON SCHEMA public FROM ` + r,
		// Tables a later migration creates are usable at once, without a
		// window between the migration and this grant.
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + r,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ` + r,
		// Audit evidence leaves only through the owner-run pruning function
		// (AUD-007).
		`REVOKE DELETE ON audit_events, audit_prunes, audit_prune_log, audit_batches FROM ` + r,
		`GRANT EXECUTE ON FUNCTION proudauth_audit_prune(text, text[]) TO ` + r,
	} {
		if _, err := db.Pool.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// RoleReport describes the role the connection uses.
type RoleReport struct {
	Role       string `json:"role"`
	Superuser  bool   `json:"superuser"`
	OwnsTables bool   `json:"owns_tables"`
	CreateRole bool   `json:"create_role"`
	// CreateInSchema: the role can create objects in public.
	CreateInSchema bool `json:"create_in_schema"`
	// MemberOfOwner: the role inherits the privileges of the schema owner.
	MemberOfOwner bool `json:"member_of_owner"`
}

// CurrentRole reports whether the connection's role has more power than the
// service needs (OPS-013).
func (db *DB) CurrentRole(ctx context.Context) (*RoleReport, error) {
	var r RoleReport
	err := db.Pool.QueryRow(ctx, `SELECT current_user, rolsuper, rolcreaterole,
		EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user),
		has_schema_privilege(current_user, 'public', 'CREATE'),
		EXISTS (SELECT 1 FROM pg_tables t WHERE t.schemaname='public' AND t.tablename='audit_events' AND t.tableowner <> current_user
			AND pg_has_role(current_user, t.tableowner, 'USAGE'))
		FROM pg_roles WHERE rolname=current_user`).Scan(&r.Role, &r.Superuser, &r.CreateRole, &r.OwnsTables, &r.CreateInSchema, &r.MemberOfOwner)
	return &r, err
}

// ValidRoleName reports whether s is an acceptable runtime role name.
func ValidRoleName(s string) bool { return roleName.MatchString(s) }
