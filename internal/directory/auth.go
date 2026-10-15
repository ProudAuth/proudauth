package directory

import (
	"context"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// unavailable is the sign-in outcome when the account's directory cannot be
// asked: a clear, retryable state, never a fallback to a stale local
// password or to another source (PROV-014, FED-012, TEST-027).
func unavailable(detail string) error {
	return problem.ErrUpstreamUnavailable.WithDetail(detail).WithRetryAfter(30 * time.Second)
}

// VerifyPassword verifies the password of a directory-sourced account by a
// bind as that account (PROV-011): the directory decides, and no password
// hash is ever read or stored. handled is false for accounts no directory
// sources, which keep their local credentials.
func (s *Service) VerifyPassword(ctx context.Context, q storage.Querier, userID, password string) (handled, ok bool, err error) {
	if s == nil {
		return false, false, nil
	}
	l, c, err := s.linkForUser(ctx, q, userID)
	if err != nil || l == nil {
		return false, false, err
	}
	if s.Disabled || c.State != "active" || !s.organizationActive(ctx, q, c) {
		s.m.binds.Inc("disabled")
		return true, false, unavailable("directory sign-in for this account is disabled")
	}
	if password == "" || len(password) > 1024 || l.SourceState == "missing" {
		// An empty password would be an unauthenticated bind (RFC 4513
		// §5.1.2), which succeeds on many servers; it is never sent.
		s.m.binds.Inc("invalid_credentials")
		return true, false, nil
	}
	dn, ok, err := s.bindAs(ctx, c, l, password)
	if err != nil {
		s.m.binds.Inc("unavailable")
		_, _ = s.d.Audit.Record(context.WithoutCancel(ctx), s.d.DB.Pool, audit.Event{Type: "directory.authentication.unavailable", RealmID: c.RealmID,
			OrgID: c.OrganizationID, Actor: audit.System, Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "connector", ID: c.ID},
			Category: "operations", Outcome: audit.Failure, ReasonCode: "DIRECTORY_UNAVAILABLE", Metadata: map[string]any{"error": publicError(err)}})
		return true, false, unavailable("the account's directory is unavailable; retry later")
	}
	if !ok {
		s.m.binds.Inc("invalid_credentials")
		return true, false, nil
	}
	s.m.binds.Inc("success")
	if dn != "" && dn != l.DN && q != nil {
		// The entry moved (renamed or another OU): follow it by its immutable
		// identifier, never by its old name.
		_, _ = q.Exec(ctx, `UPDATE connector_external_ids SET source_dn=$3, updated_at=$4 WHERE connector_id=$1 AND resource_type='User' AND external_id=$2`,
			c.ID, l.ExternalID, dn, s.d.Now())
	}
	return true, true, nil
}

// bindAs locates the linked entry (by its stored DN, then by its immutable
// identifier), checks that it is still the same object, still within the
// user filter and not disabled, and binds as it. err reports only that no
// configured endpoint could answer.
func (s *Service) bindAs(ctx context.Context, c *Connector, l *link, password string) (dn string, ok bool, err error) {
	cfg := c.ldap
	attrs := userAttributes(cfg)
	err = s.withDirectory(ctx, c, true, func(cn *conn) error {
		var found *ldap.Entry
		if l.DN != "" {
			entries, err := cn.search(l.DN, ldap.ScopeBaseObject, cfg.UserFilter, attrs, 1)
			if err != nil {
				return err
			}
			if len(entries) == 1 && idValue(cfg, entries[0]) == l.ExternalID {
				found = entries[0]
			}
		}
		if found == nil {
			entries, err := cn.search(cfg.UserBaseDN, scopeOf(cfg.UserScope), "(&"+cfg.UserFilter+idFilter(cfg, l.ExternalID)+")", attrs, 2)
			if err != nil {
				return err
			}
			if len(entries) == 1 && idValue(cfg, entries[0]) == l.ExternalID {
				found = entries[0]
			}
		}
		if found == nil || disabled(cfg, found) {
			ok = false
			return nil
		}
		dn = found.DN
		if berr := cn.bind(found.DN, password); berr != nil {
			if _, transport := isTransport(berr); transport {
				return berr
			}
			// invalidCredentials and every other refusal (locked, expired,
			// must change) are a final "no" (PROV-014).
			ok = false
			return nil
		}
		ok = true
		return nil
	})
	return dn, ok, err
}

// ProvisionOnLogin imports an account at its first sign-in (FED-015) from
// the realm's directories that enable jit_provisioning, tried in name order.
// Only realm (workforce) directories qualify: an organization's directory
// never receives sign-in attempts for identifiers it does not own. The
// identifier is escaped into the login filter (RFC 4515). The first
// directory with a matching entry decides: a wrong password there is final,
// and other directories are not tried with the same credentials. An
// unreachable directory fails closed. It returns nil when no directory knows
// the identifier.
func (s *Service) ProvisionOnLogin(ctx context.Context, tx pgx.Tx, realmID, identifier, password string) (*identity.User, error) {
	if !s.active() || password == "" || len(password) > 1024 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT `+connCols+` FROM provisioning_connectors WHERE realm_id=$1 AND kind='ldap' AND state='active'
		AND organization_id IS NULL AND (config->>'jit_provisioning')::boolean ORDER BY name, id`, realmID)
	if err != nil {
		return nil, err
	}
	var list []*Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, c)
	}
	rows.Close()
	for _, c := range list {
		if !s.organizationActive(ctx, tx, c) {
			continue
		}
		cfg := c.ldap
		var found *ldap.Entry
		matched, ok := false, false
		err := s.withDirectory(ctx, c, true, func(cn *conn) error {
			entries, err := cn.search(cfg.UserBaseDN, scopeOf(cfg.UserScope), loginFilter(cfg, identifier), userAttributes(cfg), 2)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				return nil
			}
			matched = true
			if len(entries) > 1 || disabled(cfg, entries[0]) {
				return nil // ambiguous or disabled: never guessed
			}
			if berr := cn.bind(entries[0].DN, password); berr != nil {
				if _, transport := isTransport(berr); transport {
					return berr
				}
				return nil
			}
			found, ok = entries[0], true
			return nil
		})
		if err != nil {
			s.m.binds.Inc("unavailable")
			return nil, unavailable("a directory is unavailable; retry later")
		}
		if !matched {
			continue
		}
		if !ok {
			s.m.binds.Inc("invalid_credentials")
			return nil, nil
		}
		s.m.binds.Inc("success")
		r := newRunCtx("", false, false)
		r.jit = true
		sp, err := tx.Begin(ctx)
		if err != nil {
			return nil, err
		}
		userID, err := s.applyEntry(ctx, sp, r, c, readEntry(cfg, found))
		if err != nil {
			_ = sp.Rollback(ctx)
			return nil, err
		}
		if userID == "" {
			// The entry conflicts with an existing account: sign-in does not
			// merge identities (FED-005); the conflict is evidence.
			_ = sp.Rollback(ctx)
			reason := ""
			for _, f := range r.items {
				reason = f.Reason
			}
			_, _ = s.d.Audit.Record(context.WithoutCancel(ctx), s.d.DB.Pool, audit.Event{Type: "directory.user.jit_refused", RealmID: c.RealmID,
				OrgID: c.OrganizationID, Actor: c.Ref(), Target: &audit.Ref{Type: "connector", ID: c.ID}, Category: "account", Outcome: audit.Denied,
				ReasonCode: strings.ToUpper(reason)})
			return nil, nil
		}
		if err := sp.Commit(ctx); err != nil {
			return nil, err
		}
		return s.Users.User(ctx, tx, realmID, userID)
	}
	return nil, nil
}
