package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// Declared authorities of an account's attributes and operations (USR-022).
const (
	// Locally editable through the self-service and administration APIs.
	DeclLocal = "local"
	// Externally managed: the API refuses local changes.
	DeclExternal = "externally_managed"
	// Editable locally, written to the directory first (PROV-013).
	DeclWriteBack = "write_back"
)

// Authority is an account's attribute authority declaration (USR-022).
type Authority struct {
	Source     *AuthoritySource  `json:"source"`
	Attributes map[string]string `json:"attributes"`
	Operations map[string]string `json:"operations"`
}

// AuthoritySource names the directory that sources an account.
type AuthoritySource struct {
	Type           string `json:"type"`
	ConnectorID    string `json:"connector_id"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
	Mode           string `json:"mode"`
	State          string `json:"state"`
}

// declarable are the attributes every declaration lists.
var declarable = []string{"username", "email", "phone", "display_name", "given_name", "family_name", "locale", "zoneinfo"}

// Declare reports which attributes and operations of an account are locally
// editable, externally managed or written back (USR-022).
func (s *Service) Declare(ctx context.Context, realmID, userID string) (*Authority, error) {
	out := &Authority{Attributes: map[string]string{}, Operations: map[string]string{}}
	for _, a := range declarable {
		out.Attributes[a] = DeclLocal
	}
	out.Operations["password_change"] = DeclLocal
	out.Operations["password_reset"] = DeclLocal
	out.Operations["reactivation"] = DeclLocal
	if s == nil {
		return out, nil
	}
	if _, err := s.Users.User(ctx, nil, realmID, userID); err != nil {
		return nil, err
	}
	l, c, err := s.linkForUser(ctx, nil, userID)
	if err != nil || l == nil {
		return out, err
	}
	out.Source = &AuthoritySource{Type: "directory", ConnectorID: c.ID, Name: c.Name, OrganizationID: c.OrganizationID, Mode: c.ldap.Mode, State: l.SourceState}
	// Passwords of directory-sourced accounts are verified by the directory
	// and changed there; password write-back is not offered (PROV-013).
	out.Operations["password_change"] = DeclExternal
	out.Operations["password_reset"] = DeclExternal
	u, err := s.Users.User(ctx, nil, realmID, userID)
	if err != nil {
		return nil, err
	}
	if !s.managesIdentity(ctx, s.d.DB.Pool, c, viewOf(u)) {
		return out, nil
	}
	for attr := range c.ldap.AttributeMapping {
		switch c.ldap.authority(attr) {
		case AuthorityDirectory:
			out.Attributes[attr] = DeclExternal
		case AuthorityWriteBack:
			out.Attributes[attr] = DeclWriteBack
		default:
			out.Attributes[attr] = DeclLocal
		}
	}
	if c.OrganizationID == "" && (l.SourceState == "disabled" || l.SourceState == "missing") {
		out.Operations["reactivation"] = DeclExternal
	}
	return out, nil
}

// CheckEdit implements identity.AttributeAuthority: it refuses local
// changes to attributes a directory manages, with an error naming them, and
// writes permitted write-back attributes to the directory before the local
// change commits (USR-022, PROV-013). The owning directory's own
// synchronization is not checked (identity.WithExternalWriter).
func (s *Service) CheckEdit(ctx context.Context, tx pgx.Tx, realmID, userID string, changes map[string]any) error {
	if s == nil || len(changes) == 0 || identity.IsExternalWriter(ctx) {
		return nil
	}
	l, c, err := s.linkForUser(ctx, tx, userID)
	if err != nil || l == nil {
		return err
	}
	refused := []string{}
	if _, ok := changes["password"]; ok {
		refused = append(refused, "password")
	}
	if v, ok := changes["state"]; ok && v == identity.StateActive && c.OrganizationID == "" && (l.SourceState == "disabled" || l.SourceState == "missing") {
		// The directory disabled or removed the account: reactivating it
		// locally would silently diverge until the next run reverted it.
		refused = append(refused, "state")
	}
	// Identifier edits arrive without a realm; the link's connector names it.
	u, err := s.Users.User(ctx, tx, c.RealmID, userID)
	if err != nil {
		return err
	}
	manages := s.managesIdentity(ctx, tx, c, viewOf(u))
	writeBack := map[string]string{}
	for attr, v := range changes {
		if attr == "password" || attr == "state" || !manages {
			continue
		}
		switch c.ldap.authority(attr) {
		case AuthorityDirectory:
			refused = append(refused, attr)
		case AuthorityWriteBack:
			writeBack[attr] = valueString(v)
		}
	}
	if len(refused) > 0 {
		sort.Strings(refused)
		pe := problem.ErrConflict.WithDetail(fmt.Sprintf("%s managed by the directory connector %q; change %s in the directory",
			strings.Join(refused, ", "), c.Name, map[bool]string{true: "it", false: "them"}[len(refused) == 1])).
			WithExtension("externally_managed", refused).WithExtension("connector_id", c.ID)
		for _, a := range refused {
			pe = pe.WithField(a, "externally managed")
		}
		return pe
	}
	if len(writeBack) == 0 {
		return nil
	}
	return s.writeBack(ctx, tx, c, l, writeBack)
}

func valueString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case *string:
		if x == nil {
			return ""
		}
		return *x
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// writeBack writes permitted attributes to the linked entry as the service
// account (PROV-013), then records them in the link snapshot so the next
// synchronization sees no change to apply. A refused or failed write refuses
// the local edit: the two sides never silently diverge.
func (s *Service) writeBack(ctx context.Context, tx pgx.Tx, c *Connector, l *link, values map[string]string) error {
	cfg := c.ldap
	if s.Disabled || c.State != "active" {
		return unavailable("the account's directory is disabled; the change cannot be written back")
	}
	attrs := sortedKeys(values)
	err := s.withDirectory(ctx, c, true, func(cn *conn) error {
		req := ldap.NewModifyRequest(l.DN, nil)
		for _, attr := range attrs {
			remote := cfg.AttributeMapping[attr]
			if values[attr] == "" {
				req.Replace(remote, []string{})
			} else {
				req.Replace(remote, []string{values[attr]})
			}
		}
		return cn.modify(req)
	})
	if err != nil {
		if _, transport := isTransport(err); transport || errors.Is(err, errUnavailable) {
			return unavailable("the account's directory is unavailable; the change was not made")
		}
		return problem.ErrConflict.WithDetail("the directory refused the change; it was not made locally either").WithExtension("connector_id", c.ID)
	}
	for _, attr := range attrs {
		l.Snapshot[attr] = values[attr]
		if values[attr] == "" {
			delete(l.Snapshot, attr)
		}
	}
	snap, _ := json.Marshal(l.Snapshot)
	if _, err := tx.Exec(ctx, `UPDATE connector_external_ids SET snapshot=$3, snapshot_digest=$4, updated_at=$5 WHERE connector_id=$1 AND resource_type='User'
		AND external_id=$2`, c.ID, l.ExternalID, snap, digest(l.Snapshot), s.d.Now()); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.user.written_back", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: audit.System,
		Subject: &audit.Ref{Type: "user", ID: l.UserID}, Target: &audit.Ref{Type: "connector", ID: c.ID}, Category: "account",
		Metadata: map[string]any{"attributes": attrs}})
	return err
}
