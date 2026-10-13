package identity

import (
	"context"
	"encoding/json"
	"reflect"

	"github.com/jackc/pgx/v5"
)

// AttributeAuthority decides who may change an account's attributes
// (USR-022, PROV-013). An external directory that sources an account
// implements it: CheckEdit runs inside the editing transaction with the
// attributes the edit changes ("display_name", "profile.<key>", "email",
// "username", "phone", "password", "state") and their new values, and
// returns an error naming every externally managed attribute, so a local
// edit is refused rather than silently diverging from the source. It may
// write permitted attributes back to the source before the edit commits.
type AttributeAuthority interface {
	CheckEdit(ctx context.Context, tx pgx.Tx, realmID, userID string, changes map[string]any) error
}

type externalWriterKey struct{}

// WithExternalWriter marks ctx as the owning external source applying its
// own data (a directory synchronization), which the authority check does not
// refuse.
func WithExternalWriter(ctx context.Context) context.Context {
	return context.WithValue(ctx, externalWriterKey{}, true)
}

// IsExternalWriter reports a context marked by WithExternalWriter.
func IsExternalWriter(ctx context.Context) bool {
	v, _ := ctx.Value(externalWriterKey{}).(bool)
	return v
}

// checkEdit consults the authority, if any, unless the owning source is the
// writer.
func (s *Service) checkEdit(ctx context.Context, tx pgx.Tx, realmID, userID string, changes map[string]any) error {
	if s.Authority == nil || len(changes) == 0 || IsExternalWriter(ctx) {
		return nil
	}
	return s.Authority.CheckEdit(ctx, tx, realmID, userID, changes)
}

// profileChanges lists the attributes a patch changes, with their new
// values; fields sent with their current value are not changes.
func profileChanges(u *User, p ProfilePatch) map[string]any {
	out := map[string]any{}
	str := func(name, cur string, v *string) {
		if v != nil && *v != cur {
			out[name] = *v
		}
	}
	str("display_name", u.DisplayName, p.DisplayName)
	str("given_name", u.GivenName, p.GivenName)
	str("family_name", u.FamilyName, p.FamilyName)
	str("locale", u.Locale, p.Locale)
	str("zoneinfo", u.Zoneinfo, p.Zoneinfo)
	for k, v := range p.Profile {
		if !sameJSON(u.Profile[k], v) {
			out["profile."+k] = v
		}
	}
	return out
}

func sameJSON(a, b any) bool {
	if reflect.DeepEqual(a, b) {
		return true
	}
	ja, err1 := json.Marshal(a)
	jb, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(ja) == string(jb)
}
