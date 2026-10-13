package worker

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/proudbase/proudauth/internal/identity"
)

var importLocale = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$`)

// validateImportProfile checks the profile, state, required actions and
// administrator metadata an import record sets (MIG-001, MIG-003): only states
// that are no more permissive than active, supported required actions the
// requester may set (perms, AUT-018) and bounded metadata.
func validateImportProfile(rec identity.ImportRecord, perms map[string]bool, metadataBytes int) error {
	if !identity.ImportStates[rec.State] {
		return fmt.Errorf("state must be active or suspended")
	}
	seen := map[string]bool{}
	for _, a := range rec.RequiredActions {
		if !identity.ValidRequiredAction(a) {
			return fmt.Errorf("unsupported required action %q", a)
		}
		if seen[a] {
			return fmt.Errorf("required action %q repeats", a)
		}
		seen[a] = true
		if p := identity.RequiredActionPermission(a); p != "" && !perms[p] {
			return fmt.Errorf("required action %s requires %s", a, p)
		}
	}
	if len(rec.GivenName) > 100 || len(rec.FamilyName) > 100 {
		return fmt.Errorf("given_name and family_name are at most 100 bytes")
	}
	if rec.Locale != "" && !importLocale.MatchString(rec.Locale) {
		return fmt.Errorf("locale must be a BCP 47 language tag such as en or pt-BR")
	}
	if len(rec.AdminMetadata) > 0 {
		if b, err := json.Marshal(rec.AdminMetadata); err != nil || len(b) > metadataBytes {
			return fmt.Errorf("admin_metadata exceeds %d bytes (limits.metadata_bytes)", metadataBytes)
		}
	}
	return nil
}
