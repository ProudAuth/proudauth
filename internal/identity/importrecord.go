package identity

import "slices"

// ImportRecord is one user in an import batch (MIG-001).
type ImportRecord struct {
	SourceID      string `json:"source_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Username      string `json:"username"`
	DisplayName   string `json:"display_name"`
	PasswordHash  string `json:"password_hash"`
	// TOTPSecret is a base32 TOTP seed to carry over (MIG-007). It is
	// accepted only when the import explicitly authorizes factor import, and
	// is re-encrypted into this deployment's key hierarchy.
	TOTPSecret  string             `json:"totp_secret,omitempty"`
	Memberships []ImportMembership `json:"memberships"`
	// GivenName, FamilyName and Locale carry the source profile.
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Locale     string `json:"locale,omitempty"`
	// State is "active" (the default) or "suspended" for an account the
	// source had disabled: an import never creates a more permissive state
	// than the source's.
	State string `json:"state,omitempty"`
	// RequiredActions are obligations the account starts with (AUT-018),
	// such as update_password when the source's password verifier could not
	// be imported safely (MIG-006). Each needs the authority it needs on an
	// existing account (RequiredActionPermission).
	RequiredActions []string `json:"required_actions,omitempty"`
	// AdminMetadata is administrator-only metadata, such as source
	// attributes the operator chose to keep; users cannot edit it, so no
	// policy can be steered through it by the account holder.
	AdminMetadata map[string]any `json:"admin_metadata,omitempty"`
}

// ImportStates are the account states an import may create.
var ImportStates = map[string]bool{"": true, StateActive: true, StateSuspended: true}

// ImportPermissions returns the permissions, besides realm.users.import, that
// importing records needs: forcing a credential change or a contact
// verification needs the same authority as on an existing account (AUT-018).
func ImportPermissions(records []ImportRecord) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range records {
		for _, a := range r.RequiredActions {
			if p := RequiredActionPermission(a); p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	slices.Sort(out)
	return out
}

// ImportMembership maps a membership through an explicit role translation.
type ImportMembership struct {
	Organization string   `json:"organization"`
	Roles        []string `json:"roles"`
}

// ImportFormatV1 is the normalized user import format.
const ImportFormatV1 = "proudauth.user-import.v1"

// ImportFormat names a supported source format and what it can carry over
// (MIG-002). An import declares its format; compatibility is never inferred
// from the source system's name.
type ImportFormat struct {
	Format         string   `json:"format"`
	SourceProducts []string `json:"source_products"`
	Schema         string   `json:"schema"`
	Supports       []string `json:"supports"`
	Unsupported    []string `json:"unsupported"`
}

// ImportFormats lists the formats this release accepts.
var ImportFormats = []ImportFormat{{
	Format:         ImportFormatV1,
	SourceProducts: []string{"any source, after conversion to normalized records"},
	Schema:         "api/schemas/user-import.schema.json",
	Supports: []string{"stable source IDs", "email and username identifiers", "trusted email verification (explicit)",
		"Argon2id PHC password verifiers", "legacy salted SHA-256 verifiers (rehashed at sign-in)",
		"bcrypt (cost 10 to 15) and PBKDF2-HMAC-SHA1/SHA256/SHA512 (10,000 to 2,000,000 iterations) verifiers (rehashed at sign-in)",
		"TOTP seeds (SHA-1, 6 digits, 30 s; explicit authorization)", "organization memberships with explicit role translation",
		"given and family names, locale", "suspended state for accounts disabled in the source", "required actions (such as update_password)",
		"administrator-only metadata"},
	Unsupported: []string{"scrypt, MD5-crypt, SHA-crypt and other verifier formats, and bcrypt or PBKDF2 outside the cost bounds (users recover or reset)",
		"passkeys (re-enrollment; RP ID binding)", "recovery codes", "sessions and refresh tokens", "consents", "federated links", "phone identifiers"},
}}

// LookupImportFormat returns a supported format by name.
func LookupImportFormat(name string) (*ImportFormat, bool) {
	for i := range ImportFormats {
		if ImportFormats[i].Format == name {
			return &ImportFormats[i], true
		}
	}
	return nil, false
}
