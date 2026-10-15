// Package migrate converts the exports of other identity systems into
// ProudAuth import documents (MIG-018): Keycloak realm exports, ZITADEL admin
// API exports and SuperTokens exports become proudauth.user-import.v1 records,
// organizations to create and memberships with role assignments translated
// through an explicit, reviewed mapping (MIG-005). Every conversion produces a
// capability report that counts, per entity type, what converted, what
// converted with loss (and what was lost) and what is unsupported, so nothing
// is dropped silently.
//
// The package is pure: it reads export bytes and writes documents. Applying
// them goes through the authenticated import APIs (identity-cli
// migrate-from), so the same permission checks, ceilings, idempotency
// (import_mappings keyed by source system and source ID) and audit apply as
// for any other import.
package migrate

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/canonical"
)

// Source products.
const (
	Keycloak    = "keycloak"
	Zitadel     = "zitadel"
	SuperTokens = "supertokens"
)

// Adapter describes one supported source (MIG-002): the product, the versions
// it accepts and was tested with, how to produce the export and what carries
// over.
type Adapter struct {
	Source            string   `json:"source"`
	Product           string   `json:"product"`
	SupportedVersions string   `json:"supported_versions"`
	TestedVersions    []string `json:"tested_versions"`
	ExportFormat      string   `json:"export_format"`
	ExportCommand     string   `json:"export_command"`
	Converts          []string `json:"converts"`
	ConvertsWithLoss  []string `json:"converts_with_loss"`
	Unsupported       []string `json:"unsupported"`
	// version reports whether a source version is supported.
	version func(v string) bool
}

// Adapters lists the first-party adapters of this release.
var Adapters = []Adapter{
	{
		Source: Keycloak, Product: "Keycloak", SupportedVersions: "26.x", TestedVersions: []string{"26.8.0"},
		ExportFormat:  "Keycloak realm export JSON with users (RealmRepresentation; keycloakVersion member)",
		ExportCommand: "kc.sh export --file <realm>-realm.json --realm <realm> --users same_file (or --dir <dir> --users different_files; pass every file)",
		Converts: []string{"users (username, email, verification flag, names, enabled state)", "password credentials: argon2 (argon2id, v1.3) and pbkdf2, pbkdf2-sha256, pbkdf2-sha512 within the accepted bounds",
			"OTP credentials: TOTP, HmacSHA1, 6 digits, 30 s (with explicit authorization)", "required actions UPDATE_PASSWORD, VERIFY_EMAIL, CONFIGURE_TOTP, TERMS_AND_CONDITIONS, UPDATE_PROFILE, VERIFY_PROFILE",
			"organizations (Keycloak 26 organizations) and their members", "realm roles, client roles and groups through the reviewed mapping"},
		ConvertsWithLoss: []string{"user attributes (kept as administrator metadata only with --keep-attributes)", "groups mapped as organizations (hierarchy flattened)"},
		Unsupported: []string{"argon2 types i and d, version 1.0, and parameters above the ceiling; PBKDF2 below 10,000 iterations (password reset required)",
			"FIPS padded PBKDF2 verifiers (the padding length is server configuration, not exported)", "HOTP and non-SHA-1, 8-digit or 60-second OTP (re-enrollment)",
			"WebAuthn and passkey credentials (re-enrollment)", "recovery codes", "identity provider links (users link again)", "service-account users",
			"users backed by user federation (LDAP, Kerberos)", "clients and client secrets", "identity providers and their secrets", "authentication flows, password and OTP policies",
			"sessions, offline tokens and consents"},
		version: func(v string) bool { return major(v) == 26 },
	},
	{
		Source: Zitadel, Product: "ZITADEL", SupportedVersions: "v4.x", TestedVersions: []string{"v4.16.3"},
		ExportFormat:  "ZITADEL admin API v1 data export (ExportDataResponse JSON: orgs[] with humanUsers, machineUsers, userMetadata, userLinks, orgMembers, projects, projectRoles, userGrants)",
		ExportCommand: `POST /admin/v1/export {"withPasswords": true, "withOtp": true, "responseOutput": true, "timeout": "60s"} with an IAM_OWNER token; pass the ZITADEL version with --source-version`,
		Converts: []string{"organizations", "human users (user name, email, verification flag, names, preferred language, state)", "password hashes: bcrypt and argon2id, and PBKDF2 (passlib form) within the accepted bounds",
			"TOTP secrets (with explicit authorization)", "organization members and project role grants through the reviewed mapping"},
		ConvertsWithLoss: []string{"user metadata (kept as administrator metadata only with --keep-attributes)", "locked users (imported suspended)"},
		Unsupported: []string{"md5crypt, sha-crypt, scrypt, argon2i and other hash formats (password reset required)", "machine users and their keys", "identity provider links (users link again)",
			"phone numbers", "passkeys, U2F and OTP via SMS or email (re-enrollment)", "projects, applications and client secrets", "instance members and policies", "deleted users",
			"sessions and tokens (users sign in again)"},
		version: func(v string) bool { return major(v) == 4 },
	},
	{
		Source: SuperTokens, Product: "SuperTokens core (PostgreSQL plugin)", SupportedVersions: "core 12.x", TestedVersions: []string{"12.0.7 (plugin postgresql 9.5.5, CDI 5.4)"},
		ExportFormat: "proudauth.supertokens-export.v1: the SuperTokens bulk-import user shape (externalUserId, userMetadata, userRoles, totpDevices, loginMethods) produced read-only from the core database " +
			"with identity-cli migrate-from supertokens --print-export-sql; the core API user list (GET /users, without password hashes) is also accepted",
		ExportCommand: "identity-cli migrate-from supertokens --print-export-sql > export.sql; psql \"$SUPERTOKENS_DB\" -X -A -t -q -v app_id=public -v core_version=12.0.7 -f export.sql > supertokens-export.json",
		Converts: []string{"users (primary users with linked login methods)", "emailpassword: bcrypt and argon2id hashes within the accepted bounds", "email verification",
			"TOTP devices (30 s; first compatible device; with explicit authorization)", "tenants as organizations and user roles through the reviewed mapping"},
		ConvertsWithLoss: []string{"user metadata (kept as administrator metadata only with --keep-attributes)", "users with several emails (first email kept)"},
		Unsupported: []string{"FIREBASE_SCRYPT hashes (password reset required)", "thirdparty links (users link again)", "passwordless phone numbers", "WebAuthn credentials",
			"role permissions (roles are translated by name)", "sessions"},
		version: func(v string) bool { return major(strings.TrimPrefix(v, "core ")) == 12 },
	},
}

// LookupAdapter returns the adapter of a source.
func LookupAdapter(source string) (*Adapter, bool) {
	for i := range Adapters {
		if Adapters[i].Source == source {
			return &Adapters[i], true
		}
	}
	return nil, false
}

// versionMatches reports whether a version given for an export that states
// its own version names that version: the same version or a leading part of
// it, such as the major version ("26" or "26.8" for "26.8.0", "v4" for
// "v4.16.3", "12" for SuperTokens core "12.0.7"). A leading "v" or "core "
// and a trailing ".x" ("26.x") are ignored.
func versionMatches(given, stated string) bool {
	g, s := strings.TrimSuffix(normVersion(given), ".x"), normVersion(stated)
	return g != "" && (g == s || strings.HasPrefix(s, g+"."))
}

func normVersion(v string) string {
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "core "), "v")
}

func major(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	m, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(m)
	if err != nil {
		return -1
	}
	return n
}

// MappingFormat names the reviewed translation document.
const MappingFormat = "proudauth.migration-mapping.v1"

// Mapping is the reviewed translation from source organizations and roles to
// ProudAuth organizations and organization roles (MIG-005). Nothing grants
// access unless it is listed here: an unlisted source role is reported as
// unsupported, never translated by name.
type Mapping struct {
	Format string `json:"format"`
	// Organizations maps a source organization key (Keycloak "org:<alias>"
	// or "group:<path>", ZITADEL "org:<id>", SuperTokens "tenant:<id>") to
	// the organization it becomes; null excludes it. Keycloak organizations,
	// ZITADEL organizations and SuperTokens tenants other than public
	// become organizations by default; Keycloak groups only when listed.
	Organizations map[string]*OrgTarget `json:"organizations,omitempty"`
	// MembershipRoles are given to every membership created.
	MembershipRoles []string `json:"membership_roles,omitempty"`
	// Roles maps a source role key (Keycloak "realm-role:<name>",
	// "client-role:<client>:<role>" or "group:<path>", ZITADEL
	// "org-member:<ROLE>" or "project-role:<project id>:<key>", SuperTokens
	// "role:<name>") to organization roles; null or an empty list carries no
	// roles.
	Roles map[string]*RoleTarget `json:"roles,omitempty"`
}

// OrgTarget is the organization a source organization becomes.
type OrgTarget struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name,omitempty"`
	Note        string `json:"note,omitempty"`
}

// RoleTarget lists the organization roles a source role becomes. Without
// Organization they apply in the source grant's own scope: the user's
// organizations (Keycloak roles and groups), the user's organization (ZITADEL
// project roles), the organization the member entry belongs to (ZITADEL
// organization members) or the role's tenants (SuperTokens).
type RoleTarget struct {
	Organization string   `json:"organization,omitempty"`
	Roles        []string `json:"roles"`
	Note         string   `json:"note,omitempty"`
}

// ParseMapping decodes a mapping document strictly.
func ParseMapping(b []byte) (*Mapping, error) {
	var m Mapping
	if err := decodeStrict(b, &m); err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	if m.Format != "" && m.Format != MappingFormat {
		return nil, fmt.Errorf("mapping: format must be %s", MappingFormat)
	}
	for k, t := range m.Organizations {
		if t != nil {
			if c, ok := canonical.Slug(t.Slug); !ok || c != t.Slug {
				return nil, fmt.Errorf("mapping: organizations[%q].slug must be 2-63 lowercase letters, digits or dashes", k)
			}
		}
	}
	for k, t := range m.Roles {
		if t == nil {
			continue
		}
		for _, r := range t.Roles {
			if strings.TrimSpace(r) == "" {
				return nil, fmt.Errorf("mapping: roles[%q] lists an empty role name", k)
			}
		}
	}
	return &m, nil
}

// Options control a conversion.
type Options struct {
	// SourceSystem qualifies every source ID (import_mappings, MIG-004).
	// Defaults to "<source>-<realm or app>".
	SourceSystem string
	// SourceVersion is required when the export does not state its version
	// (ZITADEL, the SuperTokens core API list). When the export states one,
	// SourceVersion must name it: the same version or a leading part of it,
	// such as the major version ("26" or "26.8" for "26.8.0").
	SourceVersion string
	Mapping       *Mapping
	// KeepAttributes keeps source attributes and metadata as
	// administrator-only metadata; otherwise they are reported as dropped.
	KeepAttributes bool
	// ImportTOTP carries compatible TOTP seeds over (MIG-007); otherwise the
	// factor is reported and the account must enroll again.
	ImportTOTP bool
	// Now stamps the report (defaults to the current time).
	Now func() time.Time
}

// TargetOrganization is an organization the import needs.
type TargetOrganization struct {
	SourceKey   string `json:"source_key"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	// ExternalID ("<source_system>:<source key with the immutable ID>")
	// identifies the organization across runs: an existing organization
	// with this external ID is reused, so re-running never duplicates it.
	ExternalID string `json:"external_id"`
	// FromMapping is true when the reviewed mapping names the target;
	// such an organization may already exist under its slug.
	FromMapping bool `json:"from_mapping"`
	Members     int  `json:"members"`
}

// Result is a converted export.
type Result struct {
	Source        SourceInfo              `json:"source"`
	SourceSystem  string                  `json:"source_system"`
	Organizations []TargetOrganization    `json:"organizations"`
	Users         []identity.ImportRecord `json:"users"`
	Report        *Report                 `json:"report"`
}

// SourceInfo identifies the export.
type SourceInfo struct {
	Product        string   `json:"product"`
	Source         string   `json:"source"`
	Version        string   `json:"version"`
	TestedVersions []string `json:"tested_versions"`
	Realm          string   `json:"realm,omitempty"`
}

// ErrUnsupportedVersion reports a source version outside the adapter's range.
var ErrUnsupportedVersion = errors.New("unsupported source version")

// Convert parses export documents of one source and converts them. Several
// documents are merged (a Keycloak directory export writes the realm and its
// users to separate files).
func Convert(source string, docs [][]byte, opts Options) (*Result, error) {
	ad, ok := LookupAdapter(source)
	if !ok {
		return nil, fmt.Errorf("unknown source %q (keycloak, zitadel or supertokens)", source)
	}
	if len(docs) == 0 {
		return nil, errors.New("no export document")
	}
	var sd *sourceData
	var err error
	switch source {
	case Keycloak:
		sd, err = parseKeycloak(docs)
	case Zitadel:
		sd, err = parseZitadel(docs)
	case SuperTokens:
		sd, err = parseSuperTokens(docs)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case sd.version == "" && opts.SourceVersion == "":
		return nil, fmt.Errorf("%w: the export does not state the %s version; pass it explicitly (supported %s)", ErrUnsupportedVersion, ad.Product, ad.SupportedVersions)
	case sd.version == "":
		sd.version = opts.SourceVersion
	}
	if !ad.version(sd.version) {
		return nil, fmt.Errorf("%w: %s %s; this release supports %s (tested: %s)", ErrUnsupportedVersion, ad.Product, sd.version,
			ad.SupportedVersions, strings.Join(ad.TestedVersions, ", "))
	}
	if opts.SourceVersion != "" && !versionMatches(opts.SourceVersion, sd.version) {
		m, _, _ := strings.Cut(normVersion(sd.version), ".")
		return nil, fmt.Errorf("%w: the export states %s version %s but %s was given; give %s or its major version %s, or leave the source version out",
			ErrUnsupportedVersion, ad.Product, sd.version, opts.SourceVersion, sd.version, m)
	}
	if opts.SourceSystem == "" {
		opts.SourceSystem = defaultSourceSystem(source, sd.scope)
	}
	if !identity.ValidSourceSystem(opts.SourceSystem) {
		return nil, fmt.Errorf("source system %q: lowercase letters, digits, '.', '_' or '-', at most 63 characters", opts.SourceSystem)
	}
	if opts.Mapping == nil {
		opts.Mapping = &Mapping{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	info := SourceInfo{Product: ad.Product, Source: source, Version: sd.version, TestedVersions: ad.TestedVersions, Realm: sd.scope}
	return translate(sd, info, opts), nil
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

func defaultSourceSystem(source, scope string) string {
	s := source
	if scope != "" {
		s += "-" + strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(scope), "-"), "-")
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.TrimRight(s, "-")
}

// slugOf derives an organization slug from a source name.
func slugOf(name string) (string, bool) {
	s := strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-"), "-")
	if len(s) > 63 {
		s = strings.TrimRight(s[:63], "-")
	}
	if len(s) < 2 {
		return "", false
	}
	return s, true
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

func uniq(in []string) []string {
	out := []string{}
	for _, s := range in {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
