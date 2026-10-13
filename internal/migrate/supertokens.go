package migrate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SuperTokensExportSQL is the read-only query that writes the
// proudauth.supertokens-export.v1 document from a SuperTokens core database
// (PostgreSQL plugin): SuperTokens has no export API that includes password
// hashes, TOTP devices, roles and metadata.
//
//go:embed supertokens_export.sql
var SuperTokensExportSQL string

// SuperTokensExportFormat names the export document.
const SuperTokensExportFormat = "proudauth.supertokens-export.v1"

type stExport struct {
	Format      string `json:"format"`
	SuperTokens *struct {
		CoreVersion string `json:"core_version"`
		AppID       string `json:"app_id"`
	} `json:"supertokens"`
	Tenants []struct {
		TenantID string `json:"tenantId"`
	} `json:"tenants"`
	Roles []struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	} `json:"roles"`
	Users  []stUser `json:"users"`
	Status string   `json:"status"`
}

// stUser is a SuperTokens bulk-import user (plus supertokensUserId), or a
// user of the core API's GET /users.
type stUser struct {
	// bulk-import shape
	SuperTokensUserID string          `json:"supertokensUserId"`
	ExternalUserID    string          `json:"externalUserId"`
	UserMetadata      map[string]any  `json:"userMetadata"`
	UserRoles         []stRole        `json:"userRoles"`
	TOTPDevices       []stTOTP        `json:"totpDevices"`
	LoginMethods      []stLoginMethod `json:"loginMethods"`
	// core API shape
	ID string `json:"id"`
}

type stRole struct {
	Role      string   `json:"role"`
	TenantIDs []string `json:"tenantIds"`
}

type stTOTP struct {
	SecretKey  string `json:"secretKey"`
	Period     int    `json:"period"`
	DeviceName string `json:"deviceName"`
}

type stLoginMethod struct {
	RecipeID         string   `json:"recipeId"`
	TenantIDs        []string `json:"tenantIds"`
	IsPrimary        bool     `json:"isPrimary"`
	IsVerified       *bool    `json:"isVerified"`
	Verified         *bool    `json:"verified"`
	TimeJoined       int64    `json:"timeJoinedInMSSinceEpoch"`
	Email            string   `json:"email"`
	PasswordHash     string   `json:"passwordHash"`
	HashingAlgorithm string   `json:"hashingAlgorithm"`
	ThirdPartyID     string   `json:"thirdPartyId"`
	ThirdPartyUserID string   `json:"thirdPartyUserId"`
	PhoneNumber      string   `json:"phoneNumber"`
	WebAuthnCredIDs  []string `json:"webauthnCredentialIds"`
	// core API shape
	RecipeUserID string `json:"recipeUserId"`
	ThirdParty   *struct {
		ID     string `json:"id"`
		UserID string `json:"userId"`
	} `json:"thirdParty"`
}

func parseSuperTokens(docs [][]byte) (*sourceData, error) {
	sd := &sourceData{roleNotes: map[string]string{}}
	tenants := map[string]bool{}
	coreAPI := false
	for i, b := range docs {
		var e stExport
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("supertokens export %d: %w", i+1, err)
		}
		if e.Format != "" && e.Format != SuperTokensExportFormat {
			return nil, fmt.Errorf("supertokens export %d: format %q is not %s", i+1, e.Format, SuperTokensExportFormat)
		}
		if e.Users == nil {
			return nil, fmt.Errorf("supertokens export %d: no users member (expected %s or a GET /users response)", i+1, SuperTokensExportFormat)
		}
		if e.SuperTokens != nil {
			if sd.version != "" && sd.version != e.SuperTokens.CoreVersion {
				return nil, fmt.Errorf("supertokens export %d: core version %s differs from %s", i+1, e.SuperTokens.CoreVersion, sd.version)
			}
			sd.version, sd.scope = e.SuperTokens.CoreVersion, firstNonEmpty(e.SuperTokens.AppID, "public")
		}
		for _, t := range e.Tenants {
			tenants[t.TenantID] = true
		}
		for _, r := range e.Roles {
			perms := "no permissions"
			if len(r.Permissions) > 0 {
				perms = "permissions " + strings.Join(r.Permissions, ", ")
			}
			sd.roleNotes["role:"+r.Role] = fmt.Sprintf("SuperTokens role %s (%s; permissions are not migrated, the translation decides what the role allows)", r.Role, perms)
		}
		for j := range e.Users {
			u, api := stConvertUser(&e.Users[j])
			coreAPI = coreAPI || api
			for _, k := range u.orgs {
				tenants[strings.TrimPrefix(k, "tenant:")] = true
			}
			sd.users = append(sd.users, u)
		}
	}
	if sd.scope == "" {
		sd.scope = "public"
	}
	ids := make([]string, 0, len(tenants))
	for t := range tenants {
		ids = append(ids, t)
	}
	sort.Strings(ids)
	for _, t := range ids {
		slug, _ := slugOf(t)
		so := &srcOrg{key: "tenant:" + t, id: t, name: t, slug: slug, defaultOn: t != "public", entity: "tenants"}
		if t == "public" {
			so.notOrgReason = "the public tenant is the default tenant, not an organization (map tenant:public to make it one)"
		}
		sd.orgs = append(sd.orgs, so)
	}
	if coreAPI {
		sd.notes = append(sd.notes, "The core API user list carries no password hashes, TOTP devices, roles or metadata: use the export SQL (identity-cli migrate-from supertokens --print-export-sql) to carry them over.")
	}
	sd.other = append(sd.other, otherEntity{entity: "sessions", id: "sessions", outcome: Unsupported,
		reasons: []string{"sessions are not exported and never portable across issuers; users sign in again (MIG-010)"}})
	return sd, nil
}

// stConvertUser converts one SuperTokens user; api reports the core API shape.
func stConvertUser(su *stUser) (*srcUser, bool) {
	api := su.ID != ""
	u := &srcUser{id: firstNonEmpty(su.ExternalUserID, su.ID, su.SuperTokensUserID)}
	if u.id == "" {
		u.unsupported = "no SuperTokens user ID (add supertokensUserId or externalUserId to the record)"
	}
	if len(su.UserMetadata) > 0 {
		u.attrs = su.UserMetadata
	}
	methods := append([]stLoginMethod{}, su.LoginMethods...)
	// The primary login method first, then by join time.
	sort.SliceStable(methods, func(i, j int) bool {
		if methods[i].IsPrimary != methods[j].IsPrimary {
			return methods[i].IsPrimary
		}
		return methods[i].TimeJoined < methods[j].TimeJoined
	})
	var emails []string
	verified := map[string]bool{}
	tenantSet := map[string]bool{}
	for _, m := range methods {
		for _, t := range m.TenantIDs {
			tenantSet[t] = true
		}
		if m.RecipeUserID != "" {
			api = true
		}
		if m.Email != "" {
			e := strings.ToLower(strings.TrimSpace(m.Email))
			if !containsStr(emails, e) {
				emails = append(emails, e)
			}
			if (m.IsVerified != nil && *m.IsVerified) || (m.Verified != nil && *m.Verified) {
				verified[e] = true
			}
		}
		switch m.RecipeID {
		case "emailpassword":
			if u.password != nil {
				u.losses = append(u.losses, "an additional emailpassword login method was not migrated")
				continue
			}
			u.password = stPassword(m, api)
		case "thirdparty":
			id, uid := m.ThirdPartyID, m.ThirdPartyUserID
			if m.ThirdParty != nil {
				id, uid = m.ThirdParty.ID, m.ThirdParty.UserID
			}
			u.links = append(u.links, id+":"+uid)
		case "passwordless":
			if m.PhoneNumber != "" {
				u.phones = append(u.phones, m.PhoneNumber)
			}
		case "webauthn":
			n := len(m.WebAuthnCredIDs)
			if n == 0 {
				n = 1
			}
			for i := 0; i < n; i++ {
				u.webauthn = append(u.webauthn, "webauthn")
			}
		default:
			u.otherCreds = append(u.otherCreds, "SuperTokens login method "+m.RecipeID)
		}
	}
	// Prefer the email of the password login method.
	if u.password != nil {
		for _, m := range methods {
			if m.RecipeID == "emailpassword" && m.Email != "" {
				e := strings.ToLower(strings.TrimSpace(m.Email))
				emails = append([]string{e}, removeStr(emails, e)...)
				break
			}
		}
	}
	if len(emails) > 0 {
		u.email, u.emailVerified = emails[0], verified[emails[0]]
		if len(emails) > 1 {
			u.losses = append(u.losses, fmt.Sprintf("%d additional email address(es) of linked login methods not migrated", len(emails)-1))
		}
	}
	for t := range tenantSet {
		u.orgs = append(u.orgs, "tenant:"+t)
	}
	sort.Strings(u.orgs)
	for _, r := range su.UserRoles {
		var scope []string
		for _, t := range r.TenantIDs {
			scope = append(scope, "tenant:"+t)
		}
		u.grants = append(u.grants, srcGrant{key: "role:" + r.Role, orgs: scope})
	}
	for _, d := range su.TOTPDevices {
		t := srcTOTP{label: d.DeviceName, seed: strings.ToUpper(strings.TrimRight(d.SecretKey, "="))}
		if d.Period != 0 && d.Period != 30 {
			t.problem = fmt.Sprintf("TOTP period %d s is not supported (30 s only)", d.Period)
		}
		u.totp = append(u.totp, t)
	}
	return u, api
}

// stPassword converts a SuperTokens password hash.
func stPassword(m stLoginMethod, api bool) *srcPassword {
	if m.PasswordHash == "" {
		if api {
			return &srcPassword{algorithm: "emailpassword", problem: "the core API does not export password hashes"}
		}
		return &srcPassword{algorithm: "emailpassword", problem: "no password hash in the export"}
	}
	h := m.PasswordHash
	alg := strings.ToUpper(m.HashingAlgorithm)
	switch {
	case strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$"):
		return &srcPassword{algorithm: "BCRYPT" + bcryptCost(h), hash: h}
	case strings.HasPrefix(h, "$argon2id$"):
		return &srcPassword{algorithm: "ARGON2 (argon2id)", hash: h}
	case strings.HasPrefix(h, "$argon2i$") || strings.HasPrefix(h, "$argon2d$"):
		return &srcPassword{algorithm: "ARGON2 (" + strings.Split(h, "$")[1] + ")", problem: strings.Split(h, "$")[1] + " is not supported (argon2id only)"}
	case strings.HasPrefix(h, "$f_scrypt$") || alg == "FIREBASE_SCRYPT":
		return &srcPassword{algorithm: "FIREBASE_SCRYPT", problem: "Firebase scrypt hashes depend on the Firebase project's signer key and are not an accepted import format"}
	}
	return &srcPassword{algorithm: firstNonEmpty(alg, "unknown"), problem: "unrecognized password hash format"}
}

func removeStr(list []string, s string) []string {
	out := list[:0:0]
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
