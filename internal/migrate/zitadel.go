package migrate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/proudbase/proudauth/internal/credential"
	"github.com/proudbase/proudauth/internal/identity"
)

// ZITADEL admin API v1 data export (POST /admin/v1/export; ExportDataResponse).
// The import request shape {"dataOrgs": {"orgs": [...]}} is accepted too.
type ztExport struct {
	Orgs     []json.RawMessage `json:"orgs"`
	DataOrgs *struct {
		Orgs []json.RawMessage `json:"orgs"`
	} `json:"dataOrgs"`
}

type ztOrg struct {
	OrgID    string `json:"orgId"`
	OrgState string `json:"orgState"`
	Org      struct {
		Name string `json:"name"`
	} `json:"org"`
	Domains []struct {
		DomainName string `json:"domainName"`
		IsVerified bool   `json:"isVerified"`
	} `json:"domains"`
	Projects []struct {
		ProjectID string `json:"projectId"`
		Project   struct {
			Name string `json:"name"`
		} `json:"project"`
	} `json:"projects"`
	ProjectRoles []struct {
		ProjectID   string `json:"projectId"`
		RoleKey     string `json:"roleKey"`
		DisplayName string `json:"displayName"`
	} `json:"projectRoles"`
	HumanUsers []struct {
		UserID string `json:"userId"`
		State  string `json:"state"`
		User   struct {
			UserName string `json:"userName"`
			Profile  struct {
				FirstName         string `json:"firstName"`
				LastName          string `json:"lastName"`
				NickName          string `json:"nickName"`
				DisplayName       string `json:"displayName"`
				PreferredLanguage string `json:"preferredLanguage"`
				Gender            string `json:"gender"`
			} `json:"profile"`
			Email struct {
				Email           string `json:"email"`
				IsEmailVerified bool   `json:"isEmailVerified"`
			} `json:"email"`
			Phone struct {
				Phone string `json:"phone"`
			} `json:"phone"`
			Password       string `json:"password"`
			HashedPassword struct {
				Value string `json:"value"`
			} `json:"hashedPassword"`
			PasswordChangeRequired bool   `json:"passwordChangeRequired"`
			OTPCode                string `json:"otpCode"`
			IdPs                   []struct {
				ConfigID       string `json:"configId"`
				ExternalUserID string `json:"externalUserId"`
			} `json:"idps"`
		} `json:"user"`
	} `json:"humanUsers"`
	MachineUsers []struct {
		UserID string `json:"userId"`
		User   struct {
			UserName string `json:"userName"`
		} `json:"user"`
	} `json:"machineUsers"`
	UserMetadata []struct {
		ID    string `json:"id"`
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"userMetadata"`
	UserLinks []struct {
		UserID         string `json:"userId"`
		IdPID          string `json:"idpId"`
		IdPName        string `json:"idpName"`
		ProvidedUserID string `json:"providedUserId"`
	} `json:"userLinks"`
	OrgMembers []struct {
		UserID string   `json:"userId"`
		Roles  []string `json:"roles"`
	} `json:"orgMembers"`
	ProjectMembers []struct {
		ProjectID string   `json:"projectId"`
		UserID    string   `json:"userId"`
		Roles     []string `json:"roles"`
	} `json:"projectMembers"`
	UserGrants []struct {
		UserID    string   `json:"userId"`
		ProjectID string   `json:"projectId"`
		RoleKeys  []string `json:"roleKeys"`
	} `json:"userGrants"`
}

// ZITADEL user states and how they import.
var ztStates = map[string]struct {
	disabled bool
	note     string
	skip     bool
}{
	"USER_STATE_ACTIVE": {}, "USER_STATE_INITIAL": {}, "USER_STATE_UNSPECIFIED": {},
	"USER_STATE_INACTIVE": {disabled: true},
	"USER_STATE_LOCKED":   {disabled: true, note: "locked in the source; imported suspended (reactivate after review)"},
	"USER_STATE_SUSPEND":  {disabled: true},
	"USER_STATE_DELETED":  {skip: true},
}

func parseZitadel(docs [][]byte) (*sourceData, error) {
	sd := &sourceData{roleNotes: map[string]string{}}
	type orgDoc struct {
		typed ztOrg
		raw   map[string]json.RawMessage
	}
	var orgs []orgDoc
	for i, b := range docs {
		var e ztExport
		if err := json.Unmarshal(b, &e); err != nil {
			return nil, fmt.Errorf("zitadel export %d: %w", i+1, err)
		}
		list := e.Orgs
		if e.DataOrgs != nil {
			list = append(list, e.DataOrgs.Orgs...)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("zitadel export %d: no orgs (expected the admin API v1 export: {\"orgs\": [...]})", i+1)
		}
		for j, raw := range list {
			var od orgDoc
			if err := json.Unmarshal(raw, &od.typed); err != nil {
				return nil, fmt.Errorf("zitadel export %d, org %d: %w", i+1, j+1, err)
			}
			if od.typed.OrgID == "" {
				return nil, fmt.Errorf("zitadel export %d, org %d: orgId missing", i+1, j+1)
			}
			_ = json.Unmarshal(raw, &od.raw)
			orgs = append(orgs, od)
		}
	}

	users := map[string]*srcUser{}
	userOrg := map[string]string{}
	projects := map[string]string{} // project ID -> name (org)
	for _, od := range orgs {
		o := od.typed
		for _, p := range o.Projects {
			projects[p.ProjectID] = fmt.Sprintf("%s (org %s)", p.Project.Name, o.Org.Name)
		}
	}
	for _, od := range orgs {
		o := od.typed
		key := "org:" + o.OrgID
		slug, _ := slugOf(o.Org.Name)
		so := &srcOrg{key: key, id: o.OrgID, name: o.Org.Name, slug: slug, defaultOn: true, entity: "organizations"}
		if o.OrgState != "" && o.OrgState != "ORG_STATE_ACTIVE" {
			so.lossNotes = append(so.lossNotes, "organization state "+o.OrgState+" in the source; created active (suspend it after review)")
		}
		if len(o.Domains) > 0 {
			var ds []string
			for _, d := range o.Domains {
				ds = append(ds, fmt.Sprintf("%s (verified=%t)", d.DomainName, d.IsVerified))
			}
			so.lossNotes = append(so.lossNotes, "domains not migrated: "+strings.Join(ds, ", "))
		}
		sd.orgs = append(sd.orgs, so)
		for _, r := range o.ProjectRoles {
			sd.roleNotes["project-role:"+r.ProjectID+":"+r.RoleKey] = fmt.Sprintf("role %s (%s) of project %s", r.RoleKey, r.DisplayName, projects[r.ProjectID])
		}
		for _, hu := range o.HumanUsers {
			pr := hu.User.Profile
			u := &srcUser{id: hu.UserID, username: hu.User.UserName, email: hu.User.Email.Email, emailVerified: hu.User.Email.IsEmailVerified,
				given: pr.FirstName, family: pr.LastName, display: pr.DisplayName, locale: pr.PreferredLanguage, orgs: []string{key}}
			st, known := ztStates[hu.State]
			switch {
			case hu.State != "" && !known:
				u.stateNote = "unknown state " + hu.State + "; imported suspended"
				u.disabled = true
			case st.skip:
				u.unsupported = "deleted in the source"
			default:
				u.disabled, u.stateNote = st.disabled, st.note
			}
			if pr.NickName != "" || (pr.Gender != "" && pr.Gender != "GENDER_UNSPECIFIED") {
				u.losses = append(u.losses, "nick name and gender not migrated")
			}
			switch {
			case hu.User.HashedPassword.Value != "":
				u.password = ztPassword(hu.User.HashedPassword.Value)
			case hu.User.Password != "":
				u.password = &srcPassword{algorithm: "plaintext", problem: "plaintext passwords are never imported (MIG-006)"}
			}
			if hu.User.PasswordChangeRequired {
				u.actions = append(u.actions, identity.ActionUpdatePassword)
			}
			if hu.User.OTPCode != "" {
				// ZITADEL TOTP is SHA-1, 6 digits, 30 seconds; the
				// export carries the base32 secret.
				u.totp = append(u.totp, srcTOTP{label: "authenticator app", seed: strings.ToUpper(hu.User.OTPCode)})
			}
			if hu.User.Phone.Phone != "" {
				u.phones = append(u.phones, hu.User.Phone.Phone)
			}
			for _, idp := range hu.User.IdPs {
				u.links = append(u.links, idp.ConfigID+":"+idp.ExternalUserID)
			}
			users[hu.UserID] = u
			userOrg[hu.UserID] = key
			sd.users = append(sd.users, u)
		}
		for _, mu := range o.MachineUsers {
			sd.users = append(sd.users, &srcUser{id: mu.UserID, machine: "ZITADEL machine user " + mu.User.UserName +
				" (service principals are created in ProudAuth; machine keys and personal access tokens cannot be migrated)"})
		}
	}
	// Relations may reference users of other organizations, so they are
	// resolved once every user is known.
	for _, od := range orgs {
		o := od.typed
		key := "org:" + o.OrgID
		for _, md := range o.UserMetadata {
			u := users[md.ID]
			if u == nil {
				continue
			}
			if u.attrs == nil {
				u.attrs = map[string]any{}
			}
			v, err := base64.StdEncoding.DecodeString(md.Value)
			if err == nil && utf8.Valid(v) {
				u.attrs[md.Key] = string(v)
			} else {
				u.attrs[md.Key] = map[string]string{"base64": md.Value}
			}
		}
		for _, l := range o.UserLinks {
			if u := users[l.UserID]; u != nil {
				u.links = append(u.links, l.IdPName+":"+l.ProvidedUserID)
			}
		}
		for _, m := range o.OrgMembers {
			u := users[m.UserID]
			if u == nil {
				continue
			}
			for _, r := range m.Roles {
				k := "org-member:" + r
				sd.roleNotes[k] = "ZITADEL organization manager role " + r
				u.grants = append(u.grants, srcGrant{key: k, orgs: []string{key}})
			}
		}
		for _, m := range o.ProjectMembers {
			u := users[m.UserID]
			if u == nil {
				continue
			}
			for _, r := range m.Roles {
				k := "project-member:" + m.ProjectID + ":" + r
				sd.roleNotes[k] = "ZITADEL project manager role " + r + " of project " + projects[m.ProjectID]
				u.grants = append(u.grants, srcGrant{key: k, orgs: []string{key}})
			}
		}
		for _, g := range o.UserGrants {
			u := users[g.UserID]
			if u == nil {
				continue
			}
			for _, r := range g.RoleKeys {
				u.grants = append(u.grants, srcGrant{key: "project-role:" + g.ProjectID + ":" + r, orgs: []string{userOrg[g.UserID]}})
			}
		}
		// Everything else in the organization is configuration that does
		// not carry over.
		for _, p := range o.Projects {
			if p.Project.Name == "ZITADEL" {
				sd.other = append(sd.other, otherEntity{entity: "projects", id: p.ProjectID, outcome: Ignored, reasons: []string{"ZITADEL built-in project"}})
				continue
			}
			sd.other = append(sd.other, otherEntity{entity: "projects", id: p.ProjectID, outcome: Unsupported,
				reasons: []string{"projects are not migrated; their roles are translated through the mapping, applications are recreated as clients"}})
		}
		builtIn := map[string]bool{}
		for _, p := range o.Projects {
			if p.Project.Name == "ZITADEL" {
				builtIn[p.ProjectID] = true
			}
		}
		for _, kind := range []string{"oidcApps", "apiApps", "samlApps"} {
			var apps []struct {
				AppID string `json:"appId"`
				App   struct {
					ProjectID string `json:"projectId"`
					Name      string `json:"name"`
				} `json:"app"`
			}
			_ = json.Unmarshal(od.raw[kind], &apps)
			for _, a := range apps {
				if builtIn[a.App.ProjectID] {
					sd.other = append(sd.other, otherEntity{entity: "clients", id: a.AppID, outcome: Ignored, reasons: []string{"ZITADEL built-in application " + a.App.Name}})
					continue
				}
				sd.other = append(sd.other, otherEntity{entity: "clients", id: a.AppID, outcome: Unsupported,
					reasons: []string{"applications are not migrated; recreate it as a client (its secret or keys are issued anew)"}})
			}
		}
		names := make([]string, 0, len(od.raw))
		for k := range od.raw {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			raw := od.raw[k]
			n := countJSON(raw)
			switch {
			case n == 0:
			case strings.HasSuffix(k, "Policy"):
				sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: o.OrgID + ":" + k, outcome: Unsupported,
					reasons: []string{"ZITADEL " + k + " is not converted; configure the realm policy"}})
			case k == "actions" || k == "triggerActions":
				addN(sd, "actions", o.OrgID+":"+k, n, "ZITADEL actions (custom code) are not converted; use ProudAuth hooks")
			case k == "appKeys" || k == "machineKeys":
				addN(sd, "keys", o.OrgID+":"+k, n, "private keys of applications and machine users cannot be exported or migrated")
			case strings.Contains(strings.ToLower(k), "idp"):
				addN(sd, "identity_providers", o.OrgID+":"+k, n, "recreate the upstream connection; its client secret is not migrated")
			case k == "projectGrants" || k == "projectGrantMembers":
				addN(sd, "project_grants", o.OrgID+":"+k, n, "project grants to other organizations are not migrated; translate their roles through the mapping")
			case k == "customTexts" || k == "loginTexts" || k == "oidcApps" || k == "apiApps" || k == "samlApps" || k == "projects" ||
				k == "projectRoles" || k == "humanUsers" || k == "machineUsers" || k == "userMetadata" || k == "userLinks" || k == "orgMembers" ||
				k == "projectMembers" || k == "userGrants" || k == "domains" || k == "orgId" || k == "org" || k == "orgState":
			default:
				addN(sd, "other_configuration", o.OrgID+":"+k, n, "ZITADEL "+k+" is not converted")
			}
		}
	}
	sd.notes = append(sd.notes,
		"The ZITADEL export does not contain passkeys, U2F tokens, OTP via SMS or email, instance members (IAM roles), instance settings or sessions: users with those factors enroll again.",
		"passwordChangeRequired is not filled in by the v4 export; users who must change their password are not marked.")
	sd.other = append(sd.other, otherEntity{entity: "sessions", id: "sessions and tokens", outcome: Unsupported,
		reasons: []string{"sessions and tokens are not exported and never portable across issuers; users sign in again (MIG-010)"}})
	return sd, nil
}

func addN(sd *sourceData, entity, id string, n int, reason string) {
	for i := 0; i < n; i++ {
		sd.other = append(sd.other, otherEntity{entity: entity, id: fmt.Sprintf("%s[%d]", id, i), outcome: Unsupported, reasons: []string{reason}})
	}
}

// countJSON counts the items of an array member (1 for an object).
func countJSON(raw json.RawMessage) int {
	var list []json.RawMessage
	if json.Unmarshal(raw, &list) == nil {
		return len(list)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil && len(obj) > 0 {
		return 1
	}
	return 0
}

// ztPassword converts a ZITADEL password hash (passwap encodings).
func ztPassword(v string) *srcPassword {
	switch {
	case strings.HasPrefix(v, "$2a$") || strings.HasPrefix(v, "$2b$") || strings.HasPrefix(v, "$2y$"):
		return &srcPassword{algorithm: "bcrypt" + bcryptCost(v), hash: v}
	case strings.HasPrefix(v, "$argon2id$"):
		return &srcPassword{algorithm: "argon2id", hash: v}
	case strings.HasPrefix(v, "$pbkdf2"):
		// passlib form: $pbkdf2-sha256$<iterations>$<ab64 salt>$<ab64 hash>
		parts := strings.Split(v, "$")
		if len(parts) != 5 {
			return &srcPassword{algorithm: "pbkdf2", problem: "malformed PBKDF2 hash"}
		}
		prf := map[string]string{"pbkdf2": "sha1", "pbkdf2-sha1": "sha1", "pbkdf2-sha256": "sha256", "pbkdf2-sha512": "sha512"}[parts[1]]
		iter, err := strconv.Atoi(parts[2])
		salt, err1 := ab64(parts[3])
		sum, err2 := ab64(parts[4])
		p := &srcPassword{algorithm: fmt.Sprintf("%s (%s iterations)", parts[1], parts[2])}
		if prf == "" || err != nil || err1 != nil || err2 != nil {
			p.problem = "malformed or unsupported PBKDF2 hash"
			return p
		}
		p.hash = credential.PBKDF2Verifier(prf, iter, salt, sum)
		return p
	}
	name := "unknown hash format"
	for prefix, n := range map[string]string{"$1$": "md5crypt", "$5$": "sha256crypt", "$6$": "sha512crypt", "$argon2i$": "argon2i",
		"$argon2d$": "argon2d", "$scrypt$": "scrypt", "$7$": "scrypt", "$P$": "phpass", "$H$": "phpass"} {
		if strings.HasPrefix(v, prefix) {
			name = n
		}
	}
	return &srcPassword{algorithm: name, problem: name + " is not an accepted import format"}
}

// ab64 decodes passlib's adapted base64 (no padding, "." for "+").
func ab64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.ReplaceAll(s, ".", "+"))
}

// bcryptCost describes the cost of a bcrypt hash for the report.
func bcryptCost(h string) string {
	if parts := strings.Split(h, "$"); len(parts) > 2 {
		if n, err := strconv.Atoi(parts[2]); err == nil {
			return fmt.Sprintf(" cost %d", n)
		}
	}
	return ""
}
