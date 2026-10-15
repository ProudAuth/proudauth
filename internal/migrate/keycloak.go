package migrate

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/identity"
)

// Keycloak realm export (kc.sh export; RealmRepresentation). Only the members
// the adapter reads are declared; the configuration among them that does not
// carry over is listed in the report.
type kcRealm struct {
	Realm           string                   `json:"realm"`
	ID              string                   `json:"id"`
	KeycloakVersion string                   `json:"keycloakVersion"`
	Users           []kcUser                 `json:"users"`
	FederatedUsers  []json.RawMessage        `json:"federatedUsers"`
	Groups          []kcGroup                `json:"groups"`
	Roles           *kcRoles                 `json:"roles"`
	Clients         []kcClient               `json:"clients"`
	IdPs            []kcIdP                  `json:"identityProviders"`
	Organizations   []kcOrg                  `json:"organizations"`
	Flows           []kcFlow                 `json:"authenticationFlows"`
	PasswordPolicy  string                   `json:"passwordPolicy"`
	OTPType         string                   `json:"otpPolicyType"`
	OTPAlgorithm    string                   `json:"otpPolicyAlgorithm"`
	OTPDigits       int                      `json:"otpPolicyDigits"`
	OTPPeriod       int                      `json:"otpPolicyPeriod"`
	WebAuthnRPID    string                   `json:"webAuthnPolicyRpId"`
	Components      map[string][]kcComponent `json:"components"`
	ClientScopes    []json.RawMessage        `json:"clientScopes"`
	SMTP            map[string]string        `json:"smtpServer"`
	BruteForce      bool                     `json:"bruteForceProtected"`
}

type kcUser struct {
	ID                     string              `json:"id"`
	Username               string              `json:"username"`
	Email                  string              `json:"email"`
	EmailVerified          bool                `json:"emailVerified"`
	FirstName              string              `json:"firstName"`
	LastName               string              `json:"lastName"`
	Enabled                *bool               `json:"enabled"`
	Attributes             map[string][]string `json:"attributes"`
	Credentials            []kcCredential      `json:"credentials"`
	RequiredActions        []string            `json:"requiredActions"`
	FederatedIdentities    []kcFederated       `json:"federatedIdentities"`
	RealmRoles             []string            `json:"realmRoles"`
	ClientRoles            map[string][]string `json:"clientRoles"`
	Groups                 []string            `json:"groups"`
	ServiceAccountClientID string              `json:"serviceAccountClientId"`
	FederationLink         string              `json:"federationLink"`
}

type kcCredential struct {
	Type           string `json:"type"`
	UserLabel      string `json:"userLabel"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

type kcFederated struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
	UserName         string `json:"userName"`
}

type kcGroup struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	SubGroups   []kcGroup           `json:"subGroups"`
	RealmRoles  []string            `json:"realmRoles"`
	ClientRoles map[string][]string `json:"clientRoles"`
	Attributes  map[string][]string `json:"attributes"`
}

type kcRoles struct {
	Realm  []kcRole            `json:"realm"`
	Client map[string][]kcRole `json:"client"`
}

type kcRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
}

type kcClient struct {
	ClientID     string `json:"clientId"`
	PublicClient bool   `json:"publicClient"`
	BearerOnly   bool   `json:"bearerOnly"`
}

type kcIdP struct {
	Alias      string `json:"alias"`
	ProviderID string `json:"providerId"`
}

type kcOrg struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Alias   string `json:"alias"`
	Enabled *bool  `json:"enabled"`
	Domains []struct {
		Name     string `json:"name"`
		Verified bool   `json:"verified"`
	} `json:"domains"`
	Members []struct {
		Username string `json:"username"`
		ID       string `json:"id"`
	} `json:"members"`
	IdentityProviders []json.RawMessage `json:"identityProviders"`
}

type kcFlow struct {
	Alias   string `json:"alias"`
	BuiltIn bool   `json:"builtIn"`
}

type kcComponent struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ProviderID string `json:"providerId"`
}

// Keycloak's own clients, created with every realm.
var kcBuiltInClients = map[string]bool{"account": true, "account-console": true, "admin-cli": true, "broker": true,
	"realm-management": true, "security-admin-console": true}

// Keycloak required actions and their ProudAuth equivalents (AUT-018).
var kcActions = map[string]string{
	"UPDATE_PASSWORD": identity.ActionUpdatePassword, "VERIFY_EMAIL": identity.ActionVerifyEmail,
	"CONFIGURE_TOTP": identity.ActionConfigureTOTP, "TERMS_AND_CONDITIONS": identity.ActionAcceptTerms,
	"UPDATE_PROFILE": identity.ActionCompleteProfile, "VERIFY_PROFILE": identity.ActionCompleteProfile,
}

func parseKeycloak(docs [][]byte) (*sourceData, error) {
	var realm *kcRealm
	var extraUsers []kcUser
	for i, b := range docs {
		var r kcRealm
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("keycloak export %d: %w", i+1, err)
		}
		if r.Realm == "" {
			return nil, fmt.Errorf("keycloak export %d: not a realm export (no realm member)", i+1)
		}
		if r.KeycloakVersion == "" {
			// A users file of a directory export: {"realm", "users"}.
			if r.Users == nil {
				return nil, fmt.Errorf("keycloak export %d: neither a realm export (keycloakVersion) nor a users file", i+1)
			}
			extraUsers = append(extraUsers, r.Users...)
			continue
		}
		if realm != nil {
			return nil, fmt.Errorf("keycloak export %d: a second realm export (%s); convert one realm at a time", i+1, r.Realm)
		}
		rr := r
		realm = &rr
	}
	if realm == nil {
		return nil, errors.New("keycloak: the realm export (the file with keycloakVersion) is required")
	}
	realm.Users = append(realm.Users, extraUsers...)
	sd := &sourceData{version: realm.KeycloakVersion, scope: realm.Realm, roleNotes: map[string]string{}}

	// Organizations (Keycloak 26) and groups.
	byUsername := map[string][]string{}
	for _, o := range realm.Organizations {
		key := "org:" + firstNonEmpty(o.Alias, o.ID)
		slug, _ := slugOf(firstNonEmpty(o.Alias, o.Name))
		so := &srcOrg{key: key, id: o.ID, name: firstNonEmpty(o.Name, o.Alias), slug: slug, defaultOn: true, entity: "organizations"}
		if o.Enabled != nil && !*o.Enabled {
			so.lossNotes = append(so.lossNotes, "disabled in the source; created active (suspend it after review)")
		}
		if len(o.Domains) > 0 {
			var ds []string
			for _, d := range o.Domains {
				ds = append(ds, fmt.Sprintf("%s (verified=%t)", d.Name, d.Verified))
			}
			so.lossNotes = append(so.lossNotes, "domains not migrated: "+strings.Join(ds, ", "))
		}
		if len(o.IdentityProviders) > 0 {
			so.lossNotes = append(so.lossNotes, fmt.Sprintf("%d linked identity provider(s) not migrated", len(o.IdentityProviders)))
		}
		sd.orgs = append(sd.orgs, so)
		for _, m := range o.Members {
			byUsername[strings.ToLower(firstNonEmpty(m.Username, m.ID))] = append(byUsername[strings.ToLower(firstNonEmpty(m.Username, m.ID))], key)
		}
	}
	groups := map[string]*kcGroup{}
	var walk func([]kcGroup)
	walk = func(gs []kcGroup) {
		for i := range gs {
			g := &gs[i]
			groups[g.Path] = g
			slug, _ := slugOf(strings.ReplaceAll(strings.Trim(g.Path, "/"), "/", "-"))
			so := &srcOrg{key: "group:" + g.Path, id: g.ID, name: g.Name, slug: slug, entity: "groups"}
			so.lossNotes = append(so.lossNotes, "group hierarchy flattened")
			if len(g.Attributes) > 0 {
				so.lossNotes = append(so.lossNotes, "group attributes not migrated")
			}
			sd.orgs = append(sd.orgs, so)
			sd.roleNotes["group:"+g.Path] = "Keycloak group " + g.Path
			walk(g.SubGroups)
		}
	}
	walk(realm.Groups)

	if realm.Roles != nil {
		for _, r := range realm.Roles.Realm {
			sd.roleNotes["realm-role:"+r.Name] = strings.TrimSpace("realm role " + r.Name + composite(r.Composite) + " " + describe(r.Description))
		}
		for client, rs := range realm.Roles.Client {
			if kcBuiltInClients[client] {
				continue
			}
			for _, r := range rs {
				sd.roleNotes["client-role:"+client+":"+r.Name] = strings.TrimSpace("client role " + r.Name + " of " + client + composite(r.Composite) + " " + describe(r.Description))
			}
		}
	}

	for _, ku := range realm.Users {
		u := &srcUser{id: ku.ID, username: ku.Username, email: ku.Email, emailVerified: ku.EmailVerified, given: ku.FirstName, family: ku.LastName}
		sd.users = append(sd.users, u)
		if ku.ServiceAccountClientID != "" {
			u.machine = "service-account user of client " + ku.ServiceAccountClientID + " (machine identities are recreated as ProudAuth service principals)"
			continue
		}
		u.disabled = ku.Enabled != nil && !*ku.Enabled
		attrs := map[string]any{}
		for k, v := range ku.Attributes {
			if k == "locale" && len(v) == 1 {
				u.locale = v[0]
				continue
			}
			if len(v) == 1 {
				attrs[k] = v[0]
			} else {
				attrs[k] = v
			}
		}
		if len(attrs) > 0 {
			u.attrs = attrs
		}
		hasPassword := false
		for _, c := range ku.Credentials {
			switch c.Type {
			case "password":
				hasPassword = true
				u.password = kcPassword(c)
			case "otp":
				u.totp = append(u.totp, kcOTP(c))
			case "webauthn", "webauthn-passwordless":
				u.webauthn = append(u.webauthn, firstNonEmpty(c.UserLabel, c.Type))
			case "recovery-authn-codes":
				u.recoveryCodes++
			default:
				u.otherCreds = append(u.otherCreds, "Keycloak credential type "+c.Type)
			}
		}
		if ku.FederationLink != "" && !hasPassword {
			u.password = &srcPassword{algorithm: "user federation " + ku.FederationLink,
				problem: "the password is held by the user federation provider (LDAP or Kerberos), not in the export"}
		}
		for _, a := range ku.RequiredActions {
			if t, ok := kcActions[a]; ok {
				if !containsStr(u.actions, t) {
					u.actions = append(u.actions, t)
				}
			} else {
				u.unsupportedActions = append(u.unsupportedActions, a)
			}
		}
		for _, f := range ku.FederatedIdentities {
			u.links = append(u.links, f.IdentityProvider+":"+f.UserID)
		}
		// Organization membership: Keycloak organizations list members by
		// user name; groups count with their ancestors.
		u.orgs = append(u.orgs, byUsername[strings.ToLower(ku.Username)]...)
		inherited := map[string]bool{}
		for _, path := range ku.Groups {
			for p := path; p != "" && p != "/"; p = parentPath(p) {
				if !containsStr(u.orgs, "group:"+p) {
					u.orgs = append(u.orgs, "group:"+p)
				}
				if g := groups[p]; g != nil {
					for _, r := range g.RealmRoles {
						inherited["realm-role:"+r] = true
					}
					for c, rs := range g.ClientRoles {
						for _, r := range rs {
							inherited["client-role:"+c+":"+r] = true
						}
					}
				}
			}
			u.grants = append(u.grants, srcGrant{key: "group:" + path})
		}
		direct := map[string]bool{}
		for _, r := range ku.RealmRoles {
			direct["realm-role:"+r] = true
		}
		clients := make([]string, 0, len(ku.ClientRoles))
		for c := range ku.ClientRoles {
			clients = append(clients, c)
		}
		sort.Strings(clients)
		for _, c := range clients {
			for _, r := range ku.ClientRoles[c] {
				direct["client-role:"+c+":"+r] = true
			}
		}
		for _, k := range sortedKeys(direct) {
			u.grants = append(u.grants, srcGrant{key: k})
		}
		for _, k := range sortedKeys(inherited) {
			if !direct[k] {
				u.grants = append(u.grants, srcGrant{key: k})
			}
		}
	}
	if n := len(realm.FederatedUsers); n > 0 {
		for i := 0; i < n; i++ {
			sd.other = append(sd.other, otherEntity{entity: "users", id: fmt.Sprintf("federated-user-%d", i+1), outcome: Unsupported,
				reasons: []string{"user stored only in a user federation provider; import it from the directory"}})
		}
	}

	// Configuration that does not carry over, listed so nothing is silent.
	for _, c := range realm.Clients {
		if kcBuiltInClients[c.ClientID] {
			sd.other = append(sd.other, otherEntity{entity: "clients", id: c.ClientID, outcome: Ignored, reasons: []string{"Keycloak built-in client"}})
			continue
		}
		reason := "clients are not migrated; recreate it (POST /clients or a configuration import)"
		if !c.PublicClient && !c.BearerOnly {
			reason += "; its client secret cannot be carried over and is issued anew"
		}
		sd.other = append(sd.other, otherEntity{entity: "clients", id: c.ClientID, outcome: Unsupported, reasons: []string{reason}})
	}
	for _, idp := range realm.IdPs {
		sd.other = append(sd.other, otherEntity{entity: "identity_providers", id: idp.Alias, outcome: Unsupported,
			reasons: []string{"recreate the upstream connection (" + idp.ProviderID + "); its client secret is not migrated"}})
	}
	for _, f := range realm.Flows {
		if !f.BuiltIn {
			sd.other = append(sd.other, otherEntity{entity: "authentication_flows", id: f.Alias, outcome: Unsupported,
				reasons: []string{"authentication flows cannot be converted; express the requirements in the realm policy"}})
		}
	}
	for kind, cs := range realm.Components {
		if kind != "org.keycloak.storage.UserStorageProvider" {
			continue
		}
		for _, c := range cs {
			sd.other = append(sd.other, otherEntity{entity: "user_federation", id: c.Name, outcome: Unsupported,
				reasons: []string{"user federation provider " + c.ProviderID + " is not migrated; configure a directory integration"}})
		}
	}
	if realm.PasswordPolicy != "" {
		sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "passwordPolicy", outcome: Unsupported,
			reasons: []string{"password policy " + strconvQuote(realm.PasswordPolicy) + " is not converted; set security.password and the realm policy"}})
	}
	if t := realm.OTPType; t != "" {
		if t == "totp" && realm.OTPAlgorithm == "HmacSHA1" && realm.OTPDigits == 6 && realm.OTPPeriod == 30 {
			sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "otpPolicy", outcome: Converted})
		} else {
			sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "otpPolicy", outcome: Unsupported,
				reasons: []string{fmt.Sprintf("OTP policy %s/%s/%d digits/%d s differs from ProudAuth TOTP (SHA-1, 6 digits, 30 s)", t, realm.OTPAlgorithm, realm.OTPDigits, realm.OTPPeriod)}})
		}
	}
	if realm.WebAuthnRPID != "" {
		sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "webAuthnPolicy", outcome: Unsupported,
			reasons: []string{"WebAuthn relying party " + realm.WebAuthnRPID + ": set webauthn.rp_id in the realm policy; existing passkeys do not carry over"}})
	}
	if realm.BruteForce {
		sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "bruteForceProtection", outcome: Unsupported,
			reasons: []string{"brute-force settings are not converted; ProudAuth applies its own attempt budgets"}})
	}
	if len(realm.ClientScopes) > 0 {
		sd.other = append(sd.other, otherEntity{entity: "client_scopes", id: fmt.Sprintf("%d client scopes", len(realm.ClientScopes)), outcome: Unsupported,
			reasons: []string{"client scopes and protocol mappers (custom claims) are not converted"}})
	}
	if len(realm.SMTP) > 0 {
		sd.other = append(sd.other, otherEntity{entity: "realm_policies", id: "smtpServer", outcome: Unsupported,
			reasons: []string{"mail delivery settings and their credentials are not migrated; configure delivery.email"}})
	}
	sd.other = append(sd.other, otherEntity{entity: "sessions", id: "sessions and offline tokens", outcome: Unsupported,
		reasons: []string{"sessions, refresh and offline tokens and consents are not exported and never portable across issuers; users sign in again (MIG-010)"}})
	return sd, nil
}

// kcPassword converts a Keycloak password credential to an import verifier.
func kcPassword(c kcCredential) *srcPassword {
	var secret struct {
		Value string `json:"value"`
		Salt  string `json:"salt"`
	}
	var data struct {
		HashIterations       int                 `json:"hashIterations"`
		Algorithm            string              `json:"algorithm"`
		AdditionalParameters map[string][]string `json:"additionalParameters"`
	}
	if json.Unmarshal([]byte(c.SecretData), &secret) != nil || json.Unmarshal([]byte(c.CredentialData), &data) != nil {
		return &srcPassword{algorithm: "unknown", problem: "malformed credential data"}
	}
	alg := data.Algorithm
	p := &srcPassword{algorithm: alg}
	salt, err1 := base64.StdEncoding.DecodeString(secret.Salt)
	sum, err2 := base64.StdEncoding.DecodeString(secret.Value)
	param := func(k string) string {
		if v := data.AdditionalParameters[k]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	switch alg {
	case "argon2":
		p.algorithm = fmt.Sprintf("argon2 (type %s, version %s, m=%s, t=%d, p=%s)", param("type"), param("version"), param("memory"), data.HashIterations, param("parallelism"))
		mem, errm := strconv.Atoi(param("memory"))
		par, errp := strconv.Atoi(param("parallelism"))
		switch {
		case err1 != nil || err2 != nil || errm != nil || errp != nil || data.HashIterations <= 0:
			p.problem = "malformed argon2 parameters"
		case param("type") != "id":
			p.problem = "argon2" + param("type") + " is not supported (argon2id only)"
		case param("version") != "1.3":
			p.problem = "argon2 version " + param("version") + " is not supported (1.3 only)"
		default:
			p.hash = fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", mem, data.HashIterations, par,
				base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum))
		}
	case "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512":
		prf := map[string]string{"pbkdf2": "sha1", "pbkdf2-sha256": "sha256", "pbkdf2-sha512": "sha512"}[alg]
		p.algorithm = fmt.Sprintf("%s (%d iterations)", alg, data.HashIterations)
		if err1 != nil || err2 != nil {
			p.problem = "malformed PBKDF2 credential"
		} else {
			p.hash = credential.PBKDF2Verifier(prf, data.HashIterations, salt, sum)
		}
	default:
		if strings.HasPrefix(secret.Value, "$2") {
			// Community bcrypt providers store the modular-crypt string.
			p.algorithm, p.hash = alg+" (bcrypt)", secret.Value
		} else {
			p.problem = "password hashing provider " + strconvQuote(alg) + " is not supported"
		}
	}
	return p
}

// kcOTP converts a Keycloak OTP credential. Keycloak keys the HMAC with the
// UTF-8 bytes of the stored secret unless the credential says the secret is
// base32 encoded.
func kcOTP(c kcCredential) srcTOTP {
	var secret struct {
		Value string `json:"value"`
	}
	var data struct {
		SubType        string `json:"subType"`
		Digits         int    `json:"digits"`
		Period         int    `json:"period"`
		Algorithm      string `json:"algorithm"`
		SecretEncoding string `json:"secretEncoding"`
	}
	t := srcTOTP{label: c.UserLabel}
	if json.Unmarshal([]byte(c.SecretData), &secret) != nil || json.Unmarshal([]byte(c.CredentialData), &data) != nil || secret.Value == "" {
		t.problem = "malformed OTP credential"
		return t
	}
	switch {
	case data.SubType != "totp":
		t.problem = "OTP type " + data.SubType + " is not supported (TOTP only)"
	case data.Algorithm != "HmacSHA1" || data.Digits != 6 || data.Period != 30:
		t.problem = fmt.Sprintf("TOTP %s, %d digits, %d s is not supported (SHA-1, 6 digits, 30 s only)", data.Algorithm, data.Digits, data.Period)
	case strings.EqualFold(data.SecretEncoding, "BASE32"):
		t.seed = strings.ToUpper(strings.TrimRight(secret.Value, "="))
	default:
		t.seed = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret.Value))
	}
	return t
}

func parentPath(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return ""
	}
	return p[:i]
}

func composite(c bool) string {
	if c {
		return " (composite; its composition is not migrated)"
	}
	return ""
}

func describe(d string) string {
	if d == "" || strings.HasPrefix(d, "${") {
		return ""
	}
	return "- " + d
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func strconvQuote(s string) string { return strconv.Quote(s) }
