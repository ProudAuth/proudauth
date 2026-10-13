package bench

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// SeedSpec sizes a generated dataset (NFR-004). Every name and password is
// derived from Seed, so the same spec recreates the same data.
type SeedSpec struct {
	Seed           uint64 `json:"seed"`
	Users          int    `json:"users"`
	Organizations  int    `json:"organizations"`
	LargeOrgUsers  int    `json:"large_organization_users"`
	MachineClients int    `json:"machine_clients"`
	RoleDepth      int    `json:"role_depth"`
	GroupMembers   int    `json:"large_group_members"`
}

// Client credentials created by the seed.
type SeedClient struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"client_secret"`
}

// SeedData is what scenarios need. It holds the benchmark realm's client
// secrets: keep the file private (it is written with mode 0600) and use a
// dedicated benchmark realm, never production.
type SeedData struct {
	Spec            SeedSpec     `json:"spec"`
	Realm           string       `json:"realm"`
	Prefix          string       `json:"prefix"`
	Audience        string       `json:"audience"`
	LargeOrgID      string       `json:"large_organization_id"`
	OrgIDs          []string     `json:"organization_ids"`
	Machine         []SeedClient `json:"machine_clients"`
	ResourceSrv     SeedClient   `json:"resource_server"`
	Web             SeedClient   `json:"web_client"`
	RedirectURI     string       `json:"redirect_uri"`
	AdminAudience   string       `json:"admin_audience"`
	AccountAudience string       `json:"account_audience,omitempty"`
	RoleID          string       `json:"organization_role_id,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
}

// UserEmail returns the email of seeded user i.
func (s *SeedData) UserEmail(i int) string {
	return fmt.Sprintf("%su%d@bench.test", s.Prefix, i)
}

// UserPassword returns the password of seeded user i.
func (s *SeedData) UserPassword(i int) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], s.Spec.Seed)
	binary.BigEndian.PutUint64(b[8:], uint64(i))
	sum := sha256.Sum256(append([]byte("proudauth-bench-password:"), b[:]...))
	return "bench-" + hex.EncodeToString(sum[:12])
}

// seedPrefix namespaces every object a seed creates. It is the whole seed in
// hex (at most 16 digits, so slugs and client IDs stay well inside their
// limits): distinct seeds never share a prefix, so a rerun with a new seed
// never collides with an earlier run in the same realm.
func seedPrefix(seed uint64) string { return fmt.Sprintf("b%x-", seed) }

// clientRef returns the internal ID of a client created through the API.
func clientRef(r *Response) (string, error) {
	c, _ := r.Body["client"].(map[string]any)
	id, _ := c["id"].(string)
	if id == "" {
		return "", fmt.Errorf("client response without client.id: %s", truncate(string(r.Raw), 300))
	}
	return id, nil
}

// legacyHash is the import format "$legacy-sha256$<salt>$<sha256(salt||password)>",
// rehashed to Argon2id at the first sign-in; computing Argon2id for every
// seeded user would make seeding slow without changing what is measured.
func legacyHash(password string, i int) string {
	salt := sha256.Sum256([]byte(fmt.Sprintf("salt-%d", i)))
	h := sha256.Sum256(append(salt[:16], []byte(password)...))
	return "$legacy-sha256$" + base64.RawStdEncoding.EncodeToString(salt[:16]) + "$" + base64.RawStdEncoding.EncodeToString(h[:])
}

// Seed creates the dataset through the administration API with admin tokens
// holding realm administration and an MFA session: a StaticToken, or
// AdminCredentials when seeding may outlast one token (large datasets).
func Seed(ctx context.Context, c *Client, admin TokenSource, spec SeedSpec, progress func(string)) (*SeedData, error) {
	if spec.Users <= 0 {
		spec.Users = 1000
	}
	if spec.Organizations <= 0 {
		spec.Organizations = 50
	}
	if spec.LargeOrgUsers <= 0 || spec.LargeOrgUsers > spec.Users {
		spec.LargeOrgUsers = spec.Users / 2
	}
	if spec.MachineClients <= 0 {
		spec.MachineClients = 10
	}
	if spec.RoleDepth <= 0 {
		spec.RoleDepth = 3
	}
	if progress == nil {
		progress = func(string) {}
	}
	prefix := seedPrefix(spec.Seed)
	d := &SeedData{Spec: spec, Realm: c.Realm, Prefix: prefix, Audience: "https://" + prefix + "api.bench.test", RedirectURI: "https://app.bench.test/callback",
		CreatedAt: time.Now().UTC()}
	api := func(method, path string, body any, want int, what string) (*Response, error) {
		tok, err := admin.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s: administrator token: %w", what, err)
		}
		r, err := c.API(ctx, method, path, tok, body)
		return Must(r, err, want, what)
	}
	progress("resources and roles")
	res, err := api("POST", "/resources", map[string]any{"name": prefix + "Bench API", "audience": d.Audience, "verification_mode": "offline",
		"requires_organization": false, "scopes": []map[string]any{{"name": "bench:read"}, {"name": "bench:write"}}}, 201, "resource")
	if err != nil {
		return nil, err
	}
	resourceID := res.Str("id")
	if _, err := api("POST", "/permissions", map[string]any{"name": prefix + "bench.read"}, 201, "permission"); err != nil {
		return nil, err
	}
	// A bounded chain of composed roles for authorization depth (NFR-004).
	var roleID string
	for level := 1; level <= spec.RoleDepth; level++ {
		body := map[string]any{"boundary_type": "organization", "name": fmt.Sprintf("%sreader-l%d", prefix, level), "permissions": []string{prefix + "bench.read"}}
		if roleID != "" {
			body["composite_role_ids"] = []string{roleID}
		}
		r, err := api("POST", "/roles", body, 201, "role")
		if err != nil {
			return nil, err
		}
		roleID = r.Str("id")
	}
	topRole := fmt.Sprintf("%sreader-l%d", prefix, spec.RoleDepth)
	d.RoleID = roleID
	resources, err := api("GET", "/resources", nil, 200, "resources")
	if err != nil {
		return nil, err
	}
	adminRes, accountRes := "", ""
	if items, ok := resources.Body["items"].([]any); ok {
		for _, it := range items {
			if m, _ := it.(map[string]any); m["kind"] == "admin" {
				adminRes, _ = m["id"].(string)
				d.AdminAudience, _ = m["audience"].(string)
			} else if m["kind"] == "account" {
				accountRes, _ = m["id"].(string)
				d.AccountAudience, _ = m["audience"].(string)
			}
		}
	}
	realmRoles, err := api("GET", "/roles?boundary_type=realm", nil, 200, "realm roles")
	if err != nil {
		return nil, err
	}
	rsRole := ""
	if items, ok := realmRoles.Body["items"].([]any); ok {
		for _, it := range items {
			if m, _ := it.(map[string]any); m["name"] == "resource-server" {
				rsRole, _ = m["id"].(string)
			}
		}
	}
	progress("clients")
	machine := func(name string) (SeedClient, string, string, error) {
		sp, err := api("POST", "/service-principals", map[string]any{"name": name}, 201, "service principal")
		if err != nil {
			return SeedClient{}, "", "", err
		}
		cl, err := api("POST", "/clients", map[string]any{"client_id": name, "name": name, "client_type": "machine", "service_principal_id": sp.Str("id"),
			"grant_types": []string{"client_credentials"}}, 201, "client")
		if err != nil {
			return SeedClient{}, "", "", err
		}
		ref, err := clientRef(cl)
		if err != nil {
			return SeedClient{}, "", "", err
		}
		return SeedClient{ClientID: name, Secret: cl.Str("client_secret")}, ref, sp.Str("id"), nil
	}
	for i := 0; i < spec.MachineClients; i++ {
		sc, ref, _, err := machine(fmt.Sprintf("%ssvc-%d", prefix, i))
		if err != nil {
			return nil, err
		}
		if _, err := api("PUT", "/clients/"+ref+"/resource-grants/"+resourceID, map[string]any{"allowed_scopes": []string{"bench:read"},
			"subject_types": []string{"service_principal"}}, 204, "grant"); err != nil {
			return nil, err
		}
		d.Machine = append(d.Machine, sc)
	}
	rs, rsRef, rsSP, err := machine(prefix + "rs")
	if err != nil {
		return nil, err
	}
	d.ResourceSrv = rs
	if _, err := api("POST", "/resources/"+resourceID+"/introspectors", map[string]any{"client": rsRef}, 204, "introspector"); err != nil {
		return nil, err
	}
	if rsRole != "" && adminRes != "" {
		if _, err := api("POST", "/role-assignments", map[string]any{"role_id": rsRole, "subject": map[string]any{"type": "service_principal", "id": rsSP}},
			201, "resource-server role"); err != nil {
			return nil, err
		}
		if _, err := api("PUT", "/clients/"+rsRef+"/resource-grants/"+adminRes, map[string]any{"allowed_scopes": []string{"proudauth:admin"},
			"subject_types": []string{"service_principal"}}, 204, "admin grant"); err != nil {
			return nil, err
		}
	}
	web, err := api("POST", "/clients", map[string]any{"client_id": prefix + "web", "name": prefix + "web", "client_type": "confidential", "first_party": true,
		"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{d.RedirectURI}, "allow_offline_access": true}, 201, "web client")
	if err != nil {
		return nil, err
	}
	d.Web = SeedClient{ClientID: prefix + "web", Secret: web.Str("client_secret")}
	webRef, err := clientRef(web)
	if err != nil {
		return nil, err
	}
	if _, err := api("PUT", "/clients/"+webRef+"/resource-grants/"+resourceID, map[string]any{"allowed_scopes": []string{"bench:read"},
		"subject_types": []string{"user"}}, 204, "web grant"); err != nil {
		return nil, err
	}
	if accountRes != "" {
		if _, err := api("PUT", "/clients/"+webRef+"/resource-grants/"+accountRes, map[string]any{"allowed_scopes": []string{"proudauth:account"},
			"subject_types": []string{"user"}}, 204, "account grant"); err != nil {
			return nil, err
		}
	}
	progress("organizations")
	large, err := api("POST", "/organizations", map[string]any{"slug": prefix + "large", "display_name": "Bench large"}, 201, "large organization")
	if err != nil {
		return nil, err
	}
	d.LargeOrgID = large.Str("id")
	slugs := []string{}
	for i := 0; i < spec.Organizations; i++ {
		slug := fmt.Sprintf("%so%d", prefix, i)
		o, err := api("POST", "/organizations", map[string]any{"slug": slug, "display_name": slug}, 201, "organization")
		if err != nil {
			return nil, err
		}
		d.OrgIDs = append(d.OrgIDs, o.Str("id"))
		slugs = append(slugs, slug)
	}
	progress("users")
	for start := 0; start < spec.Users; {
		batch := []map[string]any{}
		body := map[string]any{"source_system": "bench-" + prefix[:len(prefix)-1], "users": batch, "trust_email_verification": true,
			"verification_reason": "synthetic benchmark accounts"}
		// Bound bytes as well as records, leaving headroom below the default
		// 256 KiB request limit (NFR-004). Two memberships and imported
		// password verifiers make a 1000-user batch exceed that limit.
		envelope, _ := json.Marshal(body)
		bytes := len(envelope)
		end := start
		for i := start; i < min(start+1000, spec.Users); i++ {
			mems := []map[string]any{{"organization": slugs[i%len(slugs)], "roles": []string{topRole}}}
			if i < spec.LargeOrgUsers {
				mems = append(mems, map[string]any{"organization": prefix + "large", "roles": []string{topRole}})
			}
			record := map[string]any{"source_id": fmt.Sprintf("u%d", i), "email": d.UserEmail(i), "email_verified": true,
				"password_hash": legacyHash(d.UserPassword(i), i), "memberships": mems}
			raw, _ := json.Marshal(record)
			added := len(raw)
			if len(batch) > 0 {
				added++ // comma between records
			}
			if bytes+added > 192<<10 {
				if len(batch) == 0 {
					return nil, fmt.Errorf("seed user %d exceeds the import byte budget", i)
				}
				break
			}
			batch = append(batch, record)
			bytes += added
			end = i + 1
		}
		body["users"] = batch
		job, err := api("POST", "/user-imports", body, 202, "import")
		if err != nil {
			return nil, err
		}
		if err := waitJob(ctx, c, admin, job.Str("job_id")); err != nil {
			return nil, err
		}
		start = end
		progress(fmt.Sprintf("users %d/%d", start, spec.Users))
	}
	if spec.GroupMembers > 0 {
		progress("large group")
		g, err := api("POST", "/organizations/"+d.LargeOrgID+"/groups", map[string]any{"name": prefix + "everyone"}, 201, "group")
		if err != nil {
			return nil, err
		}
		added, cursor := 0, ""
		for added < spec.GroupMembers {
			path := "/organizations/" + d.LargeOrgID + "/members?limit=200"
			if cursor != "" {
				path += "&cursor=" + url.QueryEscape(cursor)
			}
			page, err := api("GET", path, nil, 200, "members")
			if err != nil {
				return nil, err
			}
			items, _ := page.Body["items"].([]any)
			for _, it := range items {
				if added >= spec.GroupMembers {
					break
				}
				m, _ := it.(map[string]any)
				id, _ := m["id"].(string)
				if id == "" {
					id, _ = m["membership_id"].(string)
				}
				if _, err := api("POST", "/organizations/"+d.LargeOrgID+"/groups/"+g.Str("id")+"/members", map[string]any{"membership_id": id}, 204, "group member"); err != nil {
					return nil, err
				}
				added++
			}
			cursor = page.Str("next_cursor")
			if cursor == "" || len(items) == 0 {
				break
			}
		}
	}
	return d, nil
}

func waitJob(ctx context.Context, c *Client, admin TokenSource, id string) error {
	if id == "" {
		return fmt.Errorf("benchmark import has no job ID")
	}
	for i := 0; i < 600; i++ {
		token, err := admin.Token(ctx)
		if err != nil {
			return err
		}
		r, err := c.API(ctx, "GET", "/jobs/"+id, token, nil)
		if err != nil {
			return err
		}
		if r.Status != 200 {
			return fmt.Errorf("job %s: HTTP %d", id, r.Status)
		}
		switch r.Str("state") {
		case "succeeded":
			return nil
		case "failed", "dead_letter", "cancelled":
			return fmt.Errorf("job %s %s: %s", id, r.Str("state"), r.Str("last_error"))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("job %s did not finish", id)
}
