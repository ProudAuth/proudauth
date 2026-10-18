package application

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"
)

// TestReviewedChanges covers the metadata a dynamic registration's approval
// reviews (APP-016, APP-017; alpha.6 decision 14): a change of the name,
// redirect or post-logout redirect URIs, grant types or the client, logo,
// policy and terms URIs is reported with its values before and after; lists
// compare as sets; other registrant metadata is not reported; recorded lists
// are bounded.
func TestReviewedChanges(t *testing.T) {
	base := func() *Client {
		return &Client{Name: "Partner app", RedirectURIs: []string{"https://dcr.test/cb"}, PostLogoutRedirects: []string{},
			GrantTypes: []string{GrantAuthorizationCode, GrantRefreshToken}, Contacts: []string{"dev@partner.test"},
			ProtocolOptions: ProtocolOptions{ClientURI: "https://dcr.test/", LogoURI: "https://dcr.test/logo.png",
				PolicyURI: "https://dcr.test/privacy", TOSURI: "https://dcr.test/terms", FrontchannelLogoutURI: "https://dcr.test/fcl"}}
	}
	for field, change := range map[string]func(*Client){
		"client_name":               func(c *Client) { c.Name = "Partner app (new brand)" },
		"redirect_uris":             func(c *Client) { c.RedirectURIs = append(c.RedirectURIs, "https://dcr.test/cb2") },
		"post_logout_redirect_uris": func(c *Client) { c.PostLogoutRedirects = []string{"https://dcr.test/bye"} },
		"grant_types":               func(c *Client) { c.GrantTypes = []string{GrantAuthorizationCode} },
		"client_uri":                func(c *Client) { c.ClientURI = "https://other.test/" },
		"logo_uri":                  func(c *Client) { c.LogoURI = "" },
		"policy_uri":                func(c *Client) { c.PolicyURI = "https://dcr.test/privacy-v2" },
		"tos_uri":                   func(c *Client) { c.TOSURI = "https://dcr.test/terms-v2" },
	} {
		before, after := base(), base()
		change(after)
		got := reviewedChanges(before, after)
		if len(got) != 1 || got[field] == nil {
			t.Fatalf("%s changed: %v", field, got)
		}
		b, _ := json.Marshal(got[field])
		var ch map[string]any
		_ = json.Unmarshal(b, &ch)
		if ch["before"] == nil || ch["after"] == nil || fmt.Sprint(ch["before"]) == fmt.Sprint(ch["after"]) {
			t.Fatalf("%s: before and after %s", field, b)
		}
	}
	// Unreviewed metadata and reordered lists are not changes.
	before, after := base(), base()
	after.Contacts, after.FrontchannelLogoutURI, after.Description = []string{"ops@partner.test"}, "https://dcr.test/fcl2", "changed"
	after.GrantTypes = []string{GrantRefreshToken, GrantAuthorizationCode}
	after.RedirectURIs = []string{"https://dcr.test/cb", "https://dcr.test/cb"}
	if got := reviewedChanges(before, after); len(got) != 0 {
		t.Fatalf("unreviewed or reordered metadata reported: %v", got)
	}
	// Lists are recorded sorted and at most maxAuditListEntries long.
	before, after = base(), base()
	for i := range 2 * maxAuditListEntries {
		after.PostLogoutRedirects = append(after.PostLogoutRedirects, fmt.Sprintf("https://dcr.test/bye/%03d", 2*maxAuditListEntries-i))
	}
	ch := reviewedChanges(before, after)["post_logout_redirect_uris"].(map[string]any)
	recorded := ch["after"].([]string)
	if len(recorded) != maxAuditListEntries || !slices.IsSorted(recorded) || ch["truncated"] != true || len(ch["before"].([]string)) != 0 {
		t.Fatalf("bounded list: %v", ch)
	}
	if keys := slices.Sorted(maps.Keys(ch)); !slices.Equal(keys, []string{"after", "before", "truncated"}) {
		t.Fatalf("change record members: %v", keys)
	}
}
