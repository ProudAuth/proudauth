package provisioning

import (
	"strings"
	"testing"
)

func TestParseFilter(t *testing.T) {
	user := map[string]any{
		"id": "usr_1", "externalId": "Okta-1", "userName": "Alice.Smith", "active": true,
		"name":   map[string]any{"givenName": "Alice", "familyName": "Smith"},
		"emails": []any{map[string]any{"value": "alice@work.test", "type": "work", "primary": true}, map[string]any{"value": "a@home.test", "type": "home"}},
		"meta":   map[string]any{"version": float64(3)},
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{`userName eq "alice.smith"`, true},
		{`USERNAME Eq "ALICE.SMITH"`, true},
		{`userName ne "bob"`, true},
		{`userName co "ce.sm"`, true},
		{`userName sw "ali"`, true},
		{`userName ew "SMITH"`, true},
		{`userName sw "smith"`, false},
		{`externalId eq "okta-1"`, false},
		{`externalId eq "Okta-1"`, true},
		{`id eq "USR_1"`, false},
		{`active eq true`, true},
		{`active eq false`, false},
		{`meta.version gt 2`, true},
		{`meta.version le 2`, false},
		{`name.familyName eq "smith"`, true},
		{`urn:ietf:params:scim:schemas:core:2.0:User:userName eq "alice.smith"`, true},
		{`title pr`, false},
		{`emails pr`, true},
		{`emails.value eq "a@home.test"`, true},
		{`emails[type eq "work" and value co "work.test"]`, true},
		{`emails[type eq "home" and primary eq true]`, false},
		{`emails[type eq "work"].value ew "work.test"`, true},
		{`userName eq "x" or active eq true`, true},
		{`userName eq "x" and active eq true`, false},
		{`not (userName eq "x")`, true},
		{`not (userName eq "alice.smith") or (active eq true and name.givenName sw "a")`, true},
		{`userName eq "say \"hi\""`, false},
	}
	for _, c := range cases {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		if got := f.Match(user); got != c.want {
			t.Errorf("%s = %v, want %v", c.filter, got, c.want)
		}
	}
	// Group attributes qualified with the Group schema URN (in any case)
	// name the same attributes as bare ones.
	group := map[string]any{"schemas": []string{SchemaGroup}, "id": "grp_1", "displayName": "Engineering",
		"members": []any{map[string]any{"value": "usr_1", "display": "Alice"}}}
	for _, c := range []struct {
		filter string
		want   bool
	}{
		{`urn:ietf:params:scim:schemas:core:2.0:Group:displayName eq "engineering"`, true},
		{`URN:IETF:PARAMS:SCIM:SCHEMAS:CORE:2.0:GROUP:displayName eq "engineering"`, true},
		{`urn:ietf:params:scim:schemas:core:2.0:Group:displayName eq "sales"`, false},
		{`urn:ietf:params:scim:schemas:core:2.0:Group:members[value eq "usr_1"]`, true},
		{`urn:ietf:params:scim:schemas:core:2.0:Group:members.value eq "usr_2"`, false},
	} {
		f, err := ParseFilter(c.filter)
		if err != nil {
			t.Fatalf("%s: %v", c.filter, err)
		}
		if got := f.Match(group); got != c.want {
			t.Errorf("%s = %v, want %v", c.filter, got, c.want)
		}
	}
}

func TestParseFilterRejects(t *testing.T) {
	for _, s := range []string{
		``,
		`userName zz "x"`,
		`userName eq`,
		`userName eq "x" and`,
		`(userName eq "x"`,
		`userName eq "x")`,
		`emails[type eq "work"`,
		`userName eq "unterminated`,
		`userName gt true`,
		`and eq "x"`,
		strings.Repeat(`(`, 600) + `a pr` + strings.Repeat(`)`, 600),
		strings.Repeat(`a pr or `, 80) + `a pr`,
	} {
		if _, err := ParseFilter(s); err == nil {
			t.Errorf("%q: accepted", s)
		}
	}
}
