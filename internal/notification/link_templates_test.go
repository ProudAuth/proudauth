package notification

import (
	"slices"
	"strings"
	"testing"
)

// TestAccountLinkTemplatesStatePurpose covers PWDLESS-008: the code and the
// magic link that prove control of an account for linking an external
// identity say that an account is being linked and name the connection, in
// every built-in locale, unlike the ordinary sign-in messages.
func TestAccountLinkTemplatesStatePurpose(t *testing.T) {
	c := DefaultCatalog()
	for _, tpl := range []string{TplAccountLinkCode, TplAccountLinkMagicLink} {
		if !slices.Contains(Variables[tpl], "provider") {
			t.Fatalf("%s does not declare the provider variable: %v", tpl, Variables[tpl])
		}
		en, ok := c.lookup(tpl, "en")
		if !ok {
			t.Fatalf("%s has no English template", tpl)
		}
		for _, loc := range []string{"en", "es"} {
			m, ok := c.lookup(tpl, loc)
			if !ok {
				continue
			}
			if !strings.Contains(m.Subject, "{{.provider}}") || !strings.Contains(m.Text, "{{.provider}}") {
				t.Errorf("%s/%s does not name the connection", tpl, loc)
			}
		}
		if !strings.Contains(strings.ToLower(en.Subject+en.Text), "link") {
			t.Errorf("%s does not state the linking purpose", tpl)
		}
	}
	for _, tpl := range []string{TplLoginCode, TplMagicLink} {
		m, _ := c.lookup(tpl, "en")
		if strings.Contains(m.Text, "{{.provider}}") {
			t.Errorf("%s names a connection", tpl)
		}
	}
}
