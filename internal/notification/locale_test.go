package notification

import (
	"slices"
	"testing"
)

// TestLocaleFallbacks covers NFR-009 (language tags): a message locale may be
// one tag or an OIDC ui_locales preference list; each listed tag is tried,
// then its primary language, then English, and a long list is bounded.
func TestLocaleFallbacks(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"", []string{"en"}},
		{"es", []string{"es", "en"}},
		{"es-MX", []string{"es-mx", "es", "en"}},
		{"fr-CA es en", []string{"fr-ca", "fr", "es", "en"}},
		{"  de_AT   pt-BR ", []string{"de_at", "de", "pt-br", "pt", "en"}},
		{"a b c d e f g", []string{"a", "b", "c", "d", "e", "en"}},
	} {
		if got := fallbacks(c.in); !slices.Equal(got, c.want) {
			t.Errorf("fallbacks(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	cat := DefaultCatalog()
	for _, l := range fallbacks("fr-CA es en") {
		if tpl, ok := cat.lookup(TplLoginCode, l); ok {
			if l != "es" || tpl.Subject == "" {
				t.Fatalf("first available login-code template for fr-CA es en: %s", l)
			}
			return
		}
	}
	t.Fatal("no login-code template found")
}
