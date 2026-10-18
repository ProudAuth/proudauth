package notification

import (
	"context"
	"slices"
	"testing"
	"time"
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

// TestLocalizeTimeLayout covers MSG-006: the time, expires and scheduled values
// of a notice are rendered in the locale-neutral numeric layout, in UTC when the
// message names no account (localize then makes no query, so no database is
// needed), and other values are left as they are.
func TestLocalizeTimeLayout(t *testing.T) {
	at := time.Date(2026, 1, 2, 12, 4, 0, 0, time.FixedZone("JST", 9*60*60))
	m := Message{Template: TplSupportAccess, Data: map[string]string{
		"time":      Timestamp(at),
		"expires":   Timestamp(at.Add(time.Hour)),
		"scheduled": Timestamp(at.Add(24 * time.Hour)),
		"state":     Timestamp(at),
	}}
	var s Service
	s.localize(context.Background(), nil, &m)
	for k, want := range map[string]string{
		"time":      "2026-01-02 03:04 UTC",
		"expires":   "2026-01-02 04:04 UTC",
		"scheduled": "2026-01-03 03:04 UTC",
		"state":     "2026-01-02T03:04:00Z",
	} {
		if got := m.Data[k]; got != want {
			t.Errorf("localized %s = %q, want %q", k, got, want)
		}
	}
}
