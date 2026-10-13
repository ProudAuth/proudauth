package canonical

import (
	"strings"
	"testing"
	"unicode"
)

// Canonical forms must be idempotent so uniqueness checks cannot be bypassed by
// re-submitting an already-normalized value in a different spelling (QA-003).

func FuzzEmail(f *testing.F) {
	for _, s := range []string{"Alice@Example.COM", " bob@bücher.example ", "a@b", "x@@y.z", "ü@ü.de", "a..b@c.d", "K@example.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, _, err := Email(raw)
		if err != nil {
			return
		}
		if strings.ContainsFunc(c, unicode.IsSpace) || strings.Count(c, "@") != 1 {
			t.Fatalf("canonical email %q has whitespace or multiple @", c)
		}
		if strings.ToLower(c) != c {
			t.Fatalf("canonical email %q is not lower-case", c)
		}
		again, _, err := Email(c)
		if err != nil || again != c {
			t.Fatalf("Email not idempotent: %q -> %q -> %q (%v)", raw, c, again, err)
		}
		d := EmailDomain(c)
		for _, r := range d {
			if r > unicode.MaxASCII {
				t.Fatalf("domain %q not ASCII", d)
			}
		}
	})
}

func FuzzUsername(f *testing.F) {
	for _, s := range []string{"Alice", "ａｄｍｉｎ", "bob.smith", "x", "a_b-c"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := Username(raw)
		if err != nil {
			return
		}
		if again, err := Username(c); err != nil || again != c {
			t.Fatalf("Username not idempotent: %q -> %q -> %q", raw, c, again)
		}
		if reserved[c] {
			t.Fatalf("reserved name %q accepted", c)
		}
	})
}

func FuzzDomain(f *testing.F) {
	for _, s := range []string{"Example.COM.", "bücher.example", "xn--bcher-kva.example", "a", "-a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := Domain(raw)
		if err != nil {
			return
		}
		if again, err := Domain(c); err != nil || again != c {
			t.Fatalf("Domain not idempotent: %q -> %q -> %q", raw, c, again)
		}
	})
}

func FuzzPhone(f *testing.F) {
	for _, s := range []string{"+1 (555) 010-0000", "+4915112345678", "0049", "+0123"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		c, err := Phone(raw)
		if err != nil {
			return
		}
		if again, err := Phone(c); err != nil || again != c {
			t.Fatalf("Phone not idempotent: %q -> %q", raw, c)
		}
	})
}
