package canonical

import "testing"

func TestEmailCanonicalization(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"  Alice@Example.COM ", "alice@example.com", true},
		{"first.last+tag@example.com", "first.last+tag@example.com", true}, // dots and tags are preserved (REG-003)
		{"firstlast@example.com", "firstlast@example.com", true},
		{"user@bücher.example", "user@xn--bcher-kva.example", true},
		{"no-at-sign", "", false},
		{"a@b@example.com", "", false},
		{"user@localhost", "", false},
		{".lead@example.com", "", false},
		{"dou..ble@example.com", "", false},
		{"sp ace@example.com", "", false},
	}
	for _, c := range cases {
		got, _, err := Email(c.in)
		if (err == nil) != c.ok {
			t.Fatalf("Email(%q) err=%v, want ok=%v", c.in, err, c.ok)
		}
		if c.ok && got != c.want {
			t.Fatalf("Email(%q)=%q want %q", c.in, got, c.want)
		}
	}
	// Dots and tags remain distinct identities.
	a, _, _ := Email("first.last@example.com")
	b, _, _ := Email("firstlast@example.com")
	if a == b {
		t.Fatal("dots must not be stripped")
	}
}

func TestUsernameAndPhone(t *testing.T) {
	if _, err := Username("admin"); err != ErrReservedName {
		t.Fatalf("reserved names must be rejected: %v", err)
	}
	if u, err := Username("Ａlice_01"); err != nil || u != "alice_01" {
		t.Fatalf("NFKC username: %q %v", u, err)
	}
	if _, err := Username("bad name"); err == nil {
		t.Fatal("spaces rejected")
	}
	if p, err := Phone("+1 (415) 555-0100"); err != nil || p != "+14155550100" {
		t.Fatalf("phone: %q %v", p, err)
	}
	if _, err := Phone("4155550100"); err == nil {
		t.Fatal("non-E.164 rejected")
	}
}
