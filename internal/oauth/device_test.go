package oauth

import "testing"

// TestNormalizeUserCode pins the user-code normalization applied when the
// code is stored and when the user enters it (RFC 8628 §6.1): surrounding
// space trimmed, hyphens and spaces dropped, letters upper-cased.
func TestNormalizeUserCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"WDJBMJHT", "WDJBMJHT"},
		{"wdjb-mjht", "WDJBMJHT"},
		{"  wdjb mjht  ", "WDJBMJHT"},
		{"\twdjb-mjht\n", "WDJBMJHT"},
		{"w-d-j-b m j h t", "WDJBMJHT"},
		{"wdjb\tmjht", "WDJB\tMJHT"},
		{"wdjb_mjht", "WDJB_MJHT"},
		{"----", ""},
	}
	for _, tc := range cases {
		if got := normalizeUserCode(tc.in); got != tc.want {
			t.Errorf("normalizeUserCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNilIfEmpty(t *testing.T) {
	if got := nilIfEmpty(""); got != nil {
		t.Fatalf("nilIfEmpty(\"\") = %q, want nil", *got)
	}
	if got := nilIfEmpty("org_1"); got == nil || *got != "org_1" {
		t.Fatalf("nilIfEmpty(\"org_1\") = %v, want a pointer to org_1", got)
	}
}
