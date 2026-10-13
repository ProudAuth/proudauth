package canonical

import (
	"testing"
	"unicode/utf8"
)

func TestTruncateKeepsUTF8(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"héllo", 2, "h"},
		{"日本語", 4, "日"},
		{"a\xffb", 5, "ab"},
		{"", 3, ""},
	} {
		got := Truncate(c.in, c.n)
		if got != c.want || !utf8.ValidString(got) || len(got) > c.n {
			t.Errorf("Truncate(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}
