package canonical

import (
	"strings"
	"unicode/utf8"
)

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence,
// dropping invalid sequences first: stored and logged text stays valid.
func Truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
