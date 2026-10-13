// Package canonical implements identifier canonicalization (REG-002, REG-003).
//
// Documented comparison rules (docs/protocols/identifiers.md):
//   - Email: surrounding whitespace removed; Unicode NFC; the domain is converted to
//     its IDNA ASCII form and lowercased; the local part is lowercased for comparison.
//     Dots and "+tags" are NOT stripped, because many providers treat them as
//     distinct mailboxes. The original value is preserved separately for display.
//   - Username: Unicode NFKC, lowercased, restricted to [a-z0-9._-], 3..64 chars,
//     and must not be a reserved name.
//   - Phone: E.164 only (+ followed by 8..15 digits) after removing spaces, dashes,
//     dots and parentheses.
package canonical

import (
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

// Limits (NFR-001).
const (
	MaxEmailBytes     = 254
	MaxLocalPartBytes = 64
	MinUsername       = 3
	MaxUsername       = 64
)

var (
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidUsername = errors.New("invalid username")
	ErrReservedName    = errors.New("reserved username")
	ErrInvalidPhone    = errors.New("invalid phone number")
	ErrInvalidDomain   = errors.New("invalid domain")
)

var reserved = map[string]bool{
	"admin": true, "administrator": true, "root": true, "system": true, "support": true,
	"security": true, "postmaster": true, "hostmaster": true, "webmaster": true, "abuse": true,
	"noreply": true, "no-reply": true, "help": true, "operator": true, "proudauth": true,
	"anonymous": true, "guest": true, "null": true, "undefined": true, "me": true,
}

var idnaProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(true), idna.Transitional(false))

// Domain returns the canonical ASCII form of a DNS domain name.
func Domain(d string) (string, error) {
	d = strings.TrimSuffix(strings.TrimSpace(d), ".")
	if d == "" || len(d) > 253 {
		return "", ErrInvalidDomain
	}
	ascii, err := idnaProfile.ToASCII(d)
	if err != nil || ascii == "" || !strings.Contains(ascii, ".") || len(ascii) > 253 {
		return "", ErrInvalidDomain
	}
	ascii = strings.ToLower(ascii)
	// Every label must be a non-empty LDH label (RFC 1123): no empty labels from
	// "..", no leading/trailing hyphens, at most 63 octets.
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidDomain
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", ErrInvalidDomain
			}
		}
	}
	return ascii, nil
}

// Email returns (canonical, display) forms of an email address.
func Email(raw string) (canonicalValue, display string, err error) {
	s := strings.TrimSpace(raw)
	if !utf8.ValidString(s) || len(s) == 0 || len(s) > MaxEmailBytes {
		return "", "", ErrInvalidEmail
	}
	s = norm.NFC.String(s)
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 || strings.Count(s, "@") != 1 {
		return "", "", ErrInvalidEmail
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > MaxLocalPartBytes || strings.ContainsAny(local, " \t\r\n<>()[],;:\\\"") {
		return "", "", ErrInvalidEmail
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", "", ErrInvalidEmail
	}
	for _, r := range local {
		if r < 0x21 || r == 0x7f {
			return "", "", ErrInvalidEmail
		}
	}
	d, err := Domain(domain)
	if err != nil {
		return "", "", ErrInvalidEmail
	}
	canonicalValue = strings.ToLower(local) + "@" + d
	if len(canonicalValue) > MaxEmailBytes {
		return "", "", ErrInvalidEmail
	}
	return canonicalValue, local + "@" + domain, nil
}

// EmailDomain returns the canonical domain portion of a canonical email.
func EmailDomain(canonicalEmail string) string {
	at := strings.LastIndexByte(canonicalEmail, '@')
	if at < 0 {
		return ""
	}
	return canonicalEmail[at+1:]
}

// Username returns the canonical form of a username.
func Username(raw string) (string, error) {
	s := strings.ToLower(norm.NFKC.String(strings.TrimSpace(raw)))
	if len(s) < MinUsername || len(s) > MaxUsername {
		return "", ErrInvalidUsername
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-') {
			return "", ErrInvalidUsername
		}
	}
	if reserved[s] {
		return "", ErrReservedName
	}
	return s, nil
}

// Phone returns an E.164 phone number.
func Phone(raw string) (string, error) {
	s := strings.NewReplacer(" ", "", "-", "", ".", "", "(", "", ")", "").Replace(strings.TrimSpace(raw))
	if !strings.HasPrefix(s, "+") {
		return "", ErrInvalidPhone
	}
	digits := s[1:]
	if len(digits) < 8 || len(digits) > 15 || digits[0] == '0' {
		return "", ErrInvalidPhone
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", ErrInvalidPhone
		}
	}
	return s, nil
}

// Slug validates an organization slug: lowercase [a-z0-9-], 2..63, no leading/trailing dash.
func Slug(raw string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if len(s) < 2 || len(s) > 63 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return "", false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
			return "", false
		}
	}
	return s, true
}
