package session

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"

	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/secret"
)

// BrowserState is the OP browser state of OpenID Connect Session Management
// 1.0 (OIDC-014) for a session: a keyed digest of the session ID, so it
// changes with the session and reveals nothing about it. The check-session
// iframe reads it from a script-readable cookie.
func BrowserState(kr *keys.Keyring, sessionID string) string {
	b := kr.DeriveBytes(keys.PurposeLookup, "opbs", sessionID)
	return base64.RawURLEncoding.EncodeToString(b[:16])
}

// SessionState is the session_state authorization response parameter:
// SHA-256 over client ID, RP origin, browser state and a fresh salt, in hex,
// followed by "." and the salt. The iframe recomputes it with the origin of
// the message it receives, so a value is only "unchanged" for that origin.
func SessionState(clientID, redirectURI, opbs string) string {
	salt := hex.EncodeToString(secret.Random(8))
	sum := sha256.Sum256([]byte(clientID + " " + Origin(redirectURI) + " " + opbs + " " + salt))
	return hex.EncodeToString(sum[:]) + "." + salt
}

// Origin returns scheme://host[:port] of a URL.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
