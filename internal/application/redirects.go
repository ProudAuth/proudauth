package application

import (
	"net"
	"net/url"
	"strings"
)

// ValidateRedirectRegistration checks a redirect URI at registration time (APP-004).
// It rejects wildcards, fragments, userinfo, relative URIs and (in production) plain
// http except for native loopback redirects.
func ValidateRedirectRegistration(raw, clientType, environment string) string {
	if raw == "" || len(raw) > 2048 {
		return "redirect URI must be 1..2048 bytes"
	}
	if strings.ContainsAny(raw, "*\\ \t\r\n") {
		return "wildcards, backslashes and whitespace are not allowed"
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return "redirect URI must be absolute"
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return "redirect URI must not contain a fragment"
	}
	if u.User != nil {
		return "redirect URI must not contain userinfo"
	}
	if u.Opaque != "" && u.Scheme != "" && !isPrivateUseScheme(u.Scheme) {
		return "redirect URI must be hierarchical"
	}
	lowerRaw := strings.ToLower(raw)
	if strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") || strings.Contains(u.Path, "/./") ||
		strings.Contains(lowerRaw, "%2e") || strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") {
		return "redirect URI must not contain path traversal or encoded separators"
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return "https redirect URI requires a host"
		}
		if environment == "production" && isLoopbackHost(u.Hostname()) {
			return "production clients must not redirect to localhost (APP-015)"
		}
		return ""
	case "http":
		if isLoopbackIP(u.Hostname()) && (clientType == "native" || clientType == "device") {
			return "" // RFC 8252 §7.3 loopback redirect
		}
		if environment != "production" && isLoopbackHost(u.Hostname()) {
			return ""
		}
		return "http redirect URIs are only allowed for native loopback or non-production localhost"
	default:
		if clientType == "native" && isPrivateUseScheme(u.Scheme) {
			return "" // RFC 8252 §7.1 private-use URI scheme
		}
		return "unsupported redirect URI scheme"
	}
}

func isPrivateUseScheme(s string) bool {
	// Reverse-domain private-use schemes contain a dot (RFC 8252 §7.1).
	return strings.Contains(s, ".") && !strings.ContainsAny(s, "/:")
}

func isLoopbackIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || isLoopbackIP(h)
}

// MatchRedirect performs exact string comparison against the registered redirects.
// The only exception is the RFC 8252 native loopback rule: for a registered
// http://127.0.0.1/... or http://[::1]/... redirect, any port is accepted while the
// scheme, host, path and query must still match exactly.
func MatchRedirect(registered []string, requested, clientType string) bool {
	if requested == "" {
		return false
	}
	for _, r := range registered {
		if r == requested {
			return true
		}
	}
	if clientType != "native" && clientType != "device" {
		return false
	}
	ru, err := url.Parse(requested)
	if err != nil || ru.Scheme != "http" || !isLoopbackIP(ru.Hostname()) || ru.User != nil || ru.Fragment != "" {
		return false
	}
	for _, r := range registered {
		gu, err := url.Parse(r)
		if err != nil || gu.Scheme != "http" || !isLoopbackIP(gu.Hostname()) {
			continue
		}
		if gu.Hostname() == ru.Hostname() && gu.EscapedPath() == ru.EscapedPath() && gu.RawQuery == ru.RawQuery {
			return true
		}
	}
	return false
}

// ValidateOrigin checks a browser origin registration (APP-005).
func ValidateOrigin(raw, environment string) (string, string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "origin must be scheme://host[:port] with no path"
	}
	if strings.Contains(raw, "*") {
		return "", "wildcard origins are not allowed"
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && environment != "production" && isLoopbackHost(u.Hostname())) {
		return "", "origins must use https (http only for non-production localhost)"
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), ""
}
