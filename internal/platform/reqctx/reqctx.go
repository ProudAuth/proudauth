// Package reqctx carries per-request correlation and network context.
package reqctx

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

type key int

const infoKey key = 1

// Info is request-scoped, non-secret context.
type Info struct {
	RequestID string
	TraceID   string
	SpanID    string
	Sampled   bool
	ClientIP  string // derived only through trusted proxies (SEC-001)
	UserAgent string
	Origin    string
}

// With stores info in ctx.
func With(ctx context.Context, info Info) context.Context {
	return context.WithValue(ctx, infoKey, info)
}

// From returns the request info (zero value when absent).
func From(ctx context.Context) Info {
	i, _ := ctx.Value(infoKey).(Info)
	return i
}

// NetworkContext returns a privacy-reduced network hint: /24 for IPv4 and /48 for
// IPv6 (PRV-002). The full address is retained only when explicitly configured.
func NetworkContext(ip string, full bool) string {
	if full {
		a, ok := parseAddr(ip)
		if !ok {
			return ""
		}
		return a.String()
	}
	return NetworkPrefix(ip, 24, 48)
}

// NetworkPrefix returns the network of an address as a prefix in canonical
// form ("192.0.2.0/24", "2001:db8:1::/48"): the first v4Bits bits of an IPv4
// address (an IPv4-mapped IPv6 address counts as IPv4) or the first v6Bits of
// an IPv6 address, without zone. It returns "" for an empty or unparsable
// address. Abuse budgets count per-network budgets on /32 and /64 prefixes and
// the wider ones on /24 and /48 (SEC-006, ABU-001); logs and audit records
// keep /24 and /48 (PRV-002).
func NetworkPrefix(ip string, v4Bits, v6Bits int) string {
	a, ok := parseAddr(ip)
	if !ok {
		return ""
	}
	bits := v6Bits
	if a.Is4() {
		bits = v4Bits
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// parseAddr parses an address without zone, IPv4-mapped IPv6 as IPv4.
func parseAddr(ip string) (netip.Addr, bool) {
	if ip == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// TruncateUA bounds stored user-agent strings.
func TruncateUA(ua string) string {
	ua = strings.ToValidUTF8(strings.TrimSpace(ua), "")
	if len(ua) <= 256 {
		return ua
	}
	n := 256
	for n > 0 && !utf8.RuneStart(ua[n]) {
		n--
	}
	return ua[:n]
}

// ParseTraceparent validates a W3C trace-context traceparent header
// ("00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>") and returns the trace
// ID and sampled flag. Malformed or all-zero values are rejected (OPS-003).
func ParseTraceparent(h string) (traceID string, sampled bool, ok bool) {
	if len(h) != 55 || h[2] != '-' || h[35] != '-' || h[52] != '-' || h[:2] != "00" {
		return "", false, false
	}
	isHex := func(s string) bool {
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	trace, parent, flags := h[3:35], h[36:52], h[53:55]
	if !isHex(trace) || !isHex(parent) || !isHex(flags) || strings.Trim(trace, "0") == "" || strings.Trim(parent, "0") == "" {
		return "", false, false
	}
	f, err := strconv.ParseUint(flags, 16, 8)
	return trace, err == nil && f&1 == 1, true
}

// Traceparent renders the outbound header for the current span.
func (i Info) Traceparent() string {
	if i.TraceID == "" || i.SpanID == "" {
		return ""
	}
	flags := "00"
	if i.Sampled {
		flags = "01"
	}
	return "00-" + i.TraceID + "-" + i.SpanID + "-" + flags
}
