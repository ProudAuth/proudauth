// Package reqctx carries per-request correlation and network context.
package reqctx

import (
	"context"
	"net"
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
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if full {
		return parsed.String()
	}
	if v4 := parsed.To4(); v4 != nil {
		return net.IPv4(v4[0], v4[1], v4[2], 0).String() + "/24"
	}
	mask := net.CIDRMask(48, 128)
	return parsed.Mask(mask).String() + "/48"
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
