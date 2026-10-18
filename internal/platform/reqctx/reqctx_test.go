package reqctx

import "testing"

func TestParseTraceparent(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		sampled bool
	}{
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", true, true},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00", true, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-03", true, true},
		{"00-00000000000000000000000000000000-00f067aa0ba902b7-01", false, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", false, false},
		{"00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", false, false},
		{"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", false, false},
		{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		id, sampled, ok := ParseTraceparent(c.in)
		if ok != c.ok || (ok && (sampled != c.sampled || id != c.in[3:35])) {
			t.Errorf("%q: got (%q, %v, %v)", c.in, id, sampled, ok)
		}
	}
	i := Info{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7", Sampled: true}
	if got := i.Traceparent(); got != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("Traceparent() = %q", got)
	}
}

// TestNetworkPrefix covers SEC-006, ABU-001 and PRV-002: abuse budgets count
// an IPv4 address as itself (/32) and an IPv6 address by its /64, their wider
// budgets by /24 and /48, and logs keep /24 and /48. IPv4-mapped IPv6 counts
// as IPv4, zones are dropped, and anything unparsable has no network.
func TestNetworkPrefix(t *testing.T) {
	for _, c := range []struct {
		ip            string
		fine, coarse  string
		context, full string
	}{
		{"203.0.113.77", "203.0.113.77/32", "203.0.113.0/24", "203.0.113.0/24", "203.0.113.77"},
		{"::ffff:203.0.113.77", "203.0.113.77/32", "203.0.113.0/24", "203.0.113.0/24", "203.0.113.77"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64", "2001:db8:1::/48", "2001:db8:1::/48", "2001:db8:1:2:3:4:5:6"},
		{"2001:db8:1:2:ffff::1", "2001:db8:1:2::/64", "2001:db8:1::/48", "2001:db8:1::/48", "2001:db8:1:2:ffff::1"},
		{"fe80::1%eth0", "fe80::/64", "fe80::/48", "fe80::/48", "fe80::1"},
		{"", "", "", "", ""},
		{"not-an-address", "", "", "", ""},
		{"203.0.113.77:443", "", "", "", ""},
	} {
		if got := NetworkPrefix(c.ip, 32, 64); got != c.fine {
			t.Errorf("NetworkPrefix(%q, 32, 64) = %q, want %q", c.ip, got, c.fine)
		}
		if got := NetworkPrefix(c.ip, 24, 48); got != c.coarse {
			t.Errorf("NetworkPrefix(%q, 24, 48) = %q, want %q", c.ip, got, c.coarse)
		}
		if got := NetworkContext(c.ip, false); got != c.context {
			t.Errorf("NetworkContext(%q, false) = %q, want %q", c.ip, got, c.context)
		}
		if got := NetworkContext(c.ip, true); got != c.full {
			t.Errorf("NetworkContext(%q, true) = %q, want %q", c.ip, got, c.full)
		}
	}
}
