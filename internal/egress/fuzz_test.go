package egress

import (
	"net/netip"
	"testing"
)

// FuzzAllowed (QA-003, SEC-007): without private access, loopback,
// link-local, private and unspecified addresses are never allowed, whatever
// form the address takes (IPv4, IPv6, IPv4-mapped).
func FuzzAllowed(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "::1", "::ffff:10.0.0.1", "169.254.169.254", "fd00::1", "8.8.8.8", "0.0.0.0", "100.64.0.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return
		}
		u := ip.Unmap()
		if (Policy{}).Allowed(ip) && (u.IsLoopback() || u.IsPrivate() || u.IsLinkLocalUnicast() || u.IsUnspecified() || u.IsMulticast()) {
			t.Fatalf("public-only policy allowed %s", ip)
		}
	})
}
