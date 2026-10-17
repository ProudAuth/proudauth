package egress

import (
	"net/netip"
	"testing"
)

// TestAllowedRefusesZonedAddresses (SEC-007, QA-008): netip prefixes never
// contain an address that carries a zone, so "fc00::%0" or "fe80::1%eth0"
// slipped past every blocked range and counted as global unicast. FuzzAllowed
// found it; the ranges are now compared without the zone, and a zoned address
// is never public.
func TestAllowedRefusesZonedAddresses(t *testing.T) {
	public := Policy{}
	for _, s := range []string{"fc00::%0", "fd00::1%eth0", "fe80::1%lo0", "::1%0", "2001:db8::1%x", "2606:4700::1111%eth0"} {
		if public.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("public-only policy allowed zoned address %s", s)
		}
	}
	if !public.Allowed(netip.MustParseAddr("2606:4700::1111")) {
		t.Error("public-only policy refused a public address without a zone")
	}
	private := Policy{AllowPrivate: true}
	for _, s := range []string{"fe80::1%eth0", "fc00::%0"} {
		if !private.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("allow_private_network refused %s", s)
		}
	}
	for _, s := range []string{"::%0", "ff02::1%eth0"} {
		if private.Allowed(netip.MustParseAddr(s)) {
			t.Errorf("allow_private_network allowed unspecified or multicast %s", s)
		}
	}
	listed := Policy{AllowCIDRs: []string{"fc00::/7"}}
	if !listed.Allowed(netip.MustParseAddr("fd00::1%eth0")) {
		t.Error("an allowed CIDR must match the address without its zone")
	}
}
