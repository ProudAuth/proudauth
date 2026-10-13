package egress

import (
	"errors"
	"net/netip"
	"testing"
)

// TestResidency covers PRV-003: with a residency policy, only listed hosts
// (or hosts under a listed .suffix) may be contacted, at registration and at
// connection time.
func TestResidency(t *testing.T) {
	defer SetResidency(nil)
	if !HostAllowed("anything.example") {
		t.Fatal("no policy must allow every host")
	}
	SetResidency([]string{"hooks.eu.example", ".eu-west.example"})
	for host, want := range map[string]bool{"hooks.eu.example": true, "HOOKS.EU.EXAMPLE.": true, "a.eu-west.example": true, "eu-west.example": true,
		"hooks.us.example": false, "evil-eu-west.example": false, "1.1.1.1": false} {
		if got := HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
	if err := (Policy{}).ValidateURL("https://hooks.us.example/x"); !errors.Is(err, ErrResidency) {
		t.Fatalf("registration outside the policy: %v", err)
	}
	if _, err := (Policy{}).Client().Get("https://1.1.1.1/"); !errors.Is(err, ErrResidency) {
		t.Fatalf("connection outside the policy: %v", err)
	}
}

// TestTransitionAddressesBlocked: IPv6 transition prefixes that tunnel IPv4
// are refused, so a private IPv4 target cannot hide inside them.
func TestTransitionAddressesBlocked(t *testing.T) {
	for _, a := range []string{"2002:a00:1::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b:1::a00:1"} {
		if (Policy{}).Allowed(netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
	if !(Policy{}).Allowed(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Error("public IPv6 refused")
	}
}
