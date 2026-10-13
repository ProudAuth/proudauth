package egress

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// TestBlockedRanges covers EXT-006: private, loopback, link-local, CGNAT,
// unspecified and IPv4-mapped addresses are blocked by default; only an
// explicit operator allowlist opens an internal range.
func TestBlockedRanges(t *testing.T) {
	p := Policy{}
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "192.168.1.1", "::1", "fd00::1", "0.0.0.0", "::ffff:127.0.0.1", "100.64.0.1"} {
		if p.Allowed(netip.MustParseAddr(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	if !p.Allowed(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("public address blocked")
	}
	if !(Policy{AllowCIDRs: []string{"10.20.0.0/16"}}).Allowed(netip.MustParseAddr("10.20.1.1")) {
		t.Fatal("explicit internal allowlist ignored (EXT-007)")
	}
}

// TestConnectionTimeEnforcement covers EXT-006 and TEST-052: the address
// policy is applied to the resolved address when connecting, not only at
// registration (a hostname resolving to loopback is refused, which defeats
// DNS rebinding), and redirects are never followed.
func TestConnectionTimeEnforcement(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	// localhost resolves to loopback: refused at dial time even though the URL looks harmless.
	if _, err := (Policy{}).Client().Get(srv.URL); err == nil {
		t.Fatal("loopback destination reached (TEST-052)")
	}
	if err := (Policy{}).ValidateURL("http://localhost:1/hook"); err == nil {
		t.Fatal("registration-time check must refuse loopback")
	}
	if _, err := (Policy{AllowPrivate: true}).Client().Get(srv.URL); err != nil {
		t.Fatalf("explicitly allowed private destination: %v", err)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer redirect.Close()
	res, err := (Policy{AllowPrivate: true}).Client().Get(redirect.URL)
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatal("redirects must not be followed")
	}
}
