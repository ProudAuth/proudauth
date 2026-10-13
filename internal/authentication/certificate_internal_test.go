package authentication

import (
	"crypto/x509"
	"testing"
)

// TestCertificateBudgetSubject covers PROV-016's attempt budget: before the
// transaction names an account, attempts are counted per certificate and
// client network, never against one subject the whole realm shares; after
// identify they count against the account.
func TestCertificateBudgetSubject(t *testing.T) {
	a, b := &x509.Certificate{Raw: []byte("certificate a")}, &x509.Certificate{Raw: []byte("certificate b")}
	near, sameNet, far := &Transaction{ClientIP: "203.0.113.7"}, &Transaction{ClientIP: "203.0.113.200"}, &Transaction{ClientIP: "198.51.100.1"}
	if certificateBudgetSubject(near, a) != certificateBudgetSubject(sameNet, a) {
		t.Error("one certificate from one /24 network is one budget")
	}
	if certificateBudgetSubject(near, a) == certificateBudgetSubject(near, b) {
		t.Error("two certificates shared a budget")
	}
	if certificateBudgetSubject(near, a) == certificateBudgetSubject(far, a) {
		t.Error("two networks shared a budget")
	}
	if s := certificateBudgetSubject(&Transaction{}, a); s == "" || s == certificateBudgetSubject(&Transaction{}, b) {
		t.Errorf("without a client address the certificate still keys the budget: %q", s)
	}
	if s := certificateBudgetSubject(&Transaction{UserID: "usr_1", ClientIP: "203.0.113.7"}, a); s != "usr_1" {
		t.Errorf("after identify the account keys the budget: %q", s)
	}
}
