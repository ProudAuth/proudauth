package authentication

import (
	"context"
	"crypto/x509"
	"testing"
)

// TestCertificateBudgetSubject covers PROV-016's attempt budget: before the
// transaction names an account, attempts are counted per certificate and
// client network, never against one subject the whole realm shares; after
// identify they count against the account.
func TestCertificateBudgetSubject(t *testing.T) {
	ctx := context.Background()
	a, b := &x509.Certificate{Raw: []byte("certificate a")}, &x509.Certificate{Raw: []byte("certificate b")}
	near, sameNet, far := &Transaction{ClientIP: "203.0.113.7"}, &Transaction{ClientIP: "203.0.113.200"}, &Transaction{ClientIP: "198.51.100.1"}
	if certificateBudgetSubject(ctx, near, a) != certificateBudgetSubject(ctx, sameNet, a) {
		t.Error("one certificate from one /24 network is one budget")
	}
	if certificateBudgetSubject(ctx, near, a) == certificateBudgetSubject(ctx, near, b) {
		t.Error("two certificates shared a budget")
	}
	if certificateBudgetSubject(ctx, near, a) == certificateBudgetSubject(ctx, far, a) {
		t.Error("two networks shared a budget")
	}
	if s := certificateBudgetSubject(ctx, &Transaction{}, a); s == "" || s == certificateBudgetSubject(ctx, &Transaction{}, b) {
		t.Errorf("without a client address the certificate still keys the budget: %q", s)
	}
	if s := certificateBudgetSubject(ctx, &Transaction{UserID: "usr_1", ClientIP: "203.0.113.7"}, a); s != "usr_1" {
		t.Errorf("after identify the account keys the budget: %q", s)
	}
}
