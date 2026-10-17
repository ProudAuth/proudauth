package e2e

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestDirectorySignInDeadline covers NFR-002 and PROV-014: a sign-in whose
// directory accepts connections and never answers ends at
// directory.sign_in_timeout in total, across every configured endpoint,
// with the retryable upstream_unavailable outcome. Before the overall
// deadline each blackholed endpoint held the attempt, and its database
// transaction slot, for its own connect and operation timeouts in turn.
func TestDirectorySignInDeadline(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Directory.AllowPrivateNetwork = true
		c.Directory.ConnectTimeout = 2 * time.Second
		c.Directory.OperationTimeout = 3 * time.Second
		c.Directory.SignInTimeout = 2 * time.Second
	})
	f := fixtureOn(t, h)
	var endpoints []string
	for range 3 {
		endpoints = append(endpoints, "ldap://"+testutil.BlackholeTCP(t).Addr)
	}
	f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Blackholed LDAP", "kind": "ldap", "credential": "service secret",
		"config": map[string]any{"endpoints": endpoints, "bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase,
			"dialect": "openldap", "jit_provisioning": true}}), 201, "create connector")

	start := time.Now()
	r := passwordStep(h, "nobody.known", "a password for nobody 2026")
	elapsed := time.Since(start)
	if r.Status != 503 || r.Str("code") != "upstream_unavailable" || r.Header.Get("Retry-After") == "" {
		t.Fatalf("blackholed directory: %d %s", r.Status, r.Raw)
	}
	// 2 s of directory work plus the timing pad and the request's own
	// statements; without the bound it is 3 x (2 s + 3 s).
	if elapsed > 5*time.Second {
		t.Fatalf("sign-in against a blackholed directory took %s, past directory.sign_in_timeout (2s)", elapsed)
	}
	// Local accounts are unaffected.
	if lr := f.AccountToken("alice"); lr.Tokens.Str("access_token") == "" {
		t.Fatal("local sign-in failed during the directory outage")
	}
}

// TestDirectoryPasswordStepNotRetried covers DB-014: a password step that
// asks a directory runs once. A deadlock at its commit is returned instead
// of retried, so the directory never sees the search and bind twice.
func TestDirectoryPasswordStepNotRetried(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	srv := corpDirectory(t)
	addPerson(srv, "jit.user", "Jit", "User", "jit.user@corp.test", "jit user directory pass")
	f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Corp LDAP", "kind": "ldap", "credential": "service secret",
		"config": map[string]any{"endpoints": []string{srv.LDAPSURL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase,
			"user_base_dn": "ou=people," + corpBase, "dialect": "openldap", "jit_provisioning": true}}), 201, "create connector")

	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	txID := start.Str("transaction_id")
	h.Step(txID, cont, "identify", map[string]any{"identifier": "jit.user"})
	srv.ResetCounters()
	// The first transaction to commit after the directory was asked (the
	// password step) fails with a deadlock, which Tx retries unless the
	// step is marked NoRetry.
	var fired atomic.Bool
	clear := h.App.D.DB.SetFault(func(ctx context.Context, tx pgx.Tx, point string) error {
		if binds, _, _ := srv.Stats(); point == storage.FaultCommit && binds > 0 && fired.CompareAndSwap(false, true) {
			return &pgconn.PgError{Code: "40P01", Message: "injected deadlock"}
		}
		return nil
	})
	r := h.Step(txID, cont, "password", map[string]any{"password": "jit user directory pass"})
	clear()
	if !fired.Load() {
		t.Fatalf("the fault never fired: %d %s", r.Status, r.Raw)
	}
	binds, searches, _ := srv.Stats()
	// One attempt: the service bind, the login search and the user bind.
	if binds != 2 || searches != 1 {
		t.Fatalf("the directory was asked %d binds and %d searches for one password step (a retried step repeats them)", binds, searches)
	}
	if r.Status == 200 {
		t.Fatalf("a step whose commit failed reported success: %s", r.Raw)
	}
	if userIDByUsername(t, h, "jit.user") != "" {
		t.Fatal("the failed step provisioned the account")
	}
}
