package e2e

import (
	"context"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/bench"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// TestBenchSuiteSmoke runs every identity-bench scenario briefly against a
// live server (NFR-003..NFR-008): the seed builds through the public API, the
// workloads succeed, adversarial inputs meet their budgets and the
// consistency invariants hold.
func TestBenchSuiteSmoke(t *testing.T) {
	// One client address drives every simulated user, so per-IP login
	// budgets are raised as an operator would for a load-test source; the
	// per-identifier, per-realm and send budgets stay as configured.
	h := NewHarness(t, func(c *configuration.Config) {
		c.Delivery.EgressAllowlist = []string{"127.0.0.1/32"}
		c.Security.RateLimits.LoginPerIP = 100000
		c.Security.RateLimits.LoginPerRealm = 100000
		c.Security.RateLimits.TokenPerClient = 100000
	})
	base, err := url.Parse(h.Base)
	if err != nil {
		t.Fatal(err)
	}
	f := fixtureOn(t, h, func(p *realm.Policy) {
		// Match bench-local: an IP issuer cannot supply a valid WebAuthn
		// RP ID. Explicit localhost RP/origins preserve the public API path.
		p.Login.Passkeys = true
		p.WebAuthn.RPID = "localhost"
		p.WebAuthn.Origins = []string{"http://localhost:" + base.Port()}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Exercise the real SMTP transport, without sending mail outside the
	// disposable deployment or retaining message bodies.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	smtpSink := bench.NewSMTPSink()
	smtpDone := make(chan error, 1)
	go func() { smtpDone <- smtpSink.Serve(ctx, ln) }()
	defer func() {
		cancel()
		if err := <-smtpDone; err != nil {
			t.Error(err)
		}
	}()
	h.App.D.Cfg.Delivery.Email.Adapter = "smtp"
	h.App.D.Cfg.Delivery.Email.SMTPHost = "127.0.0.1"
	h.App.D.Cfg.Delivery.Email.SMTPPort = ln.Addr().(*net.TCPAddr).Port
	h.App.D.Cfg.Delivery.Email.SMTPTLS = "none"
	h.App.D.Cfg.Delivery.Email.From = "noreply@bench.test"
	if err := h.App.D.Cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	h.App.Notify.DevSink = false
	h.App.Notify.Email = &notification.SMTPSender{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, TLSMode: "none"}
	w := worker.New(h.App, "bench")
	var fastClock atomic.Bool
	initialClock := h.Clock.Now()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			// Smoke only: advance the server clock through real retry due
			// times, without sleeping 10-12.5 seconds for every cycle.
			// Keep the complete smoke within the static admin token lifetime.
			if fastClock.Load() && h.Clock.Now().Sub(initialClock) < 240*time.Second {
				h.Clock.Advance(time.Second)
			}
			w.RunOnce(ctx)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer wg.Wait()
	defer cancel()
	c := bench.NewClient(h.Srv.URL, "main", 4)
	c.HTTP = h.Srv.Client()
	d, err := bench.Seed(ctx, c, bench.StaticToken(f.AdminToken), bench.SeedSpec{Seed: 7, Users: 30, Organizations: 3, LargeOrgUsers: 12, MachineClients: 2,
		RoleDepth: 3, GroupMembers: 5}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &bench.Env{Client: c, Admin: bench.StaticToken(f.AdminToken), Seed: d, Now: h.Clock.Now}
	metadata, err := bench.NewMetadataReceiver("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	metadataDone := make(chan error, 1)
	go func() { metadataDone <- metadata.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-metadataDone; err != nil {
			t.Error(err)
		}
	}()
	caFile := t.TempDir() + "/metadata-ca.pem"
	if err := os.WriteFile(caFile, metadata.CAPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	h.App.Workload.Egress.AllowCIDRs = []string{"127.0.0.1/32"}
	h.App.Workload.Egress.RootCAs = metadata.Roots()
	env.MetadataURL, env.MetadataCA = metadata.URL(), caFile
	expect := map[string]func(map[string]int64) bool{
		"client-credentials": onlyOK, "introspection": onlyOK, "password-login": onlyOK, "refresh": onlyOK, "policy": onlyOK,
		"audit-query": onlyOK, "import": onlyOK, "refresh-race": onlyOK,
		"passkey-assertion": onlyOK, "scim": onlyOK,
		"email-delivery":   onlyOK,
		"webhook-delivery": onlyOK, "webhook-retry": onlyOK,
		"mixed": func(o map[string]int64) bool {
			for k := range o {
				if !strings.HasSuffix(k, ":ok") {
					return false
				}
			}
			return len(o) > 0
		},
		"mixed-extended": func(o map[string]int64) bool {
			for k := range o {
				if !strings.HasSuffix(k, ":ok") {
					return false
				}
			}
			return len(o) > 0
		},
		"mixed-email": func(o map[string]int64) bool {
			for k := range o {
				if !strings.HasSuffix(k, ":ok") {
					return false
				}
			}
			return len(o) > 0
		},
		"mixed-delivery": func(o map[string]int64) bool {
			for k := range o {
				if !strings.HasSuffix(k, ":ok") {
					return false
				}
			}
			return len(o) > 0
		},
		"unknown-key":     func(o map[string]int64) bool { return o["ok"] > 0 && o["invariant_violation"] == 0 },
		"failed-password": func(o map[string]int64) bool { return o["invariant_violation"] == 0 && o["http_401"]+o["http_429"] > 0 },
		"otp-guess": func(o map[string]int64) bool {
			for k := range o {
				if k != "invalid_proof" && k != "rate_limited" && k != "transaction_limit" {
					return false
				}
			}
			return o["invalid_proof"] == 10 && o["rate_limited"] > 0
		},
		"complex-filter": func(o map[string]int64) bool {
			for k := range o {
				if k != "bounded_true" && k != "bounded_false" && k != "invalid_filter_nodes" && k != "invalid_filter_bytes" && k != "rate_limited" {
					return false
				}
			}
			return o["bounded_true"] > 0 && o["bounded_false"] > 0 && o["invalid_filter_nodes"] > 0 && o["invalid_filter_bytes"] > 0
		},
		"oversized-input": func(o map[string]int64) bool { return o["http_413"] > 0 && len(o) == 1 },
		"complex-audit-filter": func(o map[string]int64) bool {
			labels := []string{"compound_match", "compound_empty", "literal_prefix_empty", "invalid_network", "invalid_time", "cursor_scope_rejected", "cursor_page"}
			if len(o) != len(labels) {
				return false
			}
			for _, label := range labels {
				if o[label] <= 0 {
					return false
				}
			}
			return true
		},
		"notification-flood": func(o map[string]int64) bool { return o["http_429"] > 0 },
		"metadata-fetch": func(o map[string]int64) bool {
			labels := []string{"valid:ok", "unknown_key_rejected", "malformed_rejected", "oversized_rejected", "http_failure_rejected", "redirect_rejected", "timeout_rejected", "private_rejected"}
			if len(o) != len(labels) {
				return false
			}
			for _, label := range labels {
				if o[label] <= 0 {
					return false
				}
			}
			return true
		},
	}
	expect["complex-group-filter"] = expect["complex-filter"]
	for name, mk := range bench.Scenarios() {
		ok, known := expect[name]
		if !known {
			t.Errorf("scenario %s has no smoke expectation", name)
			continue
		}
		ops := int64(12)
		if name == "notification-flood" || name == "failed-password" || name == "otp-guess" {
			ops = 40
		}
		fastClock.Store(name == "webhook-retry" || name == "mixed-delivery")
		r, err := bench.Run(ctx, env, mk(), bench.Options{Concurrency: 2, Operations: ops, Seed: 3})
		fastClock.Store(false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !r.Complete || !ok(r.Outcomes) || r.LatencyMS.P50 <= 0 || len(r.Histogram) == 0 {
			t.Errorf("%s: outcomes %v latency %+v", name, r.Outcomes, r.LatencyMS)
		}
	}
	if smtpSink.Snapshot().Accepted < 12 {
		t.Error("completed email workload without actual SMTP acceptance")
	}
}

func onlyOK(o map[string]int64) bool { return o["ok"] > 0 && len(o) == 1 }

// TestTokenIssuanceBeyondConnectionPool: more concurrent token requests,
// refreshes, refresh races and sign-ins than the server has database
// connections (storage.max_conns, 20 here as by default) all complete, and
// a refresh race still lets exactly one redemption through without server
// errors (NFR-002, NFR-007). Each of these runs a transaction whose code
// also runs statements outside it on other pool connections; before
// transactions were bounded to fewer than the pool's connections
// (storage.TxSlots), every connection could be held by a transaction waiting
// for another one, and identity-bench at 32 concurrent requests saw token
// issuance, refresh and sign-in stall until statement_timeout or the request
// deadline (HTTP 500).
func TestTokenIssuanceBeyondConnectionPool(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.RateLimits.LoginPerIP = 100000
		c.Security.RateLimits.LoginPerRealm = 100000
		c.Security.RateLimits.LoginPerClient = 100000
		c.Security.RateLimits.TokenPerClient = 100000
	})
	f := fixtureOn(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	w := worker.New(h.App, "bench")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			w.RunOnce(ctx)
			time.Sleep(50 * time.Millisecond)
		}
	}()
	defer wg.Wait()
	defer cancel()
	c := bench.NewClient(h.Srv.URL, "main", 64)
	d, err := bench.Seed(ctx, c, bench.StaticToken(f.AdminToken), bench.SeedSpec{Seed: 11, Users: 400, Organizations: 4, LargeOrgUsers: 20,
		MachineClients: 4, RoleDepth: 2}, nil)
	if err != nil {
		t.Fatal(err)
	}
	env := &bench.Env{Client: c, Admin: bench.StaticToken(f.AdminToken), Seed: d}
	for _, run := range []struct {
		scenario    string
		concurrency int
		ops         int64
	}{
		{"client-credentials", 64, 1500},
		{"refresh", 64, 1000},
		{"password-login", 48, 300},
		{"refresh-race", 8, 24}, // 8 races of 8 redemptions at once
	} {
		start := time.Now()
		r, err := bench.Run(ctx, env, bench.Scenarios()[run.scenario](), bench.Options{Concurrency: run.concurrency, Operations: run.ops,
			Duration: 25 * time.Second, Seed: 5})
		if err != nil {
			t.Fatalf("%s: %v", run.scenario, err)
		}
		if r.Operations != run.ops || len(r.Outcomes) != 1 || r.Outcomes["ok"] != run.ops {
			t.Errorf("%s at concurrency %d: %d of %d operations in %s, outcomes %v (stalled on the connection pool?)", run.scenario,
				run.concurrency, r.Operations, run.ops, time.Since(start).Round(time.Millisecond), r.Outcomes)
		}
	}
}
