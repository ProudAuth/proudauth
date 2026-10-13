package bench

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type metadataFixture struct {
	profile, client, ref, subject string
	mu                            sync.Mutex
	assertion                     string
	expires                       time.Time
}
type metadataFetch struct {
	client            *http.Client
	base, privateBase string
	fixtures          []*metadataFixture
	next              atomic.Uint64
	prepared          bool
}

func (*metadataFetch) Name() string      { return "metadata-fetch" }
func (*metadataFetch) Adversarial() bool { return true }
func (*metadataFetch) Notes() []string {
	return []string{"eight alternating workload-federation profiles: valid ES256, unknown kid, malformed JWKS, valid JWKS plus whitespace over 1 MiB, HTTP 503, redirect, ten-second fetch timeout, and a live denied IPv6 loopback destination",
		"one operation is one public jwt-bearer token request; only the valid control may issue an access token, all other profiles must return 400 invalid_grant without tokens",
		"preparation probes each profile once and introspects the valid control; those upstream contacts consume the unchanged per-URI fetch budgets; adversarial warm-up uses benign discovery only",
		"receiver response counts and request times prove coalescing/cooldown, zero redirect-target/private-destination contacts; keys, assertions, client references and tokens are omitted",
		"one server process: five-minute good-key cache and one-minute unknown-key/failed-fetch cooldown; endpoint timeout ten seconds; IPv4 loopback explicitly allowed, IPv6 denied; successful and refused operations share the aggregate latency histogram",
		"assertions renew before their twenty-minute expiry; generic trust deliberately does not require jti; one fresh controlled receiver is required per run, fixture clients are decommissioned on cleanup"}
}

func (s *metadataFetch) call(ctx context.Context, path string, body any, out any) error {
	method := http.MethodGet
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(data))
		method = http.MethodPost
	}
	r, err := http.NewRequestWithContext(ctx, method, path, reader)
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(r)
	if err != nil {
		return errors.New("metadata receiver transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("metadata receiver HTTP %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out); err != nil {
			return errors.New("metadata receiver response invalid")
		}
	}
	return nil
}
func (s *metadataFetch) Prepare(ctx context.Context, e *Env) error {
	if e.Client == nil || e.Admin == nil || e.Seed == nil || e.MetadataURL == "" || e.MetadataCA == "" {
		return errors.New("metadata-fetch requires an MFA administrator, seed and fresh HTTPS metadata receiver/CA")
	}
	u, err := url.Parse(e.MetadataURL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("metadata receiver must be an IPv4 loopback HTTPS origin")
	}
	data, err := os.ReadFile(e.MetadataCA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return errors.New("metadata receiver CA is invalid")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	tr.MaxIdleConnsPerHost = max(e.Concurrency, 4)
	s.client = &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.base = u.String()
	s.privateBase = "https://" + net.JoinHostPort("::1", u.Port())
	for _, base := range []string{s.base, s.privateBase} {
		if err := s.call(ctx, base+"/ready", nil, nil); err != nil {
			return errors.New("metadata receiver IPv4/IPv6 readiness failed")
		}
	}
	var initial MetadataStats
	if err := s.call(ctx, s.base+"/stats", nil, &initial); err != nil {
		return err
	}
	if len(initial.Profiles) != 9 || initial.Inflight != 0 {
		return errors.New("metadata receiver profile catalogue incomplete")
	}
	for _, c := range initial.Profiles {
		if c.Requests != 0 || c.Bytes != 0 || len(c.Starts) != 0 {
			return errors.New("metadata-fetch requires a fresh receiver, not reused counters")
		}
	}
	prefix, err := runPrefix(e.Seed, "metadata")
	if err != nil {
		return err
	}
	api := func(method, path string, doc any, want int) (*Response, error) {
		r, err := e.Client.API(ctx, method, path, e.adminToken(ctx), doc)
		if out := expectedOutcome(r, err, want); out != "ok" {
			return nil, fmt.Errorf("metadata fixture %s: %s", method, out)
		}
		return r, nil
	}
	resources, err := api("GET", "/resources?limit=200", nil, 200)
	if err != nil {
		return err
	}
	resource := ""
	items, _ := resources.Body["items"].([]any)
	for _, item := range items {
		m := object(item)
		if stringValue(m, "audience") == e.Seed.Audience {
			resource = stringValue(m, "id")
		}
	}
	if resource == "" {
		return errors.New("metadata fixture seeded resource missing")
	}
	for _, profile := range metadataProfiles {
		name := prefix + "-" + profile
		sp, err := api("POST", "/service-principals", map[string]any{"name": name}, 201)
		if err != nil {
			return err
		}
		c, err := api("POST", "/clients", map[string]any{"client_id": name, "name": name, "client_type": "machine", "service_principal_id": sp.Str("id"),
			"token_endpoint_auth_method": "none", "grant_types": []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"}}, 201)
		if err != nil {
			return err
		}
		f := &metadataFixture{profile: profile, client: name, ref: stringValue(object(c.Body["client"]), "id"), subject: "bench:" + profile}
		if f.ref == "" {
			return errors.New("metadata fixture client reference missing")
		}
		s.fixtures = append(s.fixtures, f)
		if _, err := api("PUT", "/clients/"+f.ref+"/resource-grants/"+resource, map[string]any{"allowed_scopes": []string{"bench:read"}, "subject_types": []string{"service_principal"}}, 204); err != nil {
			return err
		}
		keys := s.base + "/jwks/" + profile
		if profile == "private" {
			keys = s.privateBase + "/jwks/private"
		}
		if _, err := api("POST", "/clients/"+f.ref+"/workload-trusts", map[string]any{"name": name, "profile": "generic", "issuer": s.base + "/issuer/" + profile,
			"jwks_uri": keys, "audience": "pa-bench-metadata", "subject": f.subject, "algorithms": []string{"ES256"}, "max_assertion_lifetime_seconds": 1200, "require_jti": false}, 201); err != nil {
			return err
		}
	}
	for _, f := range s.fixtures {
		r, err := s.token(ctx, e, f)
		if out := metadataOutcome(f.profile, r, err); out != metadataLabel(f.profile) {
			return fmt.Errorf("metadata preparation %s: %s", f.profile, out)
		}
		if f.profile == "valid" {
			v, err := e.Client.Do(ctx, Request{Method: "POST", Path: "/realms/" + e.Client.Realm + "/oauth/introspect", Basic: [2]string{e.Seed.ResourceSrv.ClientID, e.Seed.ResourceSrv.Secret}, Form: url.Values{"token": {r.Str("access_token")}}})
			if err != nil || v.Status != 200 || v.Body["active"] != true {
				return errors.New("metadata valid control did not introspect active")
			}
		}
	}
	stats, err := s.snapshot(ctx)
	if err != nil {
		return err
	}
	if err := ValidateMetadataStats(stats); err != nil {
		return err
	}
	s.prepared = true
	return nil
}
func (s *metadataFetch) token(ctx context.Context, e *Env, f *metadataFixture) (*Response, error) {
	f.mu.Lock()
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	if f.assertion == "" || !now.Before(f.expires.Add(-time.Minute)) {
		var doc struct {
			Assertion string `json:"assertion"`
		}
		err := s.call(ctx, s.base+"/issue", map[string]any{"profile": f.profile, "audience": "pa-bench-metadata", "subject": f.subject, "now": now}, &doc)
		if err != nil || doc.Assertion == "" {
			f.mu.Unlock()
			return nil, errors.New("metadata assertion renewal failed")
		}
		f.assertion = doc.Assertion
		f.expires = now.Add(20 * time.Minute)
	}
	assertion := f.assertion
	f.mu.Unlock()
	return e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Form: url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "client_id": {f.client},
		"assertion": {assertion}, "resource": {e.Seed.Audience}, "scope": {"bench:read"}}})
}
func metadataLabel(profile string) string {
	if profile == "valid" {
		return "valid:ok"
	}
	return strings.ReplaceAll(profile, "-", "_") + "_rejected"
}
func metadataOutcome(profile string, r *Response, err error) string {
	if err != nil || r == nil {
		return "transport_error"
	}
	if profile == "valid" {
		expires, _ := r.Body["expires_in"].(float64)
		if r.Status == 200 && r.Str("access_token") != "" && expires > 0 && strings.EqualFold(r.Str("token_type"), "Bearer") && r.Str("refresh_token") == "" && r.Str("id_token") == "" {
			return metadataLabel(profile)
		}
	} else if r.Status == 400 && r.Str("error") == "invalid_grant" && r.Str("access_token") == "" && r.Str("refresh_token") == "" && r.Str("id_token") == "" {
		return metadataLabel(profile)
	}
	return "invariant_unexpected_" + profile + "_response"
}
func (s *metadataFetch) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	f := s.fixtures[(s.next.Add(1)-1)%uint64(len(s.fixtures))]
	r, err := s.token(ctx, e, f)
	return metadataOutcome(f.profile, r, err)
}
func (s *metadataFetch) snapshot(ctx context.Context) (MetadataStats, error) {
	for {
		var stats MetadataStats
		if err := s.call(ctx, s.base+"/stats", nil, &stats); err != nil {
			return stats, err
		}
		if stats.Inflight == 0 {
			return stats, nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return stats, ctx.Err()
		case <-timer.C:
		}
	}
}
func (s *metadataFetch) Observations() map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stats, err := s.snapshot(ctx)
	valid := err == nil && ValidateMetadataStats(stats) == nil
	return map[string]any{"cumulative": stats, "receiver_valid": valid, "profiles": 8, "required_fetch_spacing_ms": 59900, "good_cache_ttl_s": 300, "retry_after_s": 60,
		"fetch_timeout_s": 10, "allowed_destination": "127.0.0.1/32", "denied_live_destination": "::1/128", "scope": "one workload-federation server process; preparation counts included"}
}
func (s *metadataFetch) Close(ctx context.Context, e *Env) error {
	var result error
	if s.prepared {
		stats, err := s.snapshot(ctx)
		result = errors.Join(err, ValidateMetadataStats(stats))
	}
	for _, f := range s.fixtures {
		r, err := e.Client.API(ctx, "POST", "/clients/"+f.ref+"/decommission", e.adminToken(ctx), map[string]any{"reason": "benchmark fixture cleanup"})
		if out := expectedOutcome(r, err, 200); out != "ok" {
			result = errors.Join(result, fmt.Errorf("metadata client cleanup: %s", out))
		}
		f.assertion, f.client, f.ref = "", "", ""
	}
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	s.fixtures = nil
	return result
}
