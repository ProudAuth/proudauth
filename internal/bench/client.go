package bench

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client calls a deployment's public APIs.
type Client struct {
	BaseURL string
	Realm   string
	HTTP    *http.Client
}

// NewClient returns a client with a connection pool sized for concurrency.
func NewClient(baseURL, realm string, concurrency int) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConns, tr.MaxIdleConnsPerHost = concurrency*2, concurrency*2
	// Header-only offers must wait for refusal for the entire request
	// deadline; the default one-second wait falls back to sending a body.
	tr.ExpectContinueTimeout = 31 * time.Second
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), Realm: realm, HTTP: &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Env is what scenarios use.
type Env struct {
	Client *Client
	// Admin supplies administrator tokens (audit-query, import, mixed):
	// a StaticToken, or AdminCredentials for runs longer than a token's
	// lifetime. Nil sends no token.
	Admin TokenSource
	Seed  *SeedData
	// Concurrency is set by Run before preparation; fixtures can reserve a
	// distinct credential or connector for each load worker (NFR-003).
	Concurrency int
	// WebhookListen/URL configure the load host's callback receiver. Empty
	// values use an OS-allocated loopback port (one-machine profile).
	WebhookListen, WebhookURL string
	WebhookPrivate            bool
	// MetadataURL/CA select the controlled HTTPS source for metadata-fetch.
	MetadataURL, MetadataCA string
	// Now is a test clock; command-line benchmarks use time.Now.
	Now        func() time.Time
	webhookHub *webhookHub

	userOnce sync.Once
	userNext atomic.Uint64
}

// adminToken returns an administrator token, or "" when there is none or it
// cannot be renewed (the request then fails with 401 and shows in the
// outcomes).
func (e *Env) adminToken(ctx context.Context) string {
	if e.Admin == nil {
		return ""
	}
	tok, _ := e.Admin.Token(ctx)
	return tok
}

// Response is a decoded reply.
type Response struct {
	Status int
	Body   map[string]any
	Raw    []byte
	Header http.Header
}

// Outcome classifies a response: "ok" for 2xx/3xx, else "http_<status>".
func (r *Response) Outcome() string {
	if r.Status < 400 {
		return "ok"
	}
	return fmt.Sprintf("http_%d", r.Status)
}

// Str returns a string member.
func (r *Response) Str(k string) string {
	s, _ := r.Body[k].(string)
	return s
}

// Request is one call.
type Request struct {
	Method, Path string
	Token        string
	JSON         any
	Form         url.Values
	Basic        [2]string
	Headers      map[string]string
	Raw          []byte
	// HeaderOnlyBytes offers a body of this length without allowing a
	// single byte to be read by the transport (oversized-input).
	HeaderOnlyBytes int64
}

var errBodyRequested = errors.New("bench: oversized body requested before refusal")

type headerOnlyBody struct{}

func (headerOnlyBody) Read([]byte) (int, error) { return 0, errBodyRequested }

// Do performs a request; transport failures return an error.
func (c *Client) Do(ctx context.Context, rq Request) (*Response, error) {
	var body io.Reader
	ct := ""
	switch {
	case rq.HeaderOnlyBytes > 0:
		body, ct = headerOnlyBody{}, "application/json"
	case rq.Raw != nil:
		body, ct = bytes.NewReader(rq.Raw), "application/json"
	case rq.JSON != nil:
		b, _ := json.Marshal(rq.JSON)
		body, ct = bytes.NewReader(b), "application/json"
	case rq.Form != nil:
		body, ct = strings.NewReader(rq.Form.Encode()), "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, rq.Method, c.BaseURL+rq.Path, body)
	if err != nil {
		return nil, err
	}
	if rq.HeaderOnlyBytes > 0 {
		req.ContentLength = rq.HeaderOnlyBytes
		req.Header.Set("Expect", "100-continue")
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if rq.Token != "" {
		req.Header.Set("Authorization", "Bearer "+rq.Token)
	}
	if rq.Basic[0] != "" {
		req.SetBasicAuth(url.QueryEscape(rq.Basic[0]), url.QueryEscape(rq.Basic[1]))
	}
	for k, v := range rq.Headers {
		req.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	out := &Response{Status: res.StatusCode, Raw: raw, Header: res.Header}
	_ = json.Unmarshal(raw, &out.Body)
	return out, nil
}

// API calls /api/v1/realms/{realm}{path}.
func (c *Client) API(ctx context.Context, method, path, token string, body any) (*Response, error) {
	return c.Do(ctx, Request{Method: method, Path: "/api/v1/realms/" + c.Realm + path, Token: token, JSON: body})
}

// Must fails unless the status is the expected one.
func Must(r *Response, err error, want int, what string) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if r.Status != want {
		return r, fmt.Errorf("%s: status %d: %s", what, r.Status, truncate(string(r.Raw), 300))
	}
	return r, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// PKCE returns a verifier and its S256 challenge.
func PKCE() (string, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

func outcomeOf(r *Response, err error) string {
	if errors.Is(err, errBodyRequested) {
		return "invariant_violation_body_requested"
	}
	if err != nil {
		return "transport_error"
	}
	return r.Outcome()
}
