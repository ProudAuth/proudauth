package bench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenSource supplies an access token for each request that needs one.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken is a token used as it is: a command using it must finish within
// the token's lifetime (300 s for administrator tokens).
type StaticToken string

// Token returns the token.
func (t StaticToken) Token(context.Context) (string, error) {
	if t == "" {
		return "", errors.New("no administrator token")
	}
	return string(t), nil
}

// renewable is a token a scenario holds across operations (NFR-005). Once
// less than a fifth of its lifetime (at most 60 s) is left it is renewed in
// the background while the current token is still used, so a run longer than
// the token lifetime (a soak run) crosses token expiry the way a
// well-behaved client does instead of presenting expired tokens, and the
// renewal's latency is not counted in the operation that noticed it. At most
// one renewal runs at a time: a refresh token must never be presented twice
// (reuse detection would revoke the family). An expired or missing token is
// renewed while the caller waits.
type renewable struct {
	fetch func(context.Context) (string, time.Duration, error)
	now   func() time.Time

	mu       sync.Mutex
	tok      string
	exp      time.Time
	renewAt  time.Time
	inflight chan struct{} // closed when the running renewal has finished
	err      error         // of the last renewal
}

func (r *renewable) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// set stores a token valid for ttl from now; the caller holds r.mu.
func (r *renewable) set(tok string, ttl time.Duration) {
	now := r.clock()
	r.tok, r.exp = tok, now.Add(ttl)
	r.renewAt = r.exp.Add(-min(ttl/5, time.Minute))
	r.err = nil
}

func (r *renewable) get(ctx context.Context) (string, error) {
	r.mu.Lock()
	now := r.clock()
	valid := r.tok != "" && now.Before(r.exp)
	if valid && now.Before(r.renewAt) {
		tok := r.tok
		r.mu.Unlock()
		return tok, nil
	}
	done := r.inflight
	if done == nil {
		done = make(chan struct{})
		r.inflight = done
		go r.renew(context.WithoutCancel(ctx), done)
	}
	if valid {
		tok := r.tok
		r.mu.Unlock()
		return tok, nil
	}
	r.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tok != "" && r.clock().Before(r.exp) {
		return r.tok, nil
	}
	if r.err != nil {
		return "", r.err
	}
	return "", errors.New("bench: token renewal failed")
}

func (r *renewable) renew(ctx context.Context, done chan struct{}) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tok, ttl, err := r.fetch(ctx)
	r.mu.Lock()
	if err == nil && tok != "" && ttl > 0 {
		r.set(tok, ttl)
	} else {
		if err == nil {
			err = errors.New("bench: token response without a token or lifetime")
		}
		// A still valid token stays in use; the next renewal is tried a
		// second later.
		r.err, r.renewAt = err, r.clock().Add(time.Second)
	}
	r.inflight = nil
	r.mu.Unlock()
	close(done)
}

// lifetime returns a token response's expires_in.
func lifetime(r *Response) time.Duration {
	secs, _ := r.Body["expires_in"].(float64)
	return time.Duration(secs) * time.Second
}

// tokenFetch adapts a token-endpoint call to a renewable's fetch.
func tokenFetch(what string, call func(context.Context) (*Response, error)) func(context.Context) (string, time.Duration, error) {
	return func(ctx context.Context) (string, time.Duration, error) {
		r, err := call(ctx)
		if r, err = Must(r, err, 200, what); err != nil {
			return "", 0, err
		}
		return r.Str("access_token"), lifetime(r), nil
	}
}

// credentialsFile is identity-cli's stored login (identity-cli login writes
// one per realm and audience under the user configuration directory).
type credentialsFile struct {
	URL          string    `json:"url"`
	Realm        string    `json:"realm"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Audience     string    `json:"audience"`
}

// AdminCredentials is an administrator token source backed by an identity-cli
// credentials file (PROUDAUTH_BENCH_ADMIN_CREDENTIALS). Administrator access
// tokens live 300 s and the built-in administration resource cannot be given
// a longer lifetime, so seeding a large dataset, and soak runs of the
// scenarios that use the administration API (audit-query, import, mixed),
// outlive a static token. The access token is refreshed with the refresh
// token (client proudauth-cli, as identity-cli does) before it expires; each
// refresh rotates the refresh token, so the file is rewritten (mode 0600)
// after every refresh and later commands, identity-cli's included, go on with
// the current one. Never run two commands on one file at the same time: both
// would present the same refresh token, and reuse detection revokes the
// session.
type AdminCredentials struct {
	path     string
	client   *Client
	clientID string
	r        renewable

	mu      sync.Mutex
	cred    credentialsFile
	saveErr error
}

// LoadAdminCredentials reads an identity-cli credentials file for the realm
// of c.
func LoadAdminCredentials(path string, c *Client) (*AdminCredentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cred credentialsFile
	if err := json.Unmarshal(raw, &cred); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if cred.AccessToken == "" || cred.RefreshToken == "" {
		return nil, fmt.Errorf("%s: no access_token or refresh_token (run identity-cli login)", path)
	}
	if cred.Realm != "" && cred.Realm != c.Realm {
		return nil, fmt.Errorf("%s holds credentials for realm %q, not %q", path, cred.Realm, c.Realm)
	}
	a := &AdminCredentials{path: path, client: c, clientID: "proudauth-cli", cred: cred}
	a.r.fetch = a.refresh
	if ttl := time.Until(cred.Expiry); ttl > 0 {
		a.r.mu.Lock()
		a.r.set(cred.AccessToken, ttl)
		a.r.mu.Unlock()
	}
	return a, nil
}

// Token returns a current administrator access token.
func (a *AdminCredentials) Token(ctx context.Context) (string, error) { return a.r.get(ctx) }

// SaveError reports a refresh whose rotated tokens could not be written back
// to the file: the file then holds a spent refresh token.
func (a *AdminCredentials) SaveError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.saveErr
}

func (a *AdminCredentials) refresh(ctx context.Context) (string, time.Duration, error) {
	a.mu.Lock()
	rt := a.cred.RefreshToken
	a.mu.Unlock()
	r, err := a.client.Do(ctx, Request{Method: "POST", Path: "/realms/" + a.client.Realm + "/oauth/token",
		Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {a.clientID}}})
	if r, err = Must(r, err, 200, "refreshing the administrator token"); err != nil {
		return "", 0, err
	}
	access, ttl := r.Str("access_token"), lifetime(r)
	if access == "" || ttl <= 0 {
		return "", 0, errors.New("refreshing the administrator token: response without access_token or expires_in")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cred.AccessToken, a.cred.Expiry = access, time.Now().UTC().Add(ttl)
	if next := r.Str("refresh_token"); next != "" {
		a.cred.RefreshToken = next
	}
	b, _ := json.Marshal(a.cred)
	if err := WritePrivateFile(a.path, b); err != nil {
		a.saveErr = fmt.Errorf("the refreshed administrator credentials could not be saved to %s (%w); run identity-cli login again", a.path, err)
	}
	return access, ttl, nil
}

// WritePrivateFile writes data to path with mode 0600 even when path already
// exists (os.WriteFile keeps an existing file's mode): it writes a new 0600
// file in the same directory and renames it over path.
func WritePrivateFile(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
