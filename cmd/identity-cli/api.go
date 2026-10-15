package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/proudauth/proudauth-sdk-go/admin"
	"github.com/proudauth/proudauth/internal/audit"
)

func auditEvent(typ string) audit.Event {
	return audit.Event{Type: typ, Actor: operatorRef(), Category: "operations"}
}

type credentials struct {
	URL          string    `json:"url"`
	Realm        string    `json:"realm"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	Audience     string    `json:"audience"`
}

func credPath(realm, aud string) string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "proudauth", realm+"-"+aud+".json")
}

func saveCreds(c *credentials) error {
	p := credPath(c.Realm, c.Audience)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(c)
	return writePrivateFile(p, b)
}

// errTokenResponse reports a token-endpoint reply without the members a
// successful response must carry.
var errTokenResponse = errors.New("unexpected token response from the server (missing access_token or expires_in)")

// tokenResponse reads a successful token-endpoint response. An unexpected
// shape is an error, never a panic.
func tokenResponse(m map[string]any) (access, refresh string, ttl time.Duration, err error) {
	access, _ = m["access_token"].(string)
	refresh, _ = m["refresh_token"].(string)
	secs, ok := m["expires_in"].(float64)
	if access == "" || !ok || secs <= 0 || secs > 1<<31 {
		return "", "", 0, errTokenResponse
	}
	return access, refresh, time.Duration(secs) * time.Second, nil
}

func loadCreds(realm, aud string) (*credentials, error) {
	b, err := os.ReadFile(credPath(realm, aud))
	if err != nil {
		return nil, errors.New("not logged in: run identity-cli login")
	}
	var c credentials
	return &c, json.Unmarshal(b, &c)
}

func issuerOf(base, realm string) string { return strings.TrimSuffix(base, "/") + "/realms/" + realm }

func postForm(u string, form url.Values) (map[string]any, int, error) {
	res, err := http.PostForm(u, form)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return m, res.StatusCode, nil
}

func postJSON(u, cont string, body any) (map[string]any, int, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if cont != "" {
		req.Header.Set("X-Transaction-Token", cont)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m, res.StatusCode, nil
}

var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) string {
	fmt.Fprint(os.Stderr, label)
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

func promptSecret(label string) string {
	fmt.Fprint(os.Stderr, label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b)
	}
	return prompt("")
}

func init() {
	register("setup-account", "complete account setup with a one-time setup token", func(args []string) error {
		fs := flag.NewFlagSet("setup-account", flag.ExitOnError)
		base := fs.String("url", os.Getenv("PROUDAUTH_URL"), "public origin")
		realm := fs.String("realm", "main", "realm")
		_ = fs.Parse(args)
		tok := promptSecret("setup token: ")
		pw := promptSecret("new password (15+ characters): ")
		m, st, err := postJSON(*base+"/api/v1/realms/"+*realm+"/account-setup", "", map[string]any{"setup_token": tok, "password": pw})
		if err != nil {
			return err
		}
		if st != 200 {
			return fmt.Errorf("setup failed: %v %v", m["code"], m["detail"])
		}
		fmt.Println("account ready; now run: identity-cli login --url", *base, "--realm", *realm)
		return nil
	})
	register("login", "sign in for administration (interactive headless login with MFA, or --device)", login)
	register("api", "call any realm API path: api METHOD /path [json-body]", func(args []string) error {
		fs := flag.NewFlagSet("api", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		aud := fs.String("audience", "admin", "token audience: admin or account")
		_ = fs.Parse(args)
		rest := fs.Args()
		if len(rest) < 2 {
			return errors.New("usage: identity-cli api [--realm r] METHOD /path [json]")
		}
		c, err := client(*realm, *aud)
		if err != nil {
			return err
		}
		var body any
		if len(rest) > 2 {
			if err := json.Unmarshal([]byte(rest[2]), &body); err != nil {
				return fmt.Errorf("body must be JSON: %w", err)
			}
		}
		// The raw response is printed as returned: an operator calling an
		// endpoint that issues a one-time secret needs to see it once.
		var out json.RawMessage
		opts := []admin.RequestOption{}
		if strings.ToUpper(rest[0]) == "POST" {
			opts = append(opts, admin.WithIdempotencyKey(admin.NewIdempotencyKey()))
		}
		if _, err := c.Do(context.Background(), strings.ToUpper(rest[0]), rest[1], body, &out, opts...); err != nil {
			return err
		}
		var b bytes.Buffer
		if len(out) > 0 && json.Indent(&b, out, "", "  ") == nil {
			fmt.Println(b.String())
		}
		return nil
	})
	register("users", "list users matching a query", func(args []string) error {
		fs := flag.NewFlagSet("users", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		q := fs.String("q", "", "exact email, username, display name or ID")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		return c.Users(context.Background(), *q, func(u admin.User) error {
			fmt.Printf("%s  %-10s  %s\n", u.ID, u.State, u.DisplayName)
			return nil
		})
	})
	register("orgs", "list organizations", func(args []string) error {
		fs := flag.NewFlagSet("orgs", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		return c.Organizations(context.Background(), func(o admin.Organization) error {
			fmt.Printf("%s  %-20s  %-10s %s\n", o.ID, o.Slug, o.State, o.DisplayName)
			return nil
		})
	})
	register("invite", "invite an email address to an organization", func(args []string) error {
		fs := flag.NewFlagSet("invite", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		org := fs.String("org", "", "organization ID")
		email := fs.String("email", "", "invitee email")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		out, err := c.Invite(context.Background(), *org, *email, nil)
		if err != nil {
			return err
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	})
	register("revoke-sessions", "revoke every session and grant of a user", func(args []string) error {
		fs := flag.NewFlagSet("revoke-sessions", flag.ExitOnError)
		realm := fs.String("realm", "main", "realm")
		user := fs.String("user", "", "user ID")
		_ = fs.Parse(args)
		c, err := client(*realm, "admin")
		if err != nil {
			return err
		}
		n, err := c.RevokeSessions(context.Background(), *user)
		if err == nil {
			fmt.Printf("revoked %d sessions\n", n)
		}
		return err
	})
}

func client(realm, aud string) (*admin.Client, error) {
	cr, err := loadCreds(realm, aud)
	if err != nil {
		return nil, err
	}
	return &admin.Client{BaseURL: cr.URL, Realm: realm, UserAgent: "identity-cli", Token: func(ctx context.Context) (string, error) {
		if time.Now().Before(cr.Expiry.Add(-15 * time.Second)) {
			return cr.AccessToken, nil
		}
		m, st, err := postForm(issuerOf(cr.URL, realm)+"/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {cr.RefreshToken}, "client_id": {"proudauth-cli"}})
		if err != nil || st != 200 {
			return "", errors.New("session expired: run identity-cli login again")
		}
		access, refresh, ttl, err := tokenResponse(m)
		if err != nil {
			return "", fmt.Errorf("refreshing the session: %w", err)
		}
		cr.AccessToken = access
		if refresh != "" {
			cr.RefreshToken = refresh
		}
		cr.Expiry = time.Now().Add(ttl)
		if err := saveCreds(cr); err != nil {
			// The refresh succeeded, so this command can go on, but the
			// stored credentials are stale: with refresh-token rotation the
			// next command would present a spent refresh token.
			fmt.Fprintf(warnings, "warning: the refreshed credentials could not be saved to %s (%v); the next command may need identity-cli login\n",
				credPath(realm, aud), err)
		}
		return cr.AccessToken, nil
	}}, nil
}

// warnings receives non-fatal warnings (os.Stderr; tests replace it).
var warnings io.Writer = os.Stderr

func pkce() (string, string) {
	b := make([]byte, 32)
	_, _ = randRead(b)
	v := base64.RawURLEncoding.EncodeToString(b)
	s := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(s[:])
}

func login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	base := fs.String("url", os.Getenv("PROUDAUTH_URL"), "public origin, e.g. https://id.example.com")
	realm := fs.String("realm", "main", "realm")
	aud := fs.String("audience", "admin", "admin or account")
	device := fs.Bool("device", false, "use the device authorization flow")
	_ = fs.Parse(args)
	if *base == "" {
		return errors.New("--url is required")
	}
	iss := issuerOf(*base, *realm)
	resource := iss + "/" + *aud
	scope := "proudauth:" + *aud
	var tokens map[string]any
	if *device {
		m, st, err := postForm(iss+"/oauth/device_authorization", url.Values{"client_id": {"proudauth-cli"}, "scope": {scope}, "resource": {resource}})
		if err != nil {
			return fmt.Errorf("device authorization failed: %w", err)
		}
		if st != 200 {
			return fmt.Errorf("device authorization failed: %v", m["error"])
		}
		deviceCode, _ := m["device_code"].(string)
		if deviceCode == "" {
			return errors.New("device authorization failed: unexpected response from the server (missing device_code)")
		}
		fmt.Fprintf(os.Stderr, "Visit %v and enter code %v\n", m["verification_uri"], m["user_code"])
		interval := 5 * time.Second // RFC 8628 §3.2 default
		if secs, ok := m["interval"].(float64); ok && secs > 0 && secs < 3600 {
			interval = time.Duration(secs) * time.Second
		}
		for {
			time.Sleep(interval)
			t, st, err := postForm(iss+"/oauth/token", url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}, "client_id": {"proudauth-cli"}})
			if err != nil {
				return err
			}
			if st == 200 {
				tokens = t
				break
			}
			switch t["error"] {
			case "authorization_pending":
			case "slow_down":
				interval += 5 * time.Second
			default:
				return fmt.Errorf("device login failed: %v", t["error"])
			}
		}
	} else {
		var err error
		tokens, err = headless(*base, *realm, resource, scope)
		if err != nil {
			return err
		}
	}
	access, refresh, ttl, err := tokenResponse(tokens)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	cr := &credentials{URL: *base, Realm: *realm, Audience: *aud, AccessToken: access, RefreshToken: refresh, Expiry: time.Now().Add(ttl)}
	if err := saveCreds(cr); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "logged in; credentials stored with mode 0600 at", credPath(*realm, *aud))
	return nil
}

// headless drives the interaction API as the CLI's own login surface.
func headless(base, realm, resource, scope string) (map[string]any, error) {
	api := base + "/api/v1/realms/" + realm + "/auth/transactions"
	verifier, challenge := pkce()
	start, st, err := postJSON(api, "", map[string]any{"client_id": "proudauth-cli", "redirect_uri": "http://127.0.0.1/callback", "scope": scope,
		"resource": []string{resource}, "code_challenge": challenge, "code_challenge_method": "S256", "state": "cli"})
	if err != nil {
		return nil, fmt.Errorf("cannot start login: %w", err)
	}
	if st != 201 {
		return nil, fmt.Errorf("cannot start login: %v", start["detail"])
	}
	tx, _ := start["transaction_id"].(string)
	cont, _ := start["continuation_token"].(string)
	state, _ := start["state"].(map[string]any)
	if tx == "" || cont == "" || state == nil {
		return nil, errors.New("cannot start login: unexpected response from the server")
	}
	step := func(name string, body map[string]any) map[string]any {
		m, st, err := postJSON(api+"/"+tx+"/"+name, cont, body)
		if err != nil {
			return map[string]any{"error": err.Error()}
		}
		if st >= 400 {
			fmt.Fprintf(os.Stderr, "  %v: %v\n", m["code"], m["detail"])
			return nil
		}
		return m
	}
	for i := 0; i < 30; i++ {
		if r, _ := state["redirect_to"].(string); r != "" {
			u, _ := url.Parse(r)
			code := u.Query().Get("code")
			m, st, err := postForm(issuerOf(base, realm)+"/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
				"code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {resource}})
			if err != nil || st != 200 {
				return nil, fmt.Errorf("token exchange failed: %v", m["error"])
			}
			return m, nil
		}
		if s, _ := state["status"].(string); s != "pending" {
			return nil, fmt.Errorf("login ended: %v %v", s, state["error"])
		}
		actions, _ := state["next_actions"].([]any)
		if len(actions) == 0 {
			return nil, fmt.Errorf("login blocked: %v", state["error"])
		}
		a, ok := actions[0].(map[string]any)
		if !ok {
			return nil, errors.New("login failed: unexpected response from the server")
		}
		var next map[string]any
		switch a["type"] {
		case "identify":
			next = step("identify", map[string]any{"identifier": prompt("email or username: ")})
		case "password":
			next = step("password", map[string]any{"password": promptSecret("password: ")})
		case "verify_email":
			step("otp/send", map[string]any{"purpose": "verify_email"})
			next = step("otp/verify", map[string]any{"code": prompt("email verification code: ")})
		case "enroll_totp":
			en := step("totp/enroll", nil)
			if en != nil {
				oneTime, _ := en["one_time"].(map[string]any)
				t, ok := oneTime["totp"].(map[string]any)
				if !ok {
					return nil, errors.New("authenticator enrollment failed: unexpected response from the server")
				}
				fmt.Fprintf(os.Stderr, "Add this authenticator (secret %v)\n%v\n", t["secret"], t["otpauth_uri"])
			}
			next = step("totp/activate", map[string]any{"code": prompt("authenticator code: ")})
			if next != nil {
				if ot, ok := next["one_time"].(map[string]any); ok {
					fmt.Fprintln(os.Stderr, "Recovery codes (shown once, store them offline):")
					codes, _ := ot["recovery_codes"].([]any)
					for _, c := range codes {
						fmt.Fprintln(os.Stderr, "  ", c)
					}
				}
			}
		case "totp":
			next = step("totp", map[string]any{"code": prompt("authenticator code: ")})
		case "hotp":
			next = step("hotp", map[string]any{"code": prompt("token code: ")})
		case "recovery_code":
			next = step("recovery-code", map[string]any{"code": prompt("recovery code: ")})
		case "update_password":
			next = step("password/update", map[string]any{"new_password": promptSecret("new password: ")})
		case "accept_terms":
			opts, _ := a["options"].(map[string]any)
			next = step("terms", map[string]any{"version": opts["version"]})
		default:
			return nil, fmt.Errorf("unsupported step %v in CLI login", a["type"])
		}
		if next != nil {
			state = next
		}
	}
	return nil, errors.New("too many steps")
}
