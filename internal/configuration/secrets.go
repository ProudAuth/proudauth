package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SecretResolver resolves a secret reference of one scheme (DEP-006). The
// argument is the reference without its "scheme:" prefix.
type SecretResolver func(ctx context.Context, ref string) (string, error)

var (
	resolversMu sync.RWMutex
	resolvers   = map[string]SecretResolver{
		"vault": resolveVault,
		"cred":  resolveCredential,
	}
)

// RegisterSecretResolver installs an operator-approved secret-manager adapter
// for a reference scheme (for example "awssm"). Built-in schemes are file:,
// env:, cred: (systemd LoadCredential) and vault: (HashiCorp Vault KV v2).
// Adapters are compiled in deliberately; references never select code paths
// that the operator did not build.
func RegisterSecretResolver(scheme string, fn SecretResolver) {
	resolversMu.Lock()
	defer resolversMu.Unlock()
	resolvers[scheme] = fn
}

func resolverFor(ref string) (SecretResolver, string, bool) {
	scheme, rest, ok := strings.Cut(ref, ":")
	if !ok || scheme == "file" || scheme == "env" {
		return nil, "", false
	}
	resolversMu.RLock()
	defer resolversMu.RUnlock()
	fn, found := resolvers[scheme]
	return fn, rest, found
}

// resolveCredential reads a systemd credential: cred:<name> resolves to
// $CREDENTIALS_DIRECTORY/<name>.
func resolveCredential(_ context.Context, name string) (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", fmt.Errorf("cred:%s: CREDENTIALS_DIRECTORY is not set", name)
	}
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", fmt.Errorf("cred: invalid credential name")
	}
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("cred:%s: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// VaultHTTPClient is used by the vault: resolver; tests may replace it.
var VaultHTTPClient = &http.Client{Timeout: 5 * time.Second}

// resolveVault reads a field from a HashiCorp Vault KV v2 secret:
// vault:<mount>/data/<path>#<field>. VAULT_ADDR and VAULT_TOKEN (or
// VAULT_TOKEN_FILE) come from the process environment, never from the
// configuration file. VAULT_ADDR must be https unless it is a loopback address.
func resolveVault(ctx context.Context, ref string) (string, error) {
	path, field, ok := strings.Cut(ref, "#")
	if !ok || path == "" || field == "" || strings.Contains(path, "..") {
		return "", fmt.Errorf("vault: reference must be <mount>/data/<path>#<field>")
	}
	addr := os.Getenv("VAULT_ADDR")
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("vault: VAULT_ADDR is not set or invalid")
	}
	host := u.Hostname()
	if u.Scheme != "https" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return "", fmt.Errorf("vault: VAULT_ADDR must use https")
	}
	tok := os.Getenv("VAULT_TOKEN")
	if f := os.Getenv("VAULT_TOKEN_FILE"); tok == "" && f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("vault: token file: %w", err)
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return "", fmt.Errorf("vault: VAULT_TOKEN or VAULT_TOKEN_FILE is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(addr, "/")+"/v1/"+strings.TrimLeft(path, "/"), nil)
	if err != nil {
		return "", fmt.Errorf("vault: %w", err)
	}
	req.Header.Set("X-Vault-Token", tok)
	res, err := VaultHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault: request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault: status %d for %s", res.StatusCode, path)
	}
	var body struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("vault: malformed response")
	}
	v, ok := body.Data.Data[field].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("vault: field %s not found in %s", field, path)
	}
	return v, nil
}
