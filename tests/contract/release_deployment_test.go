package contract

// DEP-002, DEP-003, DEP-004, DEP-006 and OPS-013: the release installer is
// source-free, stable on repeated initialization, secret-safe and role-separated.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/configuration"
)

func releaseInstallerCopy(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is required to verify the portable release installer")
	}
	dir := t.TempDir()
	for _, name := range []string{"init.sh", "configure.py", ".env.example", ".env.demo.example"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(deployRead(t, "deploy/release/"+name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func releaseInit(t *testing.T, dir string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(dir, "init.sh")}, args...)...)
	return cmd.CombinedOutput()
}

func releaseEnvReplace(t *testing.T, dir, name, value string) {
	t.Helper()
	path := filepath.Join(dir, ".env")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, name+"=") {
			lines[i] = name + "=" + value
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseComposeIsolation(t *testing.T) {
	compose := deployDocs(t, "deploy/release/docker-compose.yaml")[0]
	services, _ := compose["services"].(map[string]any)
	if deployDig(services["postgres"], "ports") != nil {
		t.Error("release PostgreSQL must have no host port")
	}
	if image, _ := deployDig(services["postgres"], "image").(string); image != "${POSTGRES_IMAGE:-postgres:18.6}" {
		t.Error("release PostgreSQL must default to the measured 18.6 version")
	}
	if !slices.Contains(deployStrings(deployDig(services["postgres"], "volumes")), "pgdata:/var/lib/postgresql") {
		t.Error("release PostgreSQL must use the version-aware PostgreSQL 18 volume root")
	}
	for _, name := range []string{"server", "worker", "migrate"} {
		service := services[name]
		if deployDig(service, "read_only") != true || !slices.Contains(deployStrings(deployDig(service, "cap_drop")), "ALL") {
			t.Errorf("%s must have a read-only filesystem and no capabilities", name)
		}
		if !slices.Contains(deployStrings(deployDig(service, "security_opt")), "no-new-privileges:true") {
			t.Errorf("%s must prohibit gaining privileges", name)
		}
		if tmpfs := deployStrings(deployDig(service, "tmpfs")); !slices.Equal(tmpfs, []string{"/tmp:size=64m,mode=1777"}) {
			t.Errorf("%s must use one correctly quoted bounded writable tmpfs mount", name)
		}
		secrets := deployStrings(deployDig(service, "secrets"))
		if name == "migrate" {
			if !slices.Contains(secrets, "owner_database_url") || slices.Contains(secrets, "database_url") {
				t.Error("migration service must receive only the owner DSN")
			}
		} else if !slices.Contains(secrets, "database_url") || slices.Contains(secrets, "owner_database_url") {
			t.Errorf("%s must receive only the runtime DSN", name)
		}
	}
	if !slices.Contains(deployStrings(deployDig(services["server"], "ports")), "127.0.0.1:${OPERATOR_PORT:-9090}:9090") {
		t.Error("operator port must always bind to loopback")
	}
	if deployDig(services["server"], "depends_on", "migrate", "condition") != "service_completed_successfully" {
		t.Error("server must wait for successful one-shot migration")
	}
}

func TestReleaseInitializerStableSecrets(t *testing.T) {
	dir := releaseInstallerCopy(t)
	if out, err := releaseInit(t, dir, "demo"); err != nil {
		t.Fatalf("demo init: %v\n%s", err, out)
	}
	paths := []string{".env", "config.yaml", "secrets/root_key", "secrets/postgres_password", "secrets/owner_password", "secrets/app_password", "secrets/database_url", "secrets/owner_database_url", "secrets/metrics_token", "secrets/smtp_password"}
	data := make(map[string][]byte)
	infos := make(map[string]os.FileInfo)
	for _, path := range paths {
		var err error
		data[path], err = os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal(err)
		}
		infos[path], _ = os.Stat(filepath.Join(dir, path))
	}
	if infos[".env"].Mode().Perm() != 0o600 {
		t.Error(".env must have mode 0600")
	}
	info, _ := os.Stat(filepath.Join(dir, "secrets"))
	if info.Mode().Perm() != 0o700 {
		t.Error("secret directory must have mode 0700")
	}
	if out, err := releaseInit(t, dir, "demo"); err != nil {
		t.Fatalf("repeated init: %v\n%s", err, out)
	}
	for _, path := range paths {
		after, _ := os.ReadFile(filepath.Join(dir, path))
		info, _ := os.Stat(filepath.Join(dir, path))
		if !bytes.Equal(data[path], after) || !os.SameFile(infos[path], info) {
			t.Errorf("%s must preserve credentials and mounted inode", path)
		}
		if strings.HasPrefix(path, "secrets/") && info.Mode().Perm() != 0o444 {
			t.Errorf("%s must be readable by the non-root container mount", path)
		}
	}
	cfg, err := configuration.Load(filepath.Join(dir, "config.yaml"))
	if err != nil || cfg.Validate() != nil {
		t.Fatalf("generated demo config must validate: %v", err)
	}
	if cfg.Mode != configuration.ModeDevelopment || cfg.Storage.RuntimeRole != "proudauth_app" || cfg.Storage.MigrateOnStart {
		t.Error("demo config must still separate database roles and use explicit migrations")
	}
	for _, name := range []string{"root_key", "postgres_password", "owner_password", "app_password", "metrics_token"} {
		if bytes.Contains(data[".env"], data["secrets/"+name]) || bytes.Contains(data["config.yaml"], data["secrets/"+name]) {
			t.Errorf("%s leaked into ordinary config", name)
		}
	}
}

func TestReleaseInitializerProductionSafety(t *testing.T) {
	dir := releaseInstallerCopy(t)
	if _, err := releaseInit(t, dir, "production"); err == nil {
		t.Fatal("production example placeholders must be refused")
	}
	releaseEnvReplace(t, dir, "PROUDAUTH_PUBLIC_ORIGIN", "https://identity.operator.test")
	releaseEnvReplace(t, dir, "SMTP_HOST", "smtp.operator.test")
	releaseEnvReplace(t, dir, "EMAIL_FROM", "no-reply@operator.test")
	if _, err := releaseInit(t, dir, "production"); err == nil {
		t.Fatal("authenticated SMTP must require an operator-supplied password file")
	}
	passwordPath := filepath.Join(dir, "secrets/smtp_password")
	if err := os.Chmod(passwordPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordPath, []byte("fixture-SMTP-secret-never-published"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := releaseInit(t, dir, "production"); err != nil {
		t.Fatalf("production init: %v\n%s", err, out)
	}
	cfg, err := configuration.Load(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != configuration.ModeProduction || cfg.Sessions.CookieInsecureDev || cfg.Delivery.Email.Adapter != "smtp" || cfg.Server.HostPolicy != "strict" {
		t.Error("production config must retain HTTPS, secure cookies, SMTP and strict host checks")
	}
	if cfg.Delivery.Email.SMTPPassword != "file:/run/secrets/smtp_password" || cfg.Storage.MigrationDatabaseURL != "" {
		t.Error("runtime config must have file SMTP reference and no owner credential")
	}
	config, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if bytes.Contains(config, []byte("fixture-SMTP-secret-never-published")) {
		t.Error("SMTP password leaked into config")
	}
	if _, err := releaseInit(t, dir, "demo"); err == nil {
		t.Error("initializer must refuse silently changing an existing installation's profile")
	}
}

func TestReleaseInitializerRefusesUnsafeInputs(t *testing.T) {
	for _, tc := range []struct{ name, key, value string }{
		{"shell", "SMTP_USERNAME", "$(touch sentinel)"},
		{"unknown", "UNRECOGNIZED_OPTION", "1"},
		{"public-demo", "PUBLIC_BIND", "0.0.0.0"},
		{"trust-every-proxy", "PROUDAUTH_TRUSTED_PROXIES", "0.0.0.0/0"},
		{"connection-capacity", "POOL_MAX_CONNECTIONS", "100"},
		{"pool-below-minimum", "POOL_MAX_CONNECTIONS", "1"},
		{"demo-origin-port", "PUBLIC_PORT", "8082"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := releaseInstallerCopy(t)
			if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(deployRead(t, "deploy/release/.env.demo.example")), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "unknown" {
				file, _ := os.OpenFile(filepath.Join(dir, ".env"), os.O_APPEND|os.O_WRONLY, 0o600)
				_, _ = file.WriteString(tc.key + "=" + tc.value + "\n")
				_ = file.Close()
			} else {
				releaseEnvReplace(t, dir, tc.key, tc.value)
			}
			if _, err := releaseInit(t, dir, "demo"); err == nil {
				t.Fatal("unsafe or misspelled configuration was accepted")
			}
			if _, err := os.Stat(filepath.Join(dir, "sentinel")); err == nil {
				t.Fatal(".env content was executed")
			}
		})
	}
}

func TestReleaseDeploymentBundleDeterministic(t *testing.T) {
	dir := t.TempDir()
	run := func() []byte {
		t.Helper()
		cmd := exec.Command("sh", filepath.Join(repoRoot, "scripts/package-deployment.sh"), "v0.2.0-alpha.1")
		cmd.Env = append(os.Environ(), "DEPLOYMENT_OUT="+dir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("packaging: %v\n%s", err, out)
		}
		data, err := os.ReadFile(filepath.Join(dir, "proudauth-v0.2.0-alpha.1-compose.tar.gz"))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first, second := run(), run()
	if !bytes.Equal(first, second) {
		t.Fatal("same source must produce byte-identical deployment archives")
	}
	gz, err := gzip.NewReader(bytes.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tarReader := tar.NewReader(gz)
	var names []string
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(header.Name, "proudauth-v0.2.0-alpha.1-compose/")
		if header.Typeflag == tar.TypeDir {
			continue
		}
		names = append(names, name)
		if name == ".env" || name == "config.yaml" || strings.Contains(name, "secrets/") || strings.Contains(name, ".state/") {
			t.Errorf("private state was packaged: %s", name)
		}
	}
	for _, name := range []string{"docker-compose.yaml", ".env.example", ".env.demo.example", "init.sh", "configure.py", "init-database.sh", "README.md", "ENVIRONMENT.md", "LICENSE", "NOTICE", "SHA256SUMS"} {
		if !slices.Contains(names, name) {
			t.Errorf("source-free bundle missing %s", name)
		}
	}
}
