package contract

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/configuration"
)

// composeVar matches ${NAME}, ${NAME:-default} and ${NAME:?message}.
var composeVar = regexp.MustCompile(`\$\{([A-Z0-9_]+)(?::?([-?])([^}]*))?\}`)

// deployEnvFile reads KEY=VALUE lines, ignoring comments and blank lines.
func deployEnvFile(t *testing.T, rel string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, line := range strings.Split(deployRead(t, rel), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s: malformed line %q", rel, line)
		}
		if _, dup := out[k]; dup {
			t.Fatalf("%s: duplicate variable %s", rel, k)
		}
		out[k] = v
	}
	return out
}

// deployInterpolate resolves Compose variables the way `docker compose`
// does for these files: an empty or unset value takes the default, or is an
// error for a required (?) variable.
func deployInterpolate(s string, env map[string]string) (string, error) {
	var missing error
	out := composeVar.ReplaceAllStringFunc(s, func(m string) string {
		p := composeVar.FindStringSubmatch(m)
		if v := env[p[1]]; v != "" {
			return v
		}
		if p[2] == "?" {
			missing = fmt.Errorf("required variable %s is empty", p[1])
		}
		return p[3]
	})
	return out, missing
}

// TestDeployDevAndProd: deploy/dev and deploy/prod run one image from environment
// variables alone (DEP-002, DEP-006). dev/ brings every local dependency;
// prod/ is the ProudAuth image only, fixed to production, with an empty,
// uncommitted-secret .env. ProudAuth containers run read-only without
// capabilities (DEP-004). Both .env files define the same image variables,
// and each resolves to a configuration the image accepts.
func TestDeployDevAndProd(t *testing.T) {
	loader := deployRead(t, "internal/configuration/config.go")
	for _, profile := range []struct {
		dir, mode string
		services  []string
	}{
		{"dev", "development", []string{"postgres", "mailpit", "migrate", "realm", "server", "worker", "swagger"}},
		{"prod", "production", []string{"migrate", "realm", "server", "worker"}},
	} {
		t.Run(profile.dir, func(t *testing.T) {
			compose := deployDocs(t, "deploy/"+profile.dir+"/docker-compose.yaml")[0]
			services, _ := compose["services"].(map[string]any)
			var names []string
			for name := range services {
				names = append(names, name)
			}
			slices.Sort(names)
			want := slices.Sorted(slices.Values(profile.services))
			if !slices.Equal(names, want) {
				t.Fatalf("services %v, want %v", names, want)
			}
			env := deployEnvFile(t, "deploy/"+profile.dir+"/.env")
			if profile.dir == "prod" {
				// The committed template holds no deployment values; a filled
				// copy must never be committed (DEP-006).
				for _, name := range []string{"PROUDAUTH_PUBLIC_ORIGIN", "PROUDAUTH_DATABASE_URL", "PROUDAUTH_ROOT_KEY",
					"PROUDAUTH_SMTP_HOST", "PROUDAUTH_SMTP_USERNAME", "PROUDAUTH_SMTP_PASSWORD", "PROUDAUTH_EMAIL_FROM"} {
					if v, ok := env[name]; !ok || v != "" {
						t.Errorf("prod/.env must list %s with an empty value", name)
					}
				}
				env["PROUDAUTH_PUBLIC_ORIGIN"] = "https://id.example.test"
				env["PROUDAUTH_DATABASE_URL"] = "postgres://proudauth:example-password@db.example.test:5432/proudauth?sslmode=require"
				env["PROUDAUTH_ROOT_KEY"] = strings.Repeat("ab", 32)
				env["PROUDAUTH_SMTP_HOST"] = "smtp.example.test"
				env["PROUDAUTH_SMTP_PASSWORD"] = "example-smtp-password"
				env["PROUDAUTH_EMAIL_FROM"] = "no-reply@example.test"
			}
			for after, before := range map[string]string{"realm": "migrate", "server": "realm"} {
				if deployDig(services[after], "depends_on", before, "condition") != "service_completed_successfully" {
					t.Errorf("%s must wait for the successful one-shot %s", after, before)
				}
			}
			for _, name := range names {
				svc := services[name]
				img, _ := deployDig(svc, "image").(string)
				ours := strings.HasPrefix(img, "${PROUDAUTH_IMAGE")
				if !ours {
					if profile.dir == "prod" {
						t.Errorf("prod service %s must run the ProudAuth image only, got %q", name, img)
					}
					continue
				}
				if deployDig(svc, "read_only") != true || !slices.Contains(deployStrings(deployDig(svc, "cap_drop")), "ALL") ||
					!slices.Contains(deployStrings(deployDig(svc, "security_opt")), "no-new-privileges:true") {
					t.Errorf("%s must run read-only, without capabilities and without privilege escalation", name)
				}
				if tmpfs := deployStrings(deployDig(svc, "tmpfs")); !slices.Equal(tmpfs, []string{"/tmp:size=64m,mode=1777"}) {
					t.Errorf("%s must use one bounded writable tmpfs mount, got %v", name, tmpfs)
				}
				for _, port := range deployStrings(deployDig(svc, "ports")) {
					if strings.HasSuffix(port, ":9090") && (profile.dir == "prod" || !strings.HasPrefix(port, "127.0.0.1:")) {
						t.Errorf("%s publishes the operator listener as %q; it stays private (loopback in dev, unpublished in prod)", name, port)
					}
				}
				if profile.dir == "prod" && deployDig(svc, "build") != nil {
					t.Errorf("prod service %s must use the published image, not a source build", name)
				}
				if strings.Join(deployStrings(deployDig(svc, "entrypoint")), " ") == "/usr/local/bin/identity-cli realm-create" {
					t.Errorf("%s must use realm-create -if-missing to survive restarts", name)
				}
				vars, _ := deployDig(svc, "environment").(map[string]any)
				if vars["PROUDAUTH_MODE"] != profile.mode {
					t.Errorf("%s must fix PROUDAUTH_MODE to %s, got %v", name, profile.mode, vars["PROUDAUTH_MODE"])
				}
				if profile.dir == "prod" && vars["PROUDAUTH_HOST_POLICY"] != "strict" {
					t.Errorf("%s must enforce the strict Host policy in production", name)
				}
				t.Setenv("PROUDAUTH_CONFIG", "")
				for k, raw := range vars {
					v, err := deployInterpolate(fmt.Sprint(raw), env)
					if err != nil {
						t.Fatalf("%s.%s: %v", name, k, err)
					}
					if strings.HasPrefix(k, "PROUDAUTH_") && !strings.Contains(loader, `"`+k+`"`) {
						t.Errorf("%s sets %s, which the image does not read", name, k)
					}
					t.Setenv(k, v)
				}
				cfg, err := configuration.Load("")
				if err != nil {
					t.Fatal(err)
				}
				if err := cfg.Validate(); err != nil {
					t.Fatalf("%s: the image refuses this configuration: %v", name, err)
				}
			}
		})
	}
	dev, prod := deployEnvFile(t, "deploy/dev/.env"), deployEnvFile(t, "deploy/prod/.env")
	image := func(env map[string]string) []string {
		var keys []string
		for k := range env {
			if strings.HasPrefix(k, "PROUDAUTH_") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		return keys
	}
	reference := deployRead(t, "docs/operations/environment.md")
	for _, env := range []map[string]string{dev, prod} {
		for k := range env {
			if !strings.Contains(reference, "| `"+k+"` |") {
				t.Errorf("docs/operations/environment.md does not document %s", k)
			}
		}
	}
	if !slices.Equal(image(dev), image(prod)) {
		t.Errorf("dev and prod .env must define the same PROUDAUTH_* variables:\n dev  %v\n prod %v", image(dev), image(prod))
	}
}

// TestInstallGuideShowsTheProductionFiles (DEP-002): the install guide, which
// the websites publish as their quickstart, shows deploy/prod's
// docker-compose.yaml and .env byte for byte, so copying them is installing
// exactly the release.
func TestInstallGuideShowsTheProductionFiles(t *testing.T) {
	guide := deployRead(t, "docs/operations/docker-compose.md")
	for lang, rel := range map[string]string{"yaml": "deploy/prod/docker-compose.yaml", "dotenv": "deploy/prod/.env"} {
		if !strings.Contains(guide, "```"+lang+"\n"+deployRead(t, rel)+"```\n") {
			t.Errorf("docs/operations/docker-compose.md must show %s exactly, in a ```%s block", rel, lang)
		}
	}
	for _, command := range []string{"docker compose pull\ndocker compose up -d\n", "identity-cli bootstrap"} {
		if !strings.Contains(guide, command) {
			t.Errorf("the install guide lacks %q", command)
		}
	}
}
