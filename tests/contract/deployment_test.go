package contract

// Static checks of the published deployment artifacts (DEP-002, DEP-003,
// DEP-004, DEP-007, DEP-009, DEP-013, DEP-015, DEP-017): the Compose stack,
// the container image, the release pipeline, the Kubernetes manifests and
// the air-gap bundle are read from the repository and checked for the
// properties the requirements promise. Running them (compose smoke test,
// image build, release) is CI's job; these checks keep the files honest.

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/proudbase/proudauth/internal/configuration"
)

func deployRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// deployDocs parses every YAML document of a file.
func deployDocs(t *testing.T, rel string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(deployRead(t, rel)))
	var out []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}
		if doc != nil {
			out = append(out, doc)
		}
	}
}

// deployDig follows map keys; it returns nil when a key is missing.
func deployDig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func deployList(v any) []any {
	l, _ := v.([]any)
	return l
}

func deployStrings(v any) []string {
	var out []string
	for _, x := range deployList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// deployLeaves lists the dotted paths of a YAML mapping's scalar and list
// values.
func deployLeaves(prefix string, v any, out *[]string) {
	m, ok := v.(map[string]any)
	if !ok {
		*out = append(*out, prefix)
		return
	}
	for k, x := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		deployLeaves(p, x, out)
	}
}

// TestDeployComposeStack covers DEP-002 (and DEP-004 for the Compose stack):
// the development stack is a working Compose file whose secrets come from
// generated, git-ignored files; its configuration and the production
// template hold secret references only, load and validate, and every key
// they use is in the configuration reference; a smoke-test command checks
// the running stack, and CI runs it. The application containers run with a
// read-only root filesystem, no capabilities and an explicit /tmp.
func TestDeployComposeStack(t *testing.T) {
	compose := deployDocs(t, "deploy/compose/compose.yaml")[0]
	services, _ := compose["services"].(map[string]any)
	for _, s := range []string{"postgres", "migrate", "server", "worker"} {
		if services[s] == nil {
			t.Fatalf("compose.yaml lacks the %s service", s)
		}
	}
	// PostgreSQL 18 stores PGDATA below a major-version directory. Mounting
	// the former /data path makes the official image refuse even a fresh DB.
	if !slices.Contains(deployStrings(deployDig(services["postgres"], "volumes")), "pgdata:/var/lib/postgresql") {
		t.Error("PostgreSQL 18 must persist its versioned data under /var/lib/postgresql")
	}
	t.Run("secret files work for the container UID and survive reinitialization", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "init-secrets.sh")
		if err := os.WriteFile(script, []byte(deployRead(t, "deploy/compose/init-secrets.sh")), 0o600); err != nil {
			t.Fatal(err)
		}
		previous := make(map[string][]byte)
		for pass := range 2 {
			if out, err := exec.Command("sh", script).CombinedOutput(); err != nil {
				t.Fatalf("initialization %d failed: %v\n%s", pass, err, out)
			}
			secretDir := filepath.Join(dir, "secrets")
			info, err := os.Stat(secretDir)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatal("the host secret directory must be accessible only by its owner")
			}
			for _, name := range []string{"root_key", "db_password", "database_url"} {
				path := filepath.Join(secretDir, name)
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				// Native Linux Compose binds the host file; its UID is not the
				// image's UID 65532. A readable, non-writable mount is needed.
				if mode := info.Mode().Perm(); mode&0o444 != 0o444 || mode&0o333 != 0 {
					t.Errorf("%s must be readable by the container UID without write/execute permission, got %04o", name, mode)
				}
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if pass > 0 && !bytes.Equal(previous[name], body) {
					t.Errorf("reinitialization changed %s", name)
				}
				previous[name] = body
			}
		}
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).Match(previous["root_key"]) ||
			!regexp.MustCompile(`^[0-9a-f]{36}$`).Match(previous["db_password"]) {
			t.Error("initialization must generate full-length random hex keys and passwords")
		}
		wantURL := "postgres://proudauth:" + string(previous["db_password"]) + "@postgres:5432/proudauth?sslmode=disable"
		if string(previous["database_url"]) != wantURL {
			t.Error("database URL must use the generated password")
		}
	})
	for name, svc := range services {
		for k, v := range func() map[string]any { m, _ := deployDig(svc, "environment").(map[string]any); return m }() {
			if u := strings.ToUpper(k); (strings.Contains(u, "PASSWORD") || strings.Contains(u, "SECRET") || strings.Contains(u, "KEY")) && !strings.HasSuffix(u, "_FILE") {
				t.Errorf("service %s sets %s=%v in the Compose file; use a secret file", name, k, v)
			}
		}
	}
	for name, sec := range compose["secrets"].(map[string]any) {
		if f, _ := deployDig(sec, "file").(string); !strings.HasPrefix(f, "./secrets/") {
			t.Errorf("Compose secret %s must come from a generated file under ./secrets/, got %v", name, sec)
		}
	}
	for _, name := range []string{"migrate", "server", "worker"} {
		svc := services[name]
		if deployDig(svc, "read_only") != true || !slices.Contains(deployStrings(deployDig(svc, "cap_drop")), "ALL") ||
			!slices.Contains(deployStrings(deployDig(svc, "security_opt")), "no-new-privileges:true") {
			t.Errorf("Compose service %s must run read-only, without capabilities and without privilege escalation", name)
		}
	}
	for _, name := range []string{"server", "worker"} {
		if !slices.Contains(deployStrings(deployDig(services[name], "tmpfs")), "/tmp") {
			t.Errorf("Compose service %s must declare its writable temporary location (tmpfs /tmp)", name)
		}
	}
	if !strings.Contains(deployRead(t, "deploy/compose/.gitignore"), "secrets/") || !strings.Contains(deployRead(t, ".gitignore"), "deploy/compose/secrets/") {
		t.Error("generated Compose secrets must be git-ignored")
	}
	if init := deployRead(t, "deploy/compose/init-secrets.sh"); !strings.Contains(init, "/dev/urandom") || !strings.Contains(init, "umask 077") {
		t.Error("init-secrets.sh must generate random secrets with private file modes")
	}

	// Configuration templates: secret references only, valid, documented.
	reference := deployRead(t, "docs/operations/configuration.md")
	for _, rel := range []string{"deploy/compose/config.dev.yaml", "deploy/config/production.example.yaml", "deploy/kubernetes/overlays/example/config.yaml"} {
		cfg, err := configuration.Load(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s does not validate: %v", rel, err)
		}
		secrets := map[string]string{"storage.database_url": cfg.Storage.DatabaseURL, "storage.migration_database_url": cfg.Storage.MigrationDatabaseURL,
			"delivery.email.smtp_password": cfg.Delivery.Email.SMTPPassword, "delivery.email.events_secret": cfg.Delivery.Email.EventsSecret,
			"delivery.sms.webhook_secret": cfg.Delivery.SMS.WebhookSecret, "server.metrics_token": cfg.Server.MetricsToken}
		for _, k := range slices.Concat(cfg.Keys.RootKeys, cfg.Keys.PepperKeys, cfg.Keys.SigningWrapKeys) {
			secrets["keys ref "+k.Ref] = k.Ref
		}
		for name, v := range secrets {
			if v != "" && !configuration.IsSecretRef(v) {
				t.Errorf("%s holds a literal %s; templates carry secret references only", rel, name)
			}
		}
		var leaves []string
		deployLeaves("", deployDocs(t, rel)[0], &leaves)
		for _, leaf := range leaves {
			section, key, nested := strings.Cut(leaf, ".")
			if !nested {
				section, key = "Top level", leaf
			}
			start := strings.Index(reference, "## `"+section+"`")
			if section == "Top level" {
				start = strings.Index(reference, "## Top level")
			}
			if start < 0 {
				t.Errorf("configuration reference has no section for %s (%s)", leaf, rel)
				continue
			}
			body := reference[start+3:]
			if end := strings.Index(body, "\n## "); end >= 0 {
				body = body[:end]
			}
			if !strings.Contains(body, "| `"+key+"`") {
				t.Errorf("configuration reference does not document %s (used in %s)", leaf, rel)
			}
		}
	}

	smoke := deployRead(t, "scripts/smoke-test.sh")
	for _, want := range []string{"set -eu", "/health/live", "/health/ready", "/.well-known/openid-configuration", "/jwks", "grant_type=password"} {
		if !strings.Contains(smoke, want) {
			t.Errorf("smoke-test.sh does not check %q", want)
		}
	}
	if st, err := os.Stat(filepath.Join(repoRoot, "scripts/smoke-test.sh")); err != nil || st.Mode()&0o111 == 0 {
		t.Error("smoke-test.sh must be executable")
	}
	makefile := deployRead(t, "Makefile")
	if !regexp.MustCompile(`(?m)^smoke:\s*\n\t\./scripts/smoke-test\.sh`).MatchString(makefile) ||
		!regexp.MustCompile(`(?m)^dev:\s*\n\t\./deploy/compose/init-secrets\.sh && docker compose -f deploy/compose/compose\.yaml up`).MatchString(makefile) {
		t.Error("Makefile must offer `make dev` (init secrets, compose up) and `make smoke`")
	}
	ci := deployRead(t, ".github/workflows/ci.yml")
	if !strings.Contains(ci, "deploy/compose/init-secrets.sh") || !strings.Contains(ci, "docker compose -f deploy/compose/compose.yaml up") || !strings.Contains(ci, "make smoke") {
		t.Error("CI must start the Compose stack and run the smoke test")
	}
}

// DEP-002, DEP-004: the standalone image deployment initializes private,
// stable credentials and never downloads images during startup.
func TestDeployImageLocalStack(t *testing.T) {
	compose := deployDocs(t, "docker-deploy/docker-compose.yaml")[0]
	services, _ := compose["services"].(map[string]any)
	for _, name := range []string{"postgres", "migrate", "server", "worker", "swagger"} {
		if deployDig(services[name], "pull_policy") != "never" {
			t.Errorf("%s must use an already loaded image", name)
		}
	}
	if !slices.Contains(deployStrings(deployDig(services["postgres"], "volumes")), "pgdata:/var/lib/postgresql") {
		t.Error("the standalone stack must use the PostgreSQL 18 volume root")
	}
	cfg, err := configuration.Load(filepath.Join(repoRoot, "docker-deploy/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	tunnel, err := configuration.Load(filepath.Join(repoRoot, "docker-deploy/config.tunnel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Validate(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tunnel.Server.PublicOrigin, "https://") || tunnel.Sessions.CookieInsecureDev || tunnel.Server.HostPolicy != "strict" {
		t.Error("the tunnel profile must require its public HTTPS host and secure cookies")
	}
	if deployRead(t, "docker-deploy/openapi/proudauth.yaml") != deployRead(t, "api/openapi/proudauth.yaml") {
		t.Error("the Swagger specification must match the source API contract")
	}
	dir := t.TempDir()
	for _, name := range []string{"init-env.sh", "prepare-secrets.sh", ".env.example"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(deployRead(t, "docker-deploy/"+name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(script string) {
		t.Helper()
		if out, err := exec.Command("sh", filepath.Join(dir, script)).CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", script, err, out)
		}
	}
	run("init-env.sh")
	envPath := filepath.Join(dir, ".env")
	envBefore, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{`(?m)^ROOT_KEY_VALUE=[0-9a-f]{64}$`, `(?m)^POSTGRES_PASSWORD=[0-9a-f]{48}$`} {
		if !regexp.MustCompile(pattern).Match(envBefore) {
			t.Error("initializer must create full-length random hexadecimal credentials")
		}
	}
	run("init-env.sh")
	envAfter, _ := os.ReadFile(envPath)
	info, err := os.Stat(envPath)
	if err != nil || info.Mode().Perm() != 0o600 || !bytes.Equal(envBefore, envAfter) {
		t.Fatal(".env must remain private and unchanged on reinitialization")
	}
	run("prepare-secrets.sh")
	secretDir := filepath.Join(dir, "secrets")
	info, err = os.Stat(secretDir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("secret directory must remain private")
	}
	for _, name := range []string{"root_key", "db_password", "database_url"} {
		path := filepath.Join(secretDir, name)
		before, _ := os.ReadFile(path)
		inode, _ := os.Stat(path)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		run("prepare-secrets.sh")
		after, _ := os.ReadFile(path)
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o444 || !bytes.Equal(before, after) || !os.SameFile(inode, info) {
			t.Errorf("%s must repair readability without changing credentials or the mounted inode", name)
		}
	}
}

// TestDeployImageHardening covers DEP-003 and DEP-004 for the container
// image: every base image names an explicit tag or digest (never latest),
// modules are verified against go.sum and kept current through reviewed
// Dependabot updates, the build is reproducible (trimpath, no cgo, no build
// ID), and the runtime stage is a shell-less distroless image that runs as a
// numeric non-root user and needs no writable root filesystem.
func TestDeployImageHardening(t *testing.T) {
	df := deployRead(t, "Dockerfile")
	froms := regexp.MustCompile(`(?m)^FROM\s+(?:--platform=\S+\s+)?(\S+)`).FindAllStringSubmatch(df, -1)
	if len(froms) < 2 {
		t.Fatalf("Dockerfile must be a multi-stage build, found %d stages", len(froms))
	}
	for _, f := range froms {
		img := f[1]
		if !strings.Contains(img, "@sha256:") && (!strings.Contains(img, ":") || strings.HasSuffix(img, ":latest")) {
			t.Errorf("base image %s names no explicit tag or digest", img)
		}
	}
	final := froms[len(froms)-1][1]
	if !strings.HasPrefix(final, "gcr.io/distroless/static") {
		t.Errorf("runtime stage %s must be distroless static (no shell, no package manager)", final)
	}
	runtimeStage := df[strings.LastIndex(df, "\nFROM "):]
	for _, want := range []string{"go mod verify", "CGO_ENABLED=0", "-trimpath", "-buildid="} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile build lacks %q", want)
		}
	}
	user := regexp.MustCompile(`(?m)^USER\s+(\d+)(?::(\d+))?\s*$`).FindStringSubmatch(runtimeStage)
	if user == nil || user[1] == "0" || user[2] == "0" {
		t.Errorf("runtime stage must run as a numeric non-root USER, got %v", user)
	}
	for _, forbidden := range []string{"\nVOLUME", "\nRUN "} {
		if strings.Contains(runtimeStage, forbidden) {
			t.Errorf("runtime stage must not use %s (no writable or mutable runtime image)", strings.TrimSpace(forbidden))
		}
	}
	if !strings.Contains(runtimeStage, "LICENSE NOTICE") {
		t.Error("the image must carry the LICENSE and NOTICE files")
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "go.sum")); err != nil {
		t.Error("go.sum must pin module checksums")
	}
	var ecosystems []string
	for _, u := range deployList(deployDocs(t, ".github/dependabot.yml")[0]["updates"]) {
		if e, _ := deployDig(u, "package-ecosystem").(string); e != "" {
			ecosystems = append(ecosystems, e)
		}
	}
	for _, e := range []string{"gomod", "docker", "github-actions"} {
		if !slices.Contains(ecosystems, e) {
			t.Errorf("dependency pins for %s are not kept current by Dependabot", e)
		}
	}
}

// TestDeployReleaseArtifacts covers DEP-003 and DEP-017 for the release
// pipeline: releases are built from a version tag after the full CI suite,
// the image is identified by its digest, SBOMs and build provenance are
// produced and attested for the image and every release file, the offline
// bundle (with the published image) is built, and SHA256SUMS covers every
// asset before the file provenance is attested and the release published.
func TestDeployReleaseArtifacts(t *testing.T) {
	rel := deployDocs(t, ".github/workflows/release.yml")[0]
	// yaml.v3 decodes the key "on" as a string.
	if tags := deployStrings(deployDig(rel, "on", "push", "tags")); !slices.Contains(tags, "v*") {
		t.Errorf("releases must be built from version tags, got %v", tags)
	}
	job := deployDig(rel, "jobs", "release")
	if needs := deployStrings(deployDig(job, "needs")); !slices.Contains(needs, "ci") {
		t.Error("the release job must wait for the full CI workflow")
	}
	if uses, _ := deployDig(rel, "jobs", "ci", "uses").(string); uses != "./.github/workflows/ci.yml" {
		t.Errorf("the release must run ci.yml first, got %q", uses)
	}
	steps := deployList(deployDig(job, "steps"))
	index := func(match func(step map[string]any) bool) int {
		for i, s := range steps {
			if m, ok := s.(map[string]any); ok && match(m) {
				return i
			}
		}
		return -1
	}
	runs := func(sub string) func(map[string]any) bool {
		return func(s map[string]any) bool { r, _ := s["run"].(string); return strings.Contains(r, sub) }
	}
	uses := func(action, withKey string) func(map[string]any) bool {
		return func(s map[string]any) bool {
			u, _ := s["uses"].(string)
			return strings.HasPrefix(u, action+"@") && deployDig(s, "with", withKey) != nil
		}
	}
	image := index(func(s map[string]any) bool {
		r, _ := s["run"].(string)
		return strings.Contains(r, "docker push") ||
			regexp.MustCompile(`(?m)^\s*docker buildx build(?:[^\n]*\\\n)*[^\n]*\s--push\b`).MatchString(r)
	})
	digest := index(runs("dist/IMAGE_DIGEST"))
	sourceSBOM := index(runs("syft@"))
	imageSBOM := index(func(s map[string]any) bool {
		r, _ := s["run"].(string)
		return strings.Contains(r, "syft@") && strings.Contains(r, "@${DIGEST}")
	})
	bundle := index(runs("make bundle"))
	imageProvenance := index(uses("actions/attest-build-provenance", "subject-digest"))
	sbomAttestation := index(uses("actions/attest-sbom", "sbom-path"))
	checksums := index(runs("SHA256SUMS"))
	fileProvenance := index(uses("actions/attest-build-provenance", "subject-path"))
	publish := index(runs("gh release create"))
	for name, i := range map[string]int{"image push": image, "image digest record": digest, "source SBOM": sourceSBOM, "image SBOM": imageSBOM,
		"offline bundle": bundle, "image provenance": imageProvenance, "image SBOM attestation": sbomAttestation, "checksums": checksums,
		"release file provenance": fileProvenance, "publish": publish} {
		if i < 0 {
			t.Errorf("release.yml has no %s step", name)
		}
	}
	if t.Failed() {
		return
	}
	if r, _ := deployDig(steps[bundle], "run").(string); !strings.Contains(r, "IMAGE=") || bundle < image {
		t.Error("the offline bundle must be built after the image and include it (IMAGE=...)")
	}
	if !(checksums > bundle && checksums > digest && checksums > imageSBOM && fileProvenance > checksums && publish > fileProvenance) {
		t.Error("SHA256SUMS must be written after every release file exists, then attested, then published")
	}
	if p, _ := deployDig(steps[fileProvenance], "with", "subject-path").(string); p != "dist/*" {
		t.Errorf("file provenance must cover every release file, got %q", p)
	}
}

// TestDeployKubernetesManifests covers DEP-013 (and DEP-004, DEP-009 and
// DEP-015 for Kubernetes): maintained Kustomize manifests whose pods run as
// non-root with read-only root filesystems, no capabilities, no service
// account token and size-limited explicit writable volumes; resource
// requests and limits; secrets referenced from a Secret, never embedded;
// separate liveness and readiness probes; disruption budgets; a migration
// Job with rollout guidance; and background work in its own Deployment so it
// cannot starve interactive sign-in.
func TestDeployKubernetesManifests(t *testing.T) {
	base := "deploy/kubernetes/base"
	kust := deployDocs(t, base+"/kustomization.yaml")[0]
	listed := deployStrings(kust["resources"])
	entries, err := os.ReadDir(filepath.Join(repoRoot, base))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".yaml") && n != "kustomization.yaml" && !slices.Contains(listed, n) {
			t.Errorf("%s/%s is not listed in kustomization.yaml", base, n)
		}
	}
	workloads := map[string]map[string]any{} // component -> workload
	var pdbs []map[string]any
	for _, f := range listed {
		for _, doc := range deployDocs(t, base+"/"+f) {
			kind, _ := doc["kind"].(string)
			name, _ := deployDig(doc, "metadata", "name").(string)
			switch kind {
			case "Secret":
				t.Errorf("%s: secrets must be created out of band, not shipped (%s)", f, name)
			case "PodDisruptionBudget":
				pdbs = append(pdbs, doc)
			case "Deployment", "Job":
				comp, _ := deployDig(doc, "spec", "template", "metadata", "labels", "app.kubernetes.io/component").(string)
				workloads[comp] = doc
				checkPod(t, kind+" "+name, deployDig(doc, "spec", "template", "spec"))
			}
		}
	}
	for _, c := range []string{"server", "worker", "migrate"} {
		if workloads[c] == nil {
			t.Fatalf("no %s workload in the Kubernetes base", c)
		}
	}
	if k, _ := workloads["migrate"]["kind"].(string); k != "Job" {
		t.Error("migrations must run as a separate Job")
	}

	server := deployList(deployDig(workloads["server"], "spec", "template", "spec", "containers"))[0]
	live, _ := deployDig(server, "livenessProbe", "httpGet", "path").(string)
	ready, _ := deployDig(server, "readinessProbe", "httpGet", "path").(string)
	if live != "/health/live" || ready != "/health/ready" || deployDig(server, "startupProbe") == nil {
		t.Errorf("server probes: liveness %q, readiness %q, startup %v; want separate /health/live and /health/ready and a startup probe", live, ready, deployDig(server, "startupProbe") != nil)
	}
	if mu := deployDig(workloads["server"], "spec", "strategy", "rollingUpdate", "maxUnavailable"); mu != 0 {
		t.Errorf("server rollouts must keep every ready pod (maxUnavailable 0), got %v", mu)
	}
	worker := deployList(deployDig(workloads["worker"], "spec", "template", "spec", "containers"))[0]
	if cmd := strings.Join(deployStrings(deployDig(worker, "command")), " "); !strings.Contains(cmd, "identity-worker") {
		t.Errorf("the worker Deployment must run identity-worker, got %q", cmd)
	}
	if args := strings.Join(deployStrings(deployDig(server, "command")), " "); strings.Contains(args, "identity-worker") {
		t.Error("background work must not run in the server pods")
	}
	for _, c := range []string{"server", "worker"} {
		covered := false
		for _, p := range pdbs {
			if deployDig(p, "spec", "selector", "matchLabels", "app.kubernetes.io/component") == c && deployDig(p, "spec", "minAvailable") != nil {
				covered = true
			}
		}
		if !covered {
			t.Errorf("no PodDisruptionBudget for the %s pods", c)
		}
	}
	readme := deployRead(t, "deploy/kubernetes/README.md")
	for _, want := range []string{"Kubernetes is\noptional", "## Rollout procedure", "migration Job", "proudauth-secrets"} {
		if !strings.Contains(readme, want) {
			t.Errorf("deploy/kubernetes/README.md lacks %q", want)
		}
	}
	overlay := deployRead(t, "deploy/kubernetes/overlays/example/kustomization.yaml")
	if !strings.Contains(overlay, "../../base") || !strings.Contains(overlay, "digest") {
		t.Error("the example overlay must build on the base and tell operators to pin the image digest")
	}
}

// checkPod asserts the secure defaults of one pod template.
func checkPod(t *testing.T, what string, pod any) {
	t.Helper()
	if deployDig(pod, "securityContext", "runAsNonRoot") != true || deployDig(pod, "securityContext", "runAsUser") == 0 ||
		deployDig(pod, "securityContext", "seccompProfile", "type") != "RuntimeDefault" {
		t.Errorf("%s: pod must run as non-root with the RuntimeDefault seccomp profile", what)
	}
	if deployDig(pod, "automountServiceAccountToken") == true {
		t.Errorf("%s: no service-account token is needed", what)
	}
	volumes := map[string]any{}
	for _, v := range deployList(deployDig(pod, "volumes")) {
		name, _ := deployDig(v, "name").(string)
		volumes[name] = v
		if deployDig(v, "secret") != nil && deployDig(v, "secret", "secretName") == nil {
			t.Errorf("%s: secret volume %s must reference a Secret", what, name)
		}
	}
	for _, c := range deployList(deployDig(pod, "containers")) {
		cname, _ := deployDig(c, "name").(string)
		sc := deployDig(c, "securityContext")
		if deployDig(sc, "readOnlyRootFilesystem") != true || deployDig(sc, "allowPrivilegeEscalation") != false ||
			!slices.Contains(deployStrings(deployDig(sc, "capabilities", "drop")), "ALL") {
			t.Errorf("%s/%s: container must have a read-only root filesystem, no privilege escalation and no capabilities", what, cname)
		}
		if deployDig(c, "resources", "requests", "cpu") == nil || deployDig(c, "resources", "requests", "memory") == nil ||
			deployDig(c, "resources", "limits", "memory") == nil {
			t.Errorf("%s/%s: container must declare CPU and memory requests and a memory limit", what, cname)
		}
		for _, e := range deployList(deployDig(c, "env")) {
			n, _ := deployDig(e, "name").(string)
			if u := strings.ToUpper(n); (strings.Contains(u, "PASSWORD") || strings.Contains(u, "SECRET") || strings.Contains(u, "TOKEN") || strings.Contains(u, "KEY")) &&
				deployDig(e, "valueFrom", "secretKeyRef") == nil {
				t.Errorf("%s/%s: %s must come from a secretKeyRef", what, cname, n)
			}
		}
		for _, m := range deployList(deployDig(c, "volumeMounts")) {
			if deployDig(m, "readOnly") == true {
				continue
			}
			name, _ := deployDig(m, "name").(string)
			if deployDig(volumes[name], "emptyDir", "sizeLimit") == nil {
				t.Errorf("%s/%s: writable mount %s must be an explicit, size-limited emptyDir", what, cname, name)
			}
		}
	}
}

// TestDeployOfflineBundle covers DEP-017: the air-gap bundle carries static
// binaries for both Linux architectures, the container image when one is
// named, migrations, deployment manifests, API contracts, operations
// documentation (installation and upgrades), license and notice files, the
// module list and toolchain, SHA-256 checksums and verification
// instructions, never local development secrets; the archive gets its own
// checksum and the release workflow publishes it.
func TestDeployOfflineBundle(t *testing.T) {
	script := deployRead(t, "scripts/offline-bundle.sh")
	for _, want := range []string{
		"for arch in amd64 arm64", "identity-server identity-worker identity-cli", "GOOS=linux", "CGO_ENABLED=0",
		"cp -R migrations deploy api", "operations", "LICENSE NOTICE", "modules.txt", "toolchain.txt",
		`docker save -o "$STAGE/image.tar" -- "$IMAGE"`, "SHA256SUMS", "VERIFY.md", "sha256sum -c SHA256SUMS", `rm -rf "$OUT/deploy/compose/secrets"`,
		".tar.gz.sha256",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("offline-bundle.sh lacks %q", want)
		}
	}
	for _, doc := range []string{"docs/operations/installation.md", "docs/operations/upgrades.md", "docs/operations/offline-install.md"} {
		if _, err := os.Stat(filepath.Join(repoRoot, doc)); err != nil {
			t.Errorf("%s must exist for offline installation and upgrades", doc)
		}
	}
	if off := deployRead(t, "docs/operations/offline-install.md"); !strings.Contains(off, "make bundle") || !strings.Contains(off, "SHA256SUMS") {
		t.Error("offline-install.md must describe building and verifying the bundle")
	}
	if !regexp.MustCompile(`(?m)^bundle:\s*\n\t.*\./scripts/offline-bundle\.sh \$\(VERSION\)`).MatchString(deployRead(t, "Makefile")) {
		t.Error("Makefile must offer `make bundle`")
	}
	if !strings.Contains(deployRead(t, ".github/workflows/release.yml"), "make bundle") {
		t.Error("the release workflow must build the offline bundle")
	}
}

// TestDeployNoBootstrapRoute covers DEP-007 statically: no HTTP route
// creates or bootstraps an administrator (the only setup route redeems an
// operator-issued one-time token), and the bootstrap operation is reachable
// only from the local operator CLI.
func TestDeployNoBootstrapRoute(t *testing.T) {
	for r := range registeredRoutes(t) {
		p := strings.ToLower(r.Path)
		if strings.Contains(p, "bootstrap") || strings.Contains(p, "setup") && !strings.HasSuffix(p, "/account-setup") {
			t.Errorf("route %s looks like a setup endpoint", r)
		}
	}
	var callers []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "node_modules" || n == "tests" || n == "sdk" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(".BootstrapAdmin(")) {
			rel, _ := filepath.Rel(repoRoot, path)
			callers = append(callers, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(callers, []string{"cmd/identity-cli/operator.go"}) {
		t.Errorf("BootstrapAdmin must be called only by the operator CLI, called from %v", callers)
	}
}
