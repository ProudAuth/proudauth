package contract

// DEP-002, DEP-003, DEP-004 and DEP-006: the release installer is deploy/prod,
// source-free and deterministic: docker-compose.yaml and .env with the image
// pinned to the release and no deployment value, even from a filled checkout.

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
)

// releaseBundle packages version from root and returns the archive's files.
func releaseBundle(t *testing.T, root, version string) ([]byte, map[string][]byte, map[string]int64) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is required to package the release installer")
	}
	out := t.TempDir()
	cmd := exec.Command("sh", filepath.Join(root, "scripts/package-deployment.sh"), version)
	cmd.Env = append(os.Environ(), "DEPLOYMENT_OUT="+out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("packaging: %v\n%s", err, output)
	}
	archive, err := os.ReadFile(filepath.Join(out, "proudauth-"+version+"-compose.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	files, modes := map[string][]byte{}, map[string]int64{}
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return archive, files, modes
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		name, ok := strings.CutPrefix(header.Name, "proudauth-"+version+"-compose/")
		if !ok {
			t.Fatalf("archive entry outside its directory: %s", header.Name)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		files[name], modes[name] = body, header.Mode
	}
}

func TestReleaseDeploymentBundleDeterministic(t *testing.T) {
	first, files, modes := releaseBundle(t, repoRoot, "v0.2.0-alpha.2")
	second, _, _ := releaseBundle(t, repoRoot, "v0.2.0-alpha.2")
	if !bytes.Equal(first, second) {
		t.Fatal("same source must produce byte-identical deployment archives")
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	if want := []string{".env", "LICENSE", "NOTICE", "SHA256SUMS", "docker-compose.yaml"}; !slices.Equal(names, want) {
		t.Fatalf("the release installer is deploy/prod plus its license: got %v, want %v", names, want)
	}
	if !bytes.Equal(files["docker-compose.yaml"], []byte(deployRead(t, "deploy/prod/docker-compose.yaml"))) {
		t.Error("the bundled docker-compose.yaml must be deploy/prod's")
	}
	if !bytes.Contains(files[".env"], []byte("\nPROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:0.2.0-alpha.2\n")) {
		t.Error("the bundled .env must pin the image to the packaged version")
	}
	if modes[".env"] != 0o600 {
		t.Errorf(".env receives the operator's secrets and must be packaged 0600, got %04o", modes[".env"])
	}
	for _, line := range strings.Split(string(files["SHA256SUMS"]), "\n") {
		if line != "" && !slices.Contains(names, line[strings.LastIndex(line, " ")+1:]) {
			t.Errorf("SHA256SUMS lists a file the archive lacks: %s", line)
		}
	}
	if _, other, _ := releaseBundle(t, repoRoot, "v1.0.0"); !bytes.Contains(other[".env"], []byte("\nPROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:1.0.0\n")) {
		t.Error("each release pins its own image version")
	}
}

// TestReleaseBundleEmptiesDeploymentValues: packaging from a checkout whose
// deploy/prod/.env was filled in never publishes those values (DEP-006).
func TestReleaseBundleEmptiesDeploymentValues(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"scripts/package-deployment.sh", "deploy/prod/docker-compose.yaml", "LICENSE", "NOTICE"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, rel)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), []byte(deployRead(t, rel)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const private = "private-deployment-value-must-not-be-packaged"
	filled := deployRead(t, "deploy/prod/.env")
	for _, name := range []string{"PROUDAUTH_PUBLIC_ORIGIN", "PROUDAUTH_TRUSTED_PROXIES", "PROUDAUTH_DATABASE_URL", "PROUDAUTH_ROOT_KEY",
		"PROUDAUTH_SMTP_HOST", "PROUDAUTH_SMTP_USERNAME", "PROUDAUTH_SMTP_PASSWORD", "PROUDAUTH_EMAIL_FROM"} {
		if !strings.Contains(filled, "\n"+name+"=\n") {
			t.Fatalf("deploy/prod/.env lacks the empty %s line", name)
		}
		filled = strings.Replace(filled, "\n"+name+"=\n", "\n"+name+"="+private+"\n", 1)
	}
	if err := os.WriteFile(filepath.Join(root, "deploy/prod/.env"), []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}
	_, files, _ := releaseBundle(t, root, "v0.2.0-alpha.2")
	for name, body := range files {
		if bytes.Contains(body, []byte(private)) {
			t.Errorf("a deployment value from the packaging checkout leaked into %s", name)
		}
	}
	if !bytes.Contains(files[".env"], []byte("\nPROUDAUTH_ROOT_KEY=\n")) || !bytes.Contains(files[".env"], []byte("\nPROUDAUTH_SMTP_PORT=587\n")) {
		t.Error("the bundled .env must keep every variable, emptying only deployment values")
	}
}
