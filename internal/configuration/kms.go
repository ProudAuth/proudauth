package configuration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// KMSConfig is the optional external key provider (DEP-016). Root, pepper
// and signing-wrap keys can be stored wrapped (encrypted) by the operator's
// KMS or HSM and referenced as kms:<file of wrapped key>; at startup the
// command receives the wrapped key on standard input and prints the
// unwrapped key on standard output. Any KMS with a command-line client works
// (cloud KMS CLIs, Vault transit, PKCS#11 tools); none is required.
//
// The KMS protects keys at rest and controls who can start the service: the
// unwrapped keys live in process memory while it runs, so they are not
// hardware-protected in use. Signing inside an HSM is not supported.
type KMSConfig struct {
	// Command is the program and its arguments; it is run directly, without
	// a shell. KMS_KEY_REF in its environment names the key file.
	Command []string      `yaml:"command"`
	Timeout time.Duration `yaml:"timeout"`
}

// Enabled reports whether a KMS command is configured.
func (k KMSConfig) Enabled() bool { return len(k.Command) > 0 }

// ConfigureKMS installs the kms: reference scheme for the configured command.
// Without a command, kms: references fail with a configuration error.
func ConfigureKMS(k KMSConfig) {
	if !k.Enabled() {
		RegisterSecretResolver("kms", func(context.Context, string) (string, error) {
			return "", errors.New("kms: reference used but keys.kms.command is not configured")
		})
		return
	}
	timeout := k.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cmdArgs := append([]string{}, k.Command...)
	RegisterSecretResolver("kms", func(ctx context.Context, ref string) (string, error) {
		if ref == "" {
			return "", errors.New("kms: reference must name the wrapped key file")
		}
		wrapped, err := os.ReadFile(ref)
		if err != nil {
			return "", fmt.Errorf("kms: wrapped key: %w", err)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		// The timeout kills the provider process, but a child it started can
		// keep the output pipe open and Wait would block until that child
		// exits. WaitDelay bounds the wait after the kill, so a stuck
		// provider never holds startup (or a resolution) past the timeout.
		cmd.WaitDelay = time.Second
		cmd.Stdin = bytes.NewReader(wrapped)
		// The provider tool gets its own credentials from the environment, but
		// never ProudAuth's settings, which may carry database URLs or other
		// secrets.
		env := []string{"KMS_KEY_REF=" + ref}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "PROUDAUTH_") {
				env = append(env, kv)
			}
		}
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout = &limitedWriter{w: &out, n: 8 << 10}
		cmd.Stderr = io.Discard // provider diagnostics may contain key material
		if err := cmd.Run(); err != nil {
			return "", fmt.Errorf("kms: unwrapping %s failed: %w", ref, err)
		}
		key := strings.TrimSpace(out.String())
		if key == "" {
			return "", fmt.Errorf("kms: unwrapping %s returned nothing", ref)
		}
		return key, nil
	})
}

type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("kms: output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}
