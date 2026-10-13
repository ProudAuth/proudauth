package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/bench"
)

// NFR-005, NFR-008: verify main's real signal/exit path, rather than only a
// returned Go error. The controlled HTTP fixture measures no ProudAuth capacity.
func TestBenchCLIRejectsInterruptedSoakProcess(t *testing.T) {
	if os.Getenv("PA_BENCH_PROCESS_HELPER") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				os.Exit(0)
			}
		}
		os.Exit(2)
	}
	if runtime.GOOS == "windows" {
		t.Skip("requires POSIX SIGTERM")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/bench/oauth/token" || r.Method != "POST" {
			w.WriteHeader(404)
			return
		}
		time.Sleep(2 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"synthetic-fixture-token","token_type":"Bearer","expires_in":300}`)
	}))
	defer srv.Close()
	dir := t.TempDir()
	seedPath, outPath := filepath.Join(dir, "seed.json"), filepath.Join(dir, "partial.json")
	d := bench.SeedData{Realm: "bench", Audience: "https://fixture.test/api", Machine: []bench.SeedClient{{ClientID: "fixture", Secret: "synthetic-never-valid"}}}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBenchCLIRejectsInterruptedSoakProcess$", "--", "run", "--url", srv.URL, "--seed-file", seedPath, "--scenario", "client-credentials", "--concurrency", "1", "--warmup", "0", "--soak", "20s", "--window", "200ms", "--out", outPath)
	cmd.Env = append(os.Environ(), "PA_BENCH_PROCESS_HELPER=1", "PROUDAUTH_BENCH_ADMIN_TOKEN=", "PROUDAUTH_BENCH_ADMIN_CREDENTIALS=")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = cmd.Wait()
		}
	}()
	firstWindow, scanned := make(chan struct{}), make(chan struct{})
	var once sync.Once
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), "window:") {
				once.Do(func() { close(firstWindow) })
			}
		}
	}()
	select {
	case <-firstWindow:
	case <-ctx.Done():
		t.Fatal("CLI did not finish a window before interruption")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	waited = true
	<-scanned
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("interrupted CLI exit: %v", err)
	}
	b, err = os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Complete bool           `json:"complete"`
		Windows  []bench.Result `json:"windows"`
	}
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	if result.Complete || len(result.Windows) == 0 || !result.Windows[0].Complete || result.Windows[0].Operations == 0 {
		t.Fatalf("partial evidence lost: %s", b)
	}
}
