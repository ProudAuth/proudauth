package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/bench"
)

type completionScenario struct {
	calls, closed int
	cancel        context.CancelFunc
	closeErr      error
	wait          bool
	invalidJSON   bool
}

func (*completionScenario) Name() string                              { return "completion-fixture" }
func (*completionScenario) Prepare(context.Context, *bench.Env) error { return nil }
func (s *completionScenario) Close(context.Context, *bench.Env) error { s.closed++; return s.closeErr }
func (s *completionScenario) Op(ctx context.Context, _ *bench.Env, _ int, _ *rand.Rand) string {
	s.calls++
	if s.calls == 2 && s.cancel != nil {
		s.cancel()
	}
	if s.wait {
		<-ctx.Done()
	}
	return "ok"
}
func (s *completionScenario) Observations() map[string]any {
	if s.invalidJSON {
		return map[string]any{"unsupported": func() {}}
	}
	return nil
}

// NFR-005, NFR-008: writing partial evidence must not turn an interrupted or
// uncleaned measurement into exit status zero.
func TestBenchCLIPreservesResultsAndReturnsCompletionErrors(t *testing.T) {
	for _, name := range []string{"interrupted soak", "soak cleanup", "single cleanup", "complete soak", "complete single"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cleanupErr := errors.New("fixture cleanup failed")
			s := &completionScenario{closeErr: cleanupErr, wait: true}
			total, window := 175*time.Millisecond, 100*time.Millisecond
			opt := bench.Options{Concurrency: 1}
			want := cleanupErr
			if name == "complete soak" || name == "complete single" {
				s.closeErr, want = nil, nil
			}
			if name == "interrupted soak" {
				s.closeErr = nil
				s.cancel = cancel
				want = context.Canceled
			}
			if name == "single cleanup" || name == "complete single" {
				total = 0
				opt.Operations = 1
				s.wait = false
			}
			path := filepath.Join(t.TempDir(), "result.json")
			err := runScenario(ctx, &bench.Env{Client: &bench.Client{}}, s, opt, total, window, path)
			if !errors.Is(err, want) || s.closed != 1 {
				t.Fatalf("completion error %v, cleanup %d", err, s.closed)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var data map[string]any
			if err := json.Unmarshal(b, &data); err != nil {
				t.Fatal(err)
			}
			if total > 0 {
				if data["complete"] != (want == nil) || len(data["windows"].([]any)) != 2 {
					t.Fatalf("partial evidence %s", b)
				}
			} else if data["complete"] != (want == nil) || data["operations"] != float64(1) {
				t.Fatalf("partial evidence %s", b)
			}
		})
	}
}

func TestBenchCLIRejectsInvalidSoakBeforeReadingSeed(t *testing.T) {
	for _, flags := range [][]string{{"--soak", "-1s"}, {"--soak", "1s", "--window", "0"}, {"--soak", "1s", "--window", "-1s"}} {
		args := append([]string{"--url", "http://127.0.0.1:1", "--seed-file", filepath.Join(t.TempDir(), "missing.json")}, flags...)
		if err := run(context.Background(), args); err == nil || !strings.Contains(err.Error(), "--soak") {
			t.Fatalf("invalid duration not rejected before setup: %v", err)
		}
	}
}

func TestBenchCLIReportsResultEncodingAndWriteErrors(t *testing.T) {
	sentinel := errors.New("cleanup failure")
	s := &completionScenario{invalidJSON: true, closeErr: sentinel}
	path := filepath.Join(t.TempDir(), "result.json")
	err := runScenario(context.Background(), &bench.Env{Client: &bench.Client{}}, s, bench.Options{Operations: 1}, 0, time.Second, path)
	var unsupported *json.UnsupportedTypeError
	if !errors.Is(err, sentinel) || !errors.As(err, &unsupported) {
		t.Fatalf("lost encoding/run failure: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("malformed result file written")
	}
	s = &completionScenario{closeErr: sentinel}
	err = runScenario(context.Background(), &bench.Env{Client: &bench.Client{}}, s, bench.Options{Operations: 1}, 0, time.Second, filepath.Dir(path))
	var pathErr *os.PathError
	if !errors.Is(err, sentinel) || !errors.As(err, &pathErr) {
		t.Fatalf("lost write/run failure: %v", err)
	}
}
