package main

import (
	"io"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestPasswordCalibrate covers CRED-001's benchmarked parameters: the
// calibration command measures Argon2id on this host and suggests
// parameters that never fall below the production floor (19 MiB, t=2).
func TestPasswordCalibrate(t *testing.T) {
	run := func(args ...string) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout := os.Stdout
		os.Stdout = w
		runErr := passwordCalibrate(args)
		os.Stdout = stdout
		w.Close()
		out, _ := io.ReadAll(r)
		if runErr != nil {
			t.Fatalf("password-calibrate %v: %v", args, runErr)
		}
		return string(out)
	}
	out := run("-target", "30s", "-max-memory-mib", "19", "-threads", "1")
	m := regexp.MustCompile(`argon_memory_kib: (\d+)\n\s+argon_time: (\d+)\n\s+argon_threads: 1`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no suggested configuration:\n%s", out)
	}
	mem, _ := strconv.Atoi(m[1])
	tm, _ := strconv.Atoi(m[2])
	if mem < 19456 || tm < 2 {
		t.Fatalf("suggestion below the production floor: m=%d t=%d", mem, tm)
	}
	if !regexp.MustCompile(`19MiB\s+2\s+\d`).MatchString(out) {
		t.Fatalf("no measurement reported:\n%s", out)
	}
	// An unreachable target suggests nothing and restates the floor.
	if out := run("-target", "1ns", "-max-memory-mib", "19"); !regexp.MustCompile(`no parameter set met the target; the production floor \(19456 KiB, t=2\)`).MatchString(out) {
		t.Fatalf("unreachable target:\n%s", out)
	}
	if err := passwordCalibrate([]string{"-threads", "0"}); err == nil {
		t.Fatal("invalid thread count accepted")
	}
}
