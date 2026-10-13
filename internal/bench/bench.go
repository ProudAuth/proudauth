// Package bench is ProudAuth's portable benchmark suite (NFR-003..NFR-008):
// a reproducible data seed, independent and mixed workload scenarios,
// adversarial scenarios that measure budgets under abuse, and concurrency
// stress scenarios that check invariants. It drives a running deployment only
// through its public APIs, so operators can reproduce results on their own
// hardware; results are JSON with latency histograms, errors and the
// environment.
package bench

import (
	"context"
	"errors"
	"math"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Version identifies the result format.
const Version = "1"

// Scenario is one measured workload.
type Scenario interface {
	Name() string
	// Prepare runs once before measuring (tokens, fixtures); not measured.
	Prepare(ctx context.Context, env *Env) error
	// Op performs one operation and returns its outcome: "ok", or an error
	// class such as "http_429" or "invariant_violation".
	Op(ctx context.Context, env *Env, worker int, rnd *rand.Rand) string
}

// Options control a run.
type Options struct {
	Concurrency int
	Duration    time.Duration
	// Operations stops the run after this many operations (0: until Duration).
	Operations int64
	Warmup     time.Duration
	Seed       uint64
	// SkipPrepare reuses state prepared by an earlier run (soak windows).
	SkipPrepare bool
}

// Result is the portable outcome of a run (NFR-008).
type Result struct {
	Tool         string           `json:"tool"`
	Format       string           `json:"format_version"`
	Scenario     string           `json:"scenario"`
	Target       string           `json:"target"`
	StartedAt    time.Time        `json:"started_at"`
	DurationS    float64          `json:"duration_s"`
	Concurrency  int              `json:"concurrency"`
	Seed         uint64           `json:"seed"`
	Operations   int64            `json:"operations"`
	Outcomes     map[string]int64 `json:"outcomes"`
	Throughput   float64          `json:"throughput_per_s"`
	LatencyMS    Percentiles      `json:"latency_ms"`
	Histogram    []Bucket         `json:"histogram"`
	Environment  map[string]any   `json:"environment"`
	Notes        []string         `json:"notes,omitempty"`
	Observations map[string]any   `json:"observations,omitempty"`
	Complete     bool             `json:"complete"`
}

// Percentiles summarize latency in milliseconds.
type Percentiles struct {
	Mean float64 `json:"mean"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P99  float64 `json:"p99"`
	P999 float64 `json:"p999"`
	Max  float64 `json:"max"`
}

// Bucket is one histogram bucket: operations that took at most LeMS.
type Bucket struct {
	LeMS  float64 `json:"le_ms"`
	Count int64   `json:"count"`
}

// Histogram records latencies in log-linear buckets (16 per power of two,
// about 4% resolution) from 1 µs to about 1 hour.
type Histogram struct {
	counts [36 * 16]int64
	n      int64
	sum    float64
	max    float64
}

func bucketOf(us float64) int {
	if us < 1 {
		return 0
	}
	exp := math.Floor(math.Log2(us))
	sub := math.Floor((us/math.Exp2(exp) - 1) * 16)
	i := int(exp)*16 + int(sub)
	return min(max(i, 0), 36*16-1)
}

func upperOf(i int) float64 {
	exp, sub := i/16, i%16
	return math.Exp2(float64(exp)) * (1 + float64(sub+1)/16)
}

// Record adds one latency.
func (h *Histogram) Record(d time.Duration) {
	us := float64(d.Microseconds())
	h.counts[bucketOf(us)]++
	h.n++
	h.sum += us
	if us > h.max {
		h.max = us
	}
}

// Merge adds another histogram.
func (h *Histogram) Merge(o *Histogram) {
	for i, c := range o.counts {
		h.counts[i] += c
	}
	h.n += o.n
	h.sum += o.sum
	h.max = math.Max(h.max, o.max)
}

// Quantile returns the latency at q (0..1) in milliseconds.
func (h *Histogram) Quantile(q float64) float64 {
	if h.n == 0 {
		return 0
	}
	target := int64(math.Ceil(q * float64(h.n)))
	var seen int64
	for i, c := range h.counts {
		seen += c
		if seen >= target {
			return math.Min(upperOf(i), h.max) / 1000
		}
	}
	return h.max / 1000
}

// Summary returns percentiles and non-empty buckets.
func (h *Histogram) Summary() (Percentiles, []Bucket) {
	p := Percentiles{P50: h.Quantile(0.5), P90: h.Quantile(0.9), P99: h.Quantile(0.99), P999: h.Quantile(0.999), Max: h.max / 1000}
	if h.n > 0 {
		p.Mean = h.sum / float64(h.n) / 1000
	}
	var b []Bucket
	for i, c := range h.counts {
		if c > 0 {
			b = append(b, Bucket{LeMS: math.Round(upperOf(i)) / 1000, Count: c})
		}
	}
	return p, b
}

// Run measures a scenario with Concurrency workers.
func Run(ctx context.Context, env *Env, sc Scenario, opt Options) (result *Result, err error) {
	if opt.Concurrency <= 0 {
		opt.Concurrency = 1
	}
	if opt.Duration <= 0 && opt.Operations <= 0 {
		return nil, errors.New("bench: set a duration or an operation count")
	}
	env.Concurrency = opt.Concurrency
	if !opt.SkipPrepare {
		defer func() {
			err = errors.Join(err, closeScenario(sc, env))
			if result != nil && err != nil {
				result.Complete = false
			}
		}()
		if err := sc.Prepare(ctx, env); err != nil {
			return nil, err
		}
	}
	var notes []string
	if opt.Warmup > 0 {
		if warmup(ctx, env, sc, opt) {
			notes = append(notes, "warm-up used benign discovery requests only, so warm-up did not consume the measured attack budgets; scenario notes describe any fixture preparation budget use")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rctx := ctx
	if opt.Duration > 0 {
		var cancel context.CancelFunc
		rctx, cancel = context.WithTimeout(ctx, opt.Duration)
		defer cancel()
	}
	var (
		mu       sync.Mutex
		total    Histogram
		outcomes = map[string]int64{}
		ops      int64
		wg       sync.WaitGroup
	)
	before := scenarioObservations(sc)
	start := time.Now()
	for w := 0; w < opt.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			var h Histogram
			local := map[string]int64{}
			rnd := rand.New(rand.NewPCG(opt.Seed, uint64(worker)))
			for rctx.Err() == nil {
				if opt.Operations > 0 {
					mu.Lock()
					if ops >= opt.Operations {
						mu.Unlock()
						break
					}
					ops++
					mu.Unlock()
				}
				t0 := time.Now()
				out := sc.Op(rctx, env, worker, rnd)
				if rctx.Err() != nil && out != "ok" && !strings.HasSuffix(out, ":ok") {
					break // the run ended mid-operation; not a server outcome
				}
				h.Record(time.Since(t0))
				local[out]++
			}
			mu.Lock()
			total.Merge(&h)
			for k, v := range local {
				outcomes[k] += v
			}
			mu.Unlock()
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	p, b := total.Summary()
	host, _ := os.Hostname()
	res := &Result{Tool: "identity-bench", Format: Version, Scenario: sc.Name(), Target: env.Client.BaseURL, StartedAt: start.UTC(),
		DurationS: elapsed.Seconds(), Concurrency: opt.Concurrency, Seed: opt.Seed, Operations: total.n, Outcomes: outcomes,
		Throughput: float64(total.n) / elapsed.Seconds(), LatencyMS: p, Histogram: b,
		Environment: map[string]any{"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "cpus": runtime.NumCPU(), "host": host}}
	if n, ok := sc.(interface{ Notes() []string }); ok {
		notes = append(notes, n.Notes()...)
	}
	res.Notes = notes
	res.Complete = ctx.Err() == nil
	if after := scenarioObservations(sc); after != nil {
		res.Observations = map[string]any{"before": before, "after": after}
	}
	return res, ctx.Err()
}

// Receivers/subscriptions belong to the scenario lifetime, not to one soak
// window. Cleanup also runs after partially failed preparation (NFR-008).
func closeScenario(sc Scenario, env *Env) error {
	if c, ok := sc.(interface {
		Close(context.Context, *Env) error
	}); ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return c.Close(ctx, env)
	}
	return nil
}
func scenarioObservations(sc Scenario) map[string]any {
	if s, ok := sc.(interface{ Observations() map[string]any }); ok {
		return s.Observations()
	}
	return nil
}

// adversarial is implemented by scenarios whose operations spend server-side
// budgets the scenario measures (account lockout, send budgets, key-refresh
// limits, refresh-family revocation). Warming up with their own operations
// would exhaust those budgets before measuring.
type adversarial interface{ Adversarial() bool }

func isAdversarial(sc Scenario) bool {
	a, ok := sc.(adversarial)
	return ok && a.Adversarial()
}

// warmup runs unmeasured operations with the configured concurrency for
// opt.Warmup, so connection pools and server caches are warm at the measured
// load. Adversarial scenarios warm up with benign requests only; warmup
// reports whether that substitution happened.
func warmup(ctx context.Context, env *Env, sc Scenario, opt Options) bool {
	wctx, cancel := context.WithTimeout(ctx, opt.Warmup)
	defer cancel()
	op, benign := sc.Op, isAdversarial(sc)
	if benign {
		op = benignOp
	}
	var wg sync.WaitGroup
	for w := 0; w < opt.Concurrency; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// A stream separate from the measured workers' streams.
			r := rand.New(rand.NewPCG(opt.Seed, 1<<32|uint64(worker)))
			for wctx.Err() == nil {
				op(wctx, env, worker, r)
			}
		}(w)
	}
	wg.Wait()
	return benign
}

// benignOp fetches the realm's discovery document: it warms connections
// without spending any budget an adversarial scenario measures.
func benignOp(ctx context.Context, e *Env, _ int, _ *rand.Rand) string {
	return outcomeOf(e.Client.Do(ctx, Request{Method: "GET", Path: "/realms/" + e.Client.Realm + "/.well-known/openid-configuration"}))
}

// Soak runs a scenario for total time in consecutive windows and returns one
// result per window (NFR-005), so degradation across token expiry, key
// rotation, session cleanup and database maintenance is visible over time.
func Soak(ctx context.Context, env *Env, sc Scenario, opt Options, total, window time.Duration, each func(*Result)) (results []*Result, err error) {
	if total <= 0 || window <= 0 {
		return nil, errors.New("bench: soak and window durations must be positive")
	}
	if opt.Concurrency < 1 {
		opt.Concurrency = 1
	}
	env.Concurrency = opt.Concurrency
	defer func() { err = errors.Join(err, closeScenario(sc, env)) }()
	if err := sc.Prepare(ctx, env); err != nil {
		return nil, err
	}
	var out []*Result
	opt.SkipPrepare, opt.Operations = true, 0
	// Budget measured windows, excluding preparation and the single warm-up.
	// The final window is shortened when total is not a multiple of window.
	for remaining := total; remaining > 0; remaining -= opt.Duration {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		opt.Duration = min(window, remaining)
		r, err := Run(ctx, env, sc, opt)
		if r != nil {
			out = append(out, r)
			if each != nil {
				each(r)
			}
		}
		if err != nil {
			return out, err
		}
		opt.Warmup = 0
	}
	return out, nil
}
