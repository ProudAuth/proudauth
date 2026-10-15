// Command identity-bench seeds a benchmark realm and measures ProudAuth
// through its public APIs (NFR-003..NFR-008). See docs/operations/benchmarks.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/proudauth/proudauth/internal/bench"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "seed":
		err = seed(ctx, os.Args[2:])
	case "run":
		err = run(ctx, os.Args[2:])
	case "smtp-sink":
		err = smtpSink(ctx, os.Args[2:])
	case "metadata-receiver":
		err = metadataReceiver(ctx, os.Args[2:])
	case "replica-proxy":
		err = replicaProxy(ctx, os.Args[2:])
	case "list":
		names := []string{}
		for n := range bench.Scenarios() {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Println(n)
		}
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "identity-bench:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  identity-bench seed --url URL --realm REALM [--users N --orgs N --large N --clients N --depth N --group-members N --seed S] --out seed.json
      (administrator token with an MFA session in PROUDAUTH_BENCH_ADMIN_TOKEN, or an identity-cli credentials
      file in PROUDAUTH_BENCH_ADMIN_CREDENTIALS, refreshed as needed; use a dedicated benchmark realm)
  identity-bench run --url URL --seed-file seed.json --scenario NAME [--concurrency N --duration D --ops N --warmup D --soak D --window D] [--out results.json]
  identity-bench list
  identity-bench smtp-sink --listen 127.0.0.1:0 --port-file PATH --out counts.json
      (loopback-only SMTP acceptance sink; retains counts, never message contents)
  identity-bench metadata-receiver --listen 127.0.0.1:0 --port-file PATH --ca-out PATH --out counts.json
      (disposable HTTPS JWKS source on IPv4/IPv6 loopback; signing/TLS keys stay in memory)
  identity-bench replica-proxy --listen 127.0.0.1:0 --backend http://127.0.0.1:PORT --backend http://127.0.0.1:PORT --port-file PATH --out counts.json
      (per-request round robin on loopback; no cross-backend retries; retains routing counts only)`)
}

func seed(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	base := fs.String("url", "", "public origin of the deployment")
	realm := fs.String("realm", "bench", "benchmark realm")
	spec := bench.SeedSpec{}
	fs.IntVar(&spec.Users, "users", 1000, "users")
	fs.IntVar(&spec.Organizations, "orgs", 50, "small organizations")
	fs.IntVar(&spec.LargeOrgUsers, "large", 0, "members of the one large organization (default users/2)")
	fs.IntVar(&spec.MachineClients, "clients", 10, "machine clients")
	fs.IntVar(&spec.RoleDepth, "depth", 3, "depth of the composed role chain")
	fs.IntVar(&spec.GroupMembers, "group-members", 0, "members of one large group in the large organization")
	fs.Uint64Var(&spec.Seed, "seed", uint64(time.Now().UnixNano()), "seed for names and passwords (default: time-based, so reruns do not collide)")
	out := fs.String("out", "seed.json", "seed file (written with mode 0600: it holds the benchmark clients' secrets)")
	_ = fs.Parse(args)
	if err := checkArgs(fs, *base); err != nil {
		return err
	}
	c := bench.NewClient(*base, *realm, 8)
	admin, err := adminTokens(c)
	if err != nil {
		return err
	}
	if admin == nil {
		return errors.New("PROUDAUTH_BENCH_ADMIN_TOKEN or PROUDAUTH_BENCH_ADMIN_CREDENTIALS is required")
	}
	defer warnUnsaved(admin)
	d, err := bench.Seed(ctx, c, admin, spec, func(s string) { fmt.Fprintln(os.Stderr, "seeding:", s) })
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Fprintf(os.Stderr, "seed %d, prefix %s\n", d.Spec.Seed, d.Prefix)
	return writePrivateFile(*out, append(b, '\n'))
}

// checkArgs rejects a missing or flag-like --url and leftover arguments. With
// an empty value ("--url $BENCH_URL" and BENCH_URL unset) the flag package
// would take the next flag as the URL and silently stop parsing the rest.
func checkArgs(fs *flag.FlagSet, base string) error {
	if base == "" {
		return errors.New("--url is required")
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		return fmt.Errorf("--url %q is not an http(s) origin (is a value missing?)", base)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q (is a flag value missing?)", fs.Arg(0))
	}
	return nil
}

// writePrivateFile writes data to path with mode 0600, also over an existing
// file.
func writePrivateFile(path string, data []byte) error { return bench.WritePrivateFile(path, data) }

// adminTokens returns the administrator token source:
// PROUDAUTH_BENCH_ADMIN_CREDENTIALS (an identity-cli credentials file whose
// access token is refreshed before it expires, for commands that outlast one
// token), else PROUDAUTH_BENCH_ADMIN_TOKEN as it is, else nil.
func adminTokens(c *bench.Client) (bench.TokenSource, error) {
	if path := os.Getenv("PROUDAUTH_BENCH_ADMIN_CREDENTIALS"); path != "" {
		return bench.LoadAdminCredentials(path, c)
	}
	if tok := os.Getenv("PROUDAUTH_BENCH_ADMIN_TOKEN"); tok != "" {
		return bench.StaticToken(tok), nil
	}
	return nil, nil
}

// warnUnsaved reports refreshed credentials that could not be written back.
func warnUnsaved(src bench.TokenSource) {
	if a, ok := src.(*bench.AdminCredentials); ok {
		if err := a.SaveError(); err != nil {
			fmt.Fprintln(os.Stderr, "identity-bench: warning:", err)
		}
	}
}

func run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	base := fs.String("url", "", "public origin of the deployment")
	seedFile := fs.String("seed-file", "seed.json", "seed file from identity-bench seed")
	name := fs.String("scenario", "mixed", "scenario (identity-bench list)")
	opt := bench.Options{}
	fs.IntVar(&opt.Concurrency, "concurrency", 16, "concurrent workers")
	fs.DurationVar(&opt.Duration, "duration", 60*time.Second, "measured duration")
	fs.Int64Var(&opt.Operations, "ops", 0, "stop after this many operations instead")
	fs.DurationVar(&opt.Warmup, "warmup", 5*time.Second, "unmeasured warm-up")
	fs.Uint64Var(&opt.Seed, "seed", 1, "seed for the operation mix")
	soak := fs.Duration("soak", 0, "sustained run of this total length, reported per window (NFR-005)")
	window := fs.Duration("window", time.Minute, "window length for --soak")
	out := fs.String("out", "", "write results JSON here (default stdout)")
	webhookListen := fs.String("webhook-listen", "127.0.0.1:0", "callback listener for webhook workloads (0: free port)")
	webhookURL := fs.String("webhook-url", "", "public callback base when the server is on another host; HTTPS through a caller-managed TLS proxy")
	webhookPrivate := fs.Bool("webhook-private", false, "subscription opts into operator-approved private egress (automatic for default loopback receiver)")
	metadataURL := fs.String("metadata-url", os.Getenv("PROUDAUTH_BENCH_METADATA_URL"), "controlled HTTPS metadata receiver origin")
	metadataCA := fs.String("metadata-ca", os.Getenv("PROUDAUTH_BENCH_METADATA_CA"), "public CA certificate of the controlled receiver")
	_ = fs.Parse(args)
	if err := checkArgs(fs, *base); err != nil {
		return err
	}
	if *soak < 0 || (*soak > 0 && *window <= 0) {
		return errors.New("--soak must be nonnegative and its --window must be positive")
	}
	raw, err := os.ReadFile(*seedFile)
	if err != nil {
		return err
	}
	var d bench.SeedData
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	mk, ok := bench.Scenarios()[*name]
	if !ok {
		return fmt.Errorf("unknown scenario %q", *name)
	}
	c := bench.NewClient(*base, d.Realm, opt.Concurrency)
	admin, err := adminTokens(c)
	if err != nil {
		return err
	}
	defer warnUnsaved(admin)
	env := &bench.Env{Client: c, Admin: admin, Seed: &d, WebhookListen: *webhookListen, WebhookURL: *webhookURL, WebhookPrivate: *webhookPrivate}
	env.MetadataURL, env.MetadataCA = *metadataURL, *metadataCA
	return runScenario(ctx, env, mk(), opt, *soak, *window, *out)
}

// Preserve measured data on interruption or cleanup failure, but return the
// error so a caller cannot publish an incomplete run as a successful soak.
func runScenario(ctx context.Context, env *bench.Env, sc bench.Scenario, opt bench.Options, total, window time.Duration, out string) error {
	var result any
	var runErr error
	if total > 0 {
		windows, err := bench.Soak(ctx, env, sc, opt, total, window, func(r *bench.Result) {
			fmt.Fprintf(os.Stderr, "window: %.0f ops/s p99 %.1f ms outcomes %v\n", r.Throughput, r.LatencyMS.P99, r.Outcomes)
		})
		if err != nil && len(windows) == 0 {
			return err
		}
		runErr = err
		result = map[string]any{"soak": true, "complete": err == nil, "windows": windows}
	} else {
		r, err := bench.Run(ctx, env, sc, opt)
		if r == nil {
			return err
		}
		runErr = err
		fmt.Fprintf(os.Stderr, "%s: %d ops, %.0f ops/s, p50 %.1f ms, p99 %.1f ms, outcomes %v\n", r.Scenario, r.Operations, r.Throughput,
			r.LatencyMS.P50, r.LatencyMS.P99, r.Outcomes)
		result = r
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.Join(runErr, fmt.Errorf("encode benchmark results: %w", err))
	}
	if out == "" {
		_, err = fmt.Fprintln(os.Stdout, string(b))
		return errors.Join(runErr, err)
	}
	return errors.Join(runErr, os.WriteFile(out, append(b, '\n'), 0o644))
}
