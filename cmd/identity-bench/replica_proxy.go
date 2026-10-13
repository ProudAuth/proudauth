package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"

	"github.com/proudbase/proudauth/internal/bench"
)

type backendFlags []string

func (b *backendFlags) String() string         { return "loopback backend origins" }
func (b *backendFlags) Set(value string) error { *b = append(*b, value); return nil }

func replicaProxy(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("replica-proxy", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:0", "loopback public listener")
	portFile := fs.String("port-file", "", "private file recording the chosen port")
	out := fs.String("out", "", "final counts-only JSON snapshot")
	var backends backendFlags
	fs.Var(&backends, "backend", "plain HTTP loopback origin; repeat once per independent server")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *portFile == "" || *out == "" {
		return errors.New("replica-proxy requires --port-file, --out and no leftover arguments")
	}
	p, err := bench.NewReplicaProxy(backends)
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("replica proxy must listen on a loopback IP")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	host, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("replica proxy must listen on a loopback IP")
	}
	if err := writePrivateFile(*portFile, []byte(port+"\n")); err != nil {
		return err
	}
	runErr := p.Serve(ctx, ln)
	stats := p.Snapshot(runErr == nil)
	data, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return errors.Join(runErr, err)
	}
	return errors.Join(runErr, os.WriteFile(*out, append(data, '\n'), 0o644))
}
