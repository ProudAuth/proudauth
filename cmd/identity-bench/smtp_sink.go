package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"os"
	"time"

	"github.com/proudbase/proudauth/internal/bench"
)

func smtpSink(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("smtp-sink", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:0", "loopback IP and port (0: choose a free port)")
	portFile := fs.String("port-file", "", "write bound port here")
	out := fs.String("out", "", "write counts only, never message contents")
	_ = fs.Parse(args)
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || !net.ParseIP(host).IsLoopback() || *portFile == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("smtp-sink needs a loopback IP, --port-file and --out, without leftover arguments")
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := os.WriteFile(*portFile, []byte(port+"\n"), 0o600); err != nil {
		return err
	}
	sink := bench.NewSMTPSink()
	write := func() error {
		data, err := json.MarshalIndent(sink.Snapshot(), "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out+".tmp", append(data, '\n'), 0o644); err != nil {
			return err
		}
		return os.Rename(*out+".tmp", *out)
	}
	if err := write(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- sink.Serve(ctx, ln) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return errors.Join(err, write())
		case <-tick.C:
			if err := write(); err != nil {
				cancel()
				<-done
				return err
			}
		}
	}
}
