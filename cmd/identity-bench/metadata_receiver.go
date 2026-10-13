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

func metadataReceiver(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("metadata-receiver", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:0", "IPv4 loopback address; also binds the same port on ::1")
	portFile := fs.String("port-file", "", "write bound port")
	caOut := fs.String("ca-out", "", "write ephemeral public CA certificate")
	out := fs.String("out", "", "counts-only JSON snapshot")
	_ = fs.Parse(args)
	if *portFile == "" || *caOut == "" || *out == "" || fs.NArg() != 0 {
		return errors.New("metadata-receiver needs --port-file, --ca-out and --out")
	}
	s, err := bench.NewMetadataReceiver(*addr)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := writePrivateFile(*caOut, s.CAPEM()); err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(s.URL()[len("https://"):])
	if err := writePrivateFile(*portFile, []byte(port+"\n")); err != nil {
		return err
	}
	write := func() error {
		data, err := json.MarshalIndent(s.Snapshot(), "", "  ")
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
	go func() { done <- s.Serve(ctx) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return errors.Join(err, write())
		case <-tick.C:
			if err := write(); err != nil {
				cancel()
				return errors.Join(err, <-done)
			}
		}
	}
}
