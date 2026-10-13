package bench

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"time"
)

// SMTPSink accepts SMTP on loopback without relaying or retaining message
// contents. It exercises ProudAuth's actual SMTP adapter (NFR-003, NFR-008).
// It deliberately offers neither AUTH nor TLS: the local runner uses it only
// with development mode and an explicitly recorded plain-text loopback path.
type SMTPSink struct {
	mu     sync.Mutex
	stats  SMTPStats
	active map[net.Conn]bool
}

// SMTPStats contains counts only, never addresses, headers or message bodies.
// Recipient SHA-256 counts permit checking the synthetic notification-flood
// address without publishing any message, verification code or reset token.
type SMTPStats struct {
	Accepted   int64            `json:"accepted"`
	Bytes      int64            `json:"message_bytes"`
	Rejected   int64            `json:"rejected_sessions"`
	Recipients map[string]int64 `json:"recipient_sha256"`
}

func NewSMTPSink() *SMTPSink {
	return &SMTPSink{active: map[net.Conn]bool{}, stats: SMTPStats{Recipients: map[string]int64{}}}
}

func (s *SMTPSink) Snapshot() SMTPStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stats
	out.Recipients = map[string]int64{}
	for k, v := range s.stats.Recipients {
		out.Recipients[k] = v
	}
	return out
}

// Serve owns ln and all accepted connections; cancellation closes them and
// waits for handlers, so the runner's trap leaves no listener or goroutine.
func (s *SMTPSink) Serve(ctx context.Context, ln net.Listener) error {
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		ln.Close()
		return fmt.Errorf("benchmark SMTP sink must listen on a loopback IP")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		<-ctx.Done()
		ln.Close()
		s.mu.Lock()
		defer s.mu.Unlock()
		for c := range s.active {
			c.Close()
		}
	}()
	var wg sync.WaitGroup
	defer func() { cancel(); <-closed; wg.Wait() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.mu.Lock()
		s.active[c] = true
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer c.Close()
			defer func() { s.mu.Lock(); delete(s.active, c); s.mu.Unlock() }()
			if ctx.Err() != nil {
				return
			}
			if err := s.session(c); err != nil && ctx.Err() == nil {
				s.mu.Lock()
				s.stats.Rejected++
				s.mu.Unlock()
			}
		}()
	}
}

func (s *SMTPSink) session(c net.Conn) error {
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReaderSize(io.LimitReader(c, 2<<20), 4096)
	w := bufio.NewWriter(c)
	reply := func(code int, message string) error {
		if _, err := fmt.Fprintf(w, "%d %s\r\n", code, message); err != nil {
			return err
		}
		return w.Flush()
	}
	if err := reply(220, "bench.local ESMTP"); err != nil {
		return err
	}
	hello, mail := false, false
	var recipients []string
	for commands := 0; commands < 100; commands++ {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return err
		}
		text := strings.TrimSpace(string(line))
		cmd, arg, _ := strings.Cut(text, " ")
		code, answer := 250, "ok"
		switch strings.ToUpper(cmd) {
		case "EHLO", "HELO":
			hello = arg != ""
			mail = false
			recipients = nil
		case "MAIL":
			mail = hello && strings.HasPrefix(strings.ToUpper(arg), "FROM:<") && strings.HasSuffix(arg, ">")
			recipients = nil
			if !mail {
				code, answer = 503, "MAIL sequence"
			}
		case "RCPT":
			if !mail || !strings.HasPrefix(strings.ToUpper(arg), "TO:<") || !strings.HasSuffix(arg, ">") || len(recipients) >= 20 {
				code, answer = 503, "RCPT sequence"
			} else {
				recipients = append(recipients, strings.ToLower(arg[4:len(arg)-1]))
			}
		case "DATA":
			if !mail || len(recipients) == 0 {
				code, answer = 503, "DATA sequence"
				break
			}
			if err := reply(354, "send data"); err != nil {
				return err
			}
			n, err := io.Copy(io.Discard, io.LimitReader(textproto.NewReader(r).DotReader(), (1<<20)+1))
			if err != nil {
				return err
			}
			if n > 1<<20 {
				_ = reply(552, "message too large")
				return fmt.Errorf("message too large")
			}
			// Count immediately before SMTP acceptance; no message bytes are
			// saved, even in diagnostic output.
			s.mu.Lock()
			s.stats.Accepted++
			s.stats.Bytes += n
			for _, to := range recipients {
				s.stats.Recipients[fmt.Sprintf("%x", sha256.Sum256([]byte(to)))]++
			}
			s.mu.Unlock()
			mail, recipients = false, nil
		case "RSET":
			mail, recipients = false, nil
		case "NOOP":
		case "QUIT":
			return reply(221, "bye")
		default:
			code, answer = 502, "unsupported command"
		}
		if err := reply(code, answer); err != nil {
			return err
		}
	}
	return fmt.Errorf("too many SMTP commands")
}
