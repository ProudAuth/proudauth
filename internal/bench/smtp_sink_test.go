package bench

import (
	"context"
	"encoding/json"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSMTPSinkAcceptsConcurrentSMTPWithoutRetainingContents(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewSMTPSink()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := smtp.SendMail(ln.Addr().String(), nil, "sender@bench.test", []string{"admin@bench.test"}, []byte("Subject: private-subject\r\n\r\nprivate-reset-code\r\n.secret\r\n")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got := s.Snapshot()
	if got.Accepted != 8 || got.Bytes <= 0 || got.Rejected != 0 {
		t.Fatalf("stats %+v", got)
	}
	b, _ := json.Marshal(got)
	for _, secret := range []string{"private-subject", "private-reset-code", "sender@bench.test", "admin@bench.test"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("sink retained %s", secret)
		}
	}
	got.Recipients["mutated-copy"] = 1
	if s.Snapshot().Recipients["mutated-copy"] != 0 {
		t.Fatal("snapshot shares mutable state")
	}
	// Cancellation must also close a stalled SMTP session, rather than
	// waiting for its deadline or leaving a listening socket behind.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	if _, err := c.Read(buf); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := c.Read(buf); err == nil {
		t.Fatal("stalled SMTP session survived cancellation")
	}
}

func TestSMTPSinkRejectsOversizedMailWithoutAcceptance(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewSMTPSink()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, ln) }()
	if err := smtp.SendMail(ln.Addr().String(), nil, "sender@bench.test", []string{"admin@bench.test"}, []byte(strings.Repeat("x", (1<<20)+1))); err == nil {
		t.Error("oversized message accepted")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if s.Snapshot().Accepted != 0 {
		t.Fatal("refused message counted as accepted")
	}
}
