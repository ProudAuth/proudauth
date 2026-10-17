package testutil

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func expectTimeout(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("got %v, want a timeout", err)
	}
}

func TestBlackholeTCPAcceptsAndHangs(t *testing.T) {
	e := BlackholeTCP(t)
	c := dial(t, e.Addr)
	if _, err := c.Write([]byte("hello\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	expectTimeout(t, err)
	deadline := time.Now().Add(2 * time.Second)
	for e.Accepted() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.Accepted() != 1 {
		t.Fatalf("accepted %d connections, want 1", e.Accepted())
	}
}

func TestStallingSMTPRelayGreetsThenHangs(t *testing.T) {
	e := StallingSMTPRelay(t)
	c := dial(t, e.Addr)
	r := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "220 ") {
		t.Fatalf("greeting %q, %v", line, err)
	}
	if _, err := c.Write([]byte("EHLO client.invalid\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err = r.ReadString('\n')
	expectTimeout(t, err)
}

func TestSilentSMTPRelayNeverGreets(t *testing.T) {
	e := SilentSMTPRelay(t)
	c := dial(t, e.Addr)
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, err := bufio.NewReader(c).ReadString('\n')
	expectTimeout(t, err)
}

func TestRefusedTCP(t *testing.T) {
	addr := RefusedTCP(t)
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatalf("dial %s succeeded, want refused", addr)
	}
}

func TestSlowHTTP(t *testing.T) {
	slow := SlowHTTP(t, 2*time.Second, http.StatusServiceUnavailable)
	client := &http.Client{Timeout: 100 * time.Millisecond}
	start := time.Now()
	if resp, err := client.Get(slow.URL); err == nil {
		resp.Body.Close()
		t.Fatal("request to the slow server returned before the client timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("the client timeout did not end the request")
	}
	fast := SlowHTTP(t, 10*time.Millisecond, http.StatusServiceUnavailable)
	resp, err := http.Get(fast.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", resp.StatusCode)
	}
}
