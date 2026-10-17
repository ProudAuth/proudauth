package notification

import (
	"context"
	"errors"
	"mime"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/testutil"
)

func lowerSMTPBudget(t *testing.T, d time.Duration) {
	t.Helper()
	old := smtpSessionBudget
	smtpSessionBudget = d
	t.Cleanup(func() { smtpSessionBudget = old })
}

// senderFor builds a plain-text sender for addr; viaDial gives it the shape
// of an organization mail server (TEN-022), whose connection comes from Dial
// rather than the built-in dialer.
func senderFor(t *testing.T, addr string, viaDial bool) *SMTPSender {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPSender{Host: host, TLSMode: "none"}
	if s.Port, err = strconv.Atoi(port); err != nil {
		t.Fatal(err)
	}
	if viaDial {
		s.Dial = func(ctx context.Context, h, p string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", net.JoinHostPort(h, p))
		}
	}
	return s
}

func sendAsync(s *SMTPSender, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := s.Send(ctx, Email{From: "id@example.test", To: "bob@example.test", Subject: "x", Text: "y"})
		done <- err
	}()
	return done
}

// TestSMTPSendHasSessionDeadline: a relay that accepts the connection and
// never greets, or greets and then never answers, cannot hold Send past the
// session budget, through the deployment relay and through Dial
// (organization mail servers) alike.
func TestSMTPSendHasSessionDeadline(t *testing.T) {
	lowerSMTPBudget(t, 300*time.Millisecond)
	relays := []struct {
		name  string
		relay func(testing.TB) *testutil.Endpoint
	}{{"silent", testutil.SilentSMTPRelay}, {"stalling", testutil.StallingSMTPRelay}}
	for _, r := range relays {
		for _, viaDial := range []bool{false, true} {
			name := r.name + "/dialer"
			if viaDial {
				name = r.name + "/dial"
			}
			t.Run(name, func(t *testing.T) {
				ep := r.relay(t)
				start := time.Now()
				select {
				case err := <-sendAsync(senderFor(t, ep.Addr, viaDial), context.Background()):
					if err == nil {
						t.Fatal("Send succeeded against a relay that never answers")
					}
					if el := time.Since(start); el > 3*time.Second {
						t.Fatalf("Send took %v with a 300ms budget", el)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("Send still blocked 5s after a 300ms budget")
				}
			})
		}
	}
}

// TestSMTPCheckHasSessionDeadline: the relay check (MSG-012) reports the
// stage a stalling relay hangs at instead of hanging itself.
func TestSMTPCheckHasSessionDeadline(t *testing.T) {
	lowerSMTPBudget(t, 300*time.Millisecond)
	for _, c := range []struct {
		relay func(testing.TB) *testutil.Endpoint
		stage string
	}{{testutil.SilentSMTPRelay, "greeting"}, {testutil.StallingSMTPRelay, "ok"}} {
		ep := c.relay(t)
		s := senderFor(t, ep.Addr, false)
		type result struct {
			stage string
			err   error
		}
		done := make(chan result, 1)
		go func() {
			stage, err := s.Check(context.Background())
			done <- result{stage, err}
		}()
		select {
		case r := <-done:
			// A stalling relay greets, then never answers EHLO, so the
			// failure surfaces at the final QUIT.
			if r.err == nil || r.stage != c.stage {
				t.Fatalf("check: stage %q, error %v; want stage %q with an error", r.stage, r.err, c.stage)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Check still blocked 5s after a 300ms budget")
		}
	}
}

// TestSMTPSendEndsWithContext: cancelling the context (the worker's task
// timeout) closes the connection although the session budget is far away.
func TestSMTPSendEndsWithContext(t *testing.T) {
	for _, viaDial := range []bool{false, true} {
		ep := testutil.StallingSMTPRelay(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := sendAsync(senderFor(t, ep.Addr, viaDial), ctx)
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Send after cancel (dial %v): %v", viaDial, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Send ignored the cancelled context (dial %v)", viaDial)
		}
	}
}

// TestSMTPSendEncodesNonASCII covers the header part of MSG-006
// localization: a Spanish subject and sender name travel as RFC 2047 encoded
// words and the body as quoted-printable, so no raw 8-bit byte reaches the
// relay.
func TestSMTPSendEncodesNonASCII(t *testing.T) {
	port, got := fakeRelay(t)
	s := &SMTPSender{Host: "127.0.0.1", Port: port, TLSMode: "none"}
	subject := "Tu código de verificación"
	if _, err := s.Send(context.Background(), Email{From: "id@example.test", FromName: "Señal Ñandú", To: "bob@example.test",
		Subject: subject, Text: "Tu código es 123456. ¡Gracias!", HTML: "<p>Tu código es 123456.</p>"}); err != nil {
		t.Fatal(err)
	}
	var sess smtpSession
	select {
	case sess = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("relay saw no complete session")
	}
	if !isASCII(sess.data) {
		t.Fatalf("message carries raw 8-bit bytes:\n%s", sess.data)
	}
	headers, body, _ := strings.Cut(sess.data, "\r\n\r\n")
	const wantSubject = "Subject: =?utf-8?q?Tu_c=C3=B3digo_de_verificaci=C3=B3n?="
	if !strings.Contains(headers+"\r\n", wantSubject+"\r\n") {
		t.Fatalf("subject not RFC 2047 encoded, want %q in:\n%s", wantSubject, headers)
	}
	var subj, from string
	for _, line := range strings.Split(headers, "\r\n") {
		if v, ok := strings.CutPrefix(line, "Subject: "); ok {
			subj = v
		}
		if v, ok := strings.CutPrefix(line, "From: "); ok {
			from = v
		}
	}
	dec := new(mime.WordDecoder)
	if d, err := dec.DecodeHeader(subj); err != nil || d != subject {
		t.Fatalf("subject decodes to %q (%v)", d, err)
	}
	if d, err := dec.DecodeHeader(from); err != nil || d != "Señal Ñandú <id@example.test>" {
		t.Fatalf("From decodes to %q (%v), raw %q", d, err, from)
	}
	if !strings.Contains(body, "Content-Transfer-Encoding: quoted-printable") ||
		!strings.Contains(body, "Tu c=C3=B3digo es 123456. =C2=A1Gracias!") || !strings.Contains(body, "<p>Tu c=C3=B3digo es 123456.</p>") {
		t.Fatalf("body parts not quoted-printable:\n%s", body)
	}
}
