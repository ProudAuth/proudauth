package notification

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
)

// The SMTP adapter is one implementation of the pluggable transport.
var _ EmailSender = (*SMTPSender)(nil)

type smtpSession struct {
	auth, from, to, data string
}

// fakeRelay accepts one SMTP session on a loopback port and reports what it
// received: greeting, EHLO with AUTH PLAIN, MAIL, RCPT, DATA and QUIT.
func fakeRelay(t *testing.T) (int, <-chan smtpSession) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan smtpSession, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		reply := func(lines ...string) {
			for _, l := range lines {
				_, _ = conn.Write([]byte(l + "\r\n"))
			}
		}
		var s smtpSession
		reply("220 relay.test ESMTP")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			upper := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(upper, "EHLO "):
				reply("250-relay.test", "250 AUTH PLAIN")
			case strings.HasPrefix(upper, "AUTH PLAIN "):
				s.auth = line[len("AUTH PLAIN "):]
				reply("235 2.7.0 accepted")
			case strings.HasPrefix(upper, "MAIL FROM:"):
				s.from = line[len("MAIL FROM:"):]
				reply("250 OK")
			case strings.HasPrefix(upper, "RCPT TO:"):
				s.to = line[len("RCPT TO:"):]
				reply("250 OK")
			case upper == "DATA":
				reply("354 end with <CRLF>.<CRLF>")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				s.data = b.String()
				reply("250 OK queued")
			case upper == "QUIT":
				reply("221 bye")
				got <- s
				return
			default:
				reply("502 unrecognized")
			}
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

// TestSMTPSenderSpeaksStandardSMTP covers MSG-001: the bundled adapter
// delivers through any standard SMTP relay (AUTH PLAIN with a password
// resolved from a secret reference, MAIL, RCPT, DATA), with no hosted vendor
// involved, and header values cannot inject extra headers.
func TestSMTPSenderSpeaksStandardSMTP(t *testing.T) {
	port, got := fakeRelay(t)
	var resolved string
	s := &SMTPSender{Host: "127.0.0.1", Port: port, Username: "mailer", PasswordRef: "env:RELAY_PASSWORD", TLSMode: "none",
		Resolve: func(ref string) (string, error) { resolved = ref; return "relay-secret", nil }}
	id, err := s.Send(context.Background(), Email{From: "id@example.test", FromName: "Main\r\nBcc: thief@example.test",
		ReplyTo: "help@example.test\r\nX-Injected: 1", To: "bob@example.test", Subject: "Your code\r\nBcc: thief@example.test",
		Text: "Your code is 123456.", HTML: "<p>Your code is 123456.</p>"})
	if err != nil {
		t.Fatalf("send through a standard relay: %v", err)
	}
	var sess smtpSession
	select {
	case sess = <-got:
	case <-time.After(10 * time.Second):
		t.Fatal("relay saw no complete session")
	}
	if resolved != "env:RELAY_PASSWORD" {
		t.Fatalf("password not resolved from its secret reference: %q", resolved)
	}
	if auth, _ := base64.StdEncoding.DecodeString(sess.auth); string(auth) != "\x00mailer\x00relay-secret" {
		t.Fatalf("AUTH PLAIN credentials: %q", auth)
	}
	if sess.from != "<id@example.test>" || sess.to != "<bob@example.test>" {
		t.Fatalf("envelope: from %q to %q", sess.from, sess.to)
	}
	headers, body, _ := strings.Cut(sess.data, "\r\n\r\n")
	for _, want := range []string{"\r\nTo: bob@example.test\r\n", "\r\nMessage-ID: " + id + "\r\n", "\r\nSubject: Your codeBcc: thief@example.test\r\n",
		"Content-Type: multipart/alternative"} {
		if !strings.Contains("\r\n"+headers+"\r\n", want) {
			t.Fatalf("header %q missing from:\n%s", want, headers)
		}
	}
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(line, "Bcc:") || strings.HasPrefix(line, "X-Injected:") {
			t.Fatalf("header injected through a value: %q", line)
		}
	}
	if !strings.Contains(body, "Your code is 123456.") || !strings.Contains(body, "<p>Your code is 123456.</p>") {
		t.Fatalf("text and HTML parts missing:\n%s", body)
	}
}

// TestValidateTemplate covers MSG-004: custom templates may reference only
// the documented variables of their event, cannot call functions, run
// pipelines or other template actions, cannot place values in scripts,
// styles or event handlers, and cannot build a link from anything but the
// server-built {{.link}}; untrusted values lose control characters.
func TestValidateTemplate(t *testing.T) {
	reset, newLogin := Variables[TplPasswordReset], Variables[TplNewLogin]
	ok := []struct{ subject, text, html string }{
		{"Reset {{.realm}}", "Code {{.code}}, or {{ .link }}. Expires in {{- .expires_minutes -}} min.", ""},
		{"Reset", "Code {{.code}}", `<p title="{{.realm}}">Code <b>{{.code}}</b></p><a href="{{.link}}">Reset</a><a href={{ .link }}>again</a>`},
	}
	for _, c := range ok {
		if err := ValidateTemplate(c.subject, c.text, c.html, reset); err != nil {
			t.Errorf("valid template refused: %+v: %v", c, err)
		}
	}
	refused := map[string]struct {
		text, html string
		vars       []string
	}{
		"undocumented variable":          {"{{.secret}}", "", reset},
		"configuration":                  {"{{.Cfg.Delivery.Email.SMTPPassword}}", "", reset},
		"whole data map":                 {"{{.}}", "", reset},
		"another event's secret":         {"Code {{.code}}", "", newLogin},
		"function call":                  {`{{printf "%s" .code}}`, "", reset},
		"call builtin":                   {"{{call .link}}", "", reset},
		"pipeline":                       {"{{.code | html}}", "", reset},
		"nested template":                {`{{template "x" .}}`, "", reset},
		"definition":                     {`{{define "x"}}{{end}}`, "", reset},
		"variable":                       {"{{$c := .code}}{{$c}}", "", reset},
		"range":                          {"{{range .code}}{{end}}", "", reset},
		"conditional":                    {"{{if .code}}x{{end}}", "", reset},
		"unterminated action":            {"Code {{.code", "", reset},
		"value builds a link":            {"x", `<a href="https://evil.test/?c={{.code}}">x</a>`, reset},
		"untrusted value as link":        {"x", `<a href="{{.device}}">x</a>`, newLogin},
		"link inside another URL":        {"x", `<a href="https://evil.test/?r={{.link}}">x</a>`, reset},
		"image source":                   {"x", `<img src="{{.realm}}">`, reset},
		"script":                         {"x", `<script>location = {{.link}}</script>`, reset},
		"style element":                  {"x", `<style>p { color: {{.realm}} }</style>`, reset},
		"style attribute":                {"x", `<p style="background:url({{.link}})">x</p>`, reset},
		"event handler":                  {"x", `<p onclick="go({{.realm}})">x</p>`, reset},
		"meta refresh":                   {"x", `<meta http-equiv="refresh" content="0;url={{.link}}">`, reset},
		"attribute name":                 {"x", `<p {{.realm}}="1">x</p>`, reset},
		"tag name":                       {"x", `<{{.realm}}>x`, reset},
		"html variable not documented":   {"x", `<p>{{.network}}</p>`, reset},
		"html unclosed attribute at end": {"x", `<a href="{{.link}}`, reset},
	}
	for name, c := range refused {
		if err := ValidateTemplate("Subject", c.text, c.html, c.vars); err == nil {
			t.Errorf("%s: unsafe template accepted (text %q, html %q)", name, c.text, c.html)
		}
	}
	if err := ValidateTemplate("{{.realm}}", strings.Repeat("x", 33*1024), "", reset); err == nil {
		t.Error("oversized template accepted")
	}
	if got := sanitizeValue("Bob\r\nBcc: thief@example.test\x00\x1b[31m"); got != "Bob  Bcc: thief@example.test[31m" {
		t.Errorf("control characters kept in an untrusted value: %q", got)
	}
}
