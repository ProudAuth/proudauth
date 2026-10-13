package notification

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/proudbase/proudauth/internal/egress"
)

func TestWebhookSMSSenderSignsRequests(t *testing.T) {
	t.Setenv("SMS_SECRET", "gateway-secret")
	var got struct {
		body, ts, sig string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.body, got.ts, got.sig = string(b), r.Header.Get("X-ProudAuth-Timestamp"), r.Header.Get("X-ProudAuth-Signature")
		_ = json.NewEncoder(w).Encode(map[string]string{"message_id": "m-1"})
	}))
	defer srv.Close()
	s := &WebhookSMSSender{URL: srv.URL, SecretRef: "env:SMS_SECRET", Egress: egress.Policy{AllowPrivate: true}, Now: func() int64 { return 1700000000 }}
	id, err := s.Send(context.Background(), "+15550100001", "Your code is 123456")
	if err != nil || id != "m-1" {
		t.Fatalf("send: %v %q", err, id)
	}
	mac := hmac.New(sha256.New, []byte("gateway-secret"))
	mac.Write([]byte("1700000000." + got.body))
	if got.ts != "1700000000" || got.sig != "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature: ts=%s sig=%s", got.ts, got.sig)
	}
	// The egress policy applies: private destinations are refused by default.
	blocked := &WebhookSMSSender{URL: srv.URL, SecretRef: "env:SMS_SECRET", Egress: egress.Policy{}, Now: s.Now}
	if _, err := blocked.Send(context.Background(), "+15550100001", "x"); err == nil {
		t.Fatal("SMS gateway on a private address reached without an explicit egress allowance")
	}
	if !smsAllowed([]string{"+1", "+44"}, "+447700900000") || smsAllowed([]string{"+1"}, "+447700900000") || !smsAllowed(nil, "+33") {
		t.Fatal("country prefix restriction")
	}
}
