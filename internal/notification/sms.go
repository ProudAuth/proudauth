package notification

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/platform/ids"
)

// WebhookSMSSender delivers SMS through an operator-run gateway (MSG-008,
// PWDLESS-005). The project ships no paid SMS provider integration; the gateway
// relays to whatever carrier the operator chooses. Requests are signed with
// HMAC-SHA256 over "<timestamp>.<body>" so the gateway can reject forgeries:
//
//	X-ProudAuth-Timestamp: <unix seconds>
//	X-ProudAuth-Signature: v1,<base64 HMAC>
//
// The body is {"id","to","text"}; the gateway returns 2xx with an optional
// {"message_id"}.
type WebhookSMSSender struct {
	URL       string
	SecretRef string
	Egress    egress.Policy
	Now       func() int64
}

// Send posts one message to the gateway.
func (w *WebhookSMSSender) Send(ctx context.Context, to, text string) (string, error) {
	key, err := configuration.ResolveSecret(w.SecretRef)
	if err != nil || key == "" {
		return "", fmt.Errorf("sms gateway secret unavailable")
	}
	if err := w.Egress.ValidateURL(w.URL); err != nil {
		return "", err
	}
	id := ids.New("sms")
	body, _ := json.Marshal(map[string]string{"id": id, "to": to, "text": text})
	ts := strconv.FormatInt(w.Now(), 10)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-ProudAuth-Timestamp", ts)
	req.Header.Set("X-ProudAuth-Signature", "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	res, err := w.Egress.Client().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	raw, _ := w.Egress.ReadLimited(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return "", fmt.Errorf("sms gateway returned %d", res.StatusCode)
	}
	var out struct {
		MessageID string `json:"message_id"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.MessageID == "" {
		out.MessageID = id
	}
	return out.MessageID, nil
}

// smsAllowed reports whether an E.164 number matches the operator's allowed
// country calling-code prefixes (empty list: no restriction).
func smsAllowed(prefixes []string, to string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(to, p) {
			return true
		}
	}
	return false
}

// SMSCountryAllowed applies the operator's country restriction.
func (s *Service) SMSCountryAllowed(to string) bool {
	return smsAllowed(s.d.Cfg.Delivery.SMS.AllowedCountries, to)
}
