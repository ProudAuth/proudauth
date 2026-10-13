package webhooks

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPublishedSignatureVector covers EXT-003 and EXT-004: the signature
// scheme published in api/events/envelope.v1.json (x-signature) is the one
// the server computes. Each value is versioned ("v1,"), covers the exact body
// together with the Webhook-Id and Webhook-Timestamp, and during a secret
// rollover the previous secret signs alongside the new one. A receiver
// rejects a changed body, event ID or timestamp, a stale timestamp and an
// unrelated key, so a valid signature alone is not proof of freshness.
func TestPublishedSignatureVector(t *testing.T) {
	raw, err := os.ReadFile("../../api/events/envelope.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Signature struct {
			Scheme string `json:"scheme"`
			Vector struct {
				Secret           string `json:"secret"`
				PreviousSecret   string `json:"previous_secret"`
				WebhookID        string `json:"webhook_id"`
				WebhookTimestamp string `json:"webhook_timestamp"`
				Body             string `json:"body"`
				WebhookSignature string `json:"webhook_signature"`
			} `json:"test_vector"`
		} `json:"x-signature"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	v := doc.Signature.Vector
	if doc.Signature.Scheme != "v1" || v.Secret == "" || v.PreviousSecret == "" || v.WebhookID == "" || v.Body == "" || v.WebhookSignature == "" {
		t.Fatalf("published test vector incomplete: %+v", doc.Signature)
	}
	ts, err := strconv.ParseInt(v.WebhookTimestamp, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(v.Body)
	got := Sign(v.Secret, v.WebhookID, ts, body) + " " + Sign(v.PreviousSecret, v.WebhookID, ts, body)
	if got != v.WebhookSignature {
		t.Fatalf("server signature differs from the published vector:\n got %s\nwant %s", got, v.WebhookSignature)
	}
	for _, part := range strings.Fields(got) {
		if !strings.HasPrefix(part, "v1,") {
			t.Fatalf("signature value is not versioned: %q", part)
		}
	}
	// Secrets issued before v0.2 were unpadded; both forms are the same key.
	if Sign(strings.TrimRight(v.Secret, "=")+"=", v.WebhookID, ts, body) != Sign(v.Secret, v.WebhookID, ts, body) {
		t.Fatal("padded and unpadded secrets sign differently")
	}

	now := time.Unix(ts, 0)
	const tolerance = 5 * time.Minute
	for name, sec := range map[string]string{"new secret": v.Secret, "previous secret": v.PreviousSecret} {
		if err := VerifySignature(sec, v.WebhookID, v.WebhookTimestamp, v.WebhookSignature, body, now, tolerance); err != nil {
			t.Fatalf("%s does not verify during the rollover: %v", name, err)
		}
	}
	refused := map[string]error{
		"changed body":      VerifySignature(v.Secret, v.WebhookID, v.WebhookTimestamp, v.WebhookSignature, append([]byte(v.Body), ' '), now, tolerance),
		"other event id":    VerifySignature(v.Secret, "obx_01jbh0ybgaravg3xcq0zdp2egz", v.WebhookTimestamp, v.WebhookSignature, body, now, tolerance),
		"other timestamp":   VerifySignature(v.Secret, v.WebhookID, strconv.FormatInt(ts+1, 10), v.WebhookSignature, body, now, tolerance),
		"stale timestamp":   VerifySignature(v.Secret, v.WebhookID, v.WebhookTimestamp, v.WebhookSignature, body, now.Add(tolerance+time.Second), tolerance),
		"future timestamp":  VerifySignature(v.Secret, v.WebhookID, v.WebhookTimestamp, v.WebhookSignature, body, now.Add(-tolerance-time.Second), tolerance),
		"unrelated key":     VerifySignature("whsec_d3Jvbmcta2V5LXdyb25nLWtleS13cm9uZy1rZXk=", v.WebhookID, v.WebhookTimestamp, v.WebhookSignature, body, now, tolerance),
		"unversioned value": VerifySignature(v.Secret, v.WebhookID, v.WebhookTimestamp, strings.TrimPrefix(Sign(v.Secret, v.WebhookID, ts, body), "v1,"), body, now, tolerance),
	}
	for name, err := range refused {
		if err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// TestMinimalPayloadForm covers EXT-008's minimal-PII event form: a
// "minimal" subscription receives the envelope with only identifiers and the
// listed non-personal members of data; personal attributes are removed and
// the envelope itself is unchanged.
func TestMinimalPayloadForm(t *testing.T) {
	in := []byte(`{"event_id":"obx_1","event_type":"user.updated","event_version":1,"occurred_at":"2026-10-10T12:00:00Z","realm_id":"rlm_1","org_id":"org_1",
		"data":{"user_id":"usr_1","membership_id":"mem_1","state":"active","reason":"TEST","authorization_revision":3,
		"email":"alice@example.test","display_name":"Alice","phone":"+15550100","given_name":"Alice","ip_address":"192.0.2.1"}}`)
	var out map[string]any
	if err := json.Unmarshal(minimal(in), &out); err != nil {
		t.Fatal(err)
	}
	data := out["data"].(map[string]any)
	for _, kept := range []string{"user_id", "membership_id", "state", "reason", "authorization_revision"} {
		if _, ok := data[kept]; !ok {
			t.Errorf("minimal form dropped %s", kept)
		}
	}
	for _, personal := range []string{"email", "display_name", "phone", "given_name", "ip_address"} {
		if _, ok := data[personal]; ok {
			t.Errorf("minimal form kept personal member %s", personal)
		}
	}
	for _, member := range []string{"event_id", "event_type", "event_version", "occurred_at", "realm_id", "org_id"} {
		if out[member] == nil {
			t.Errorf("minimal form changed the envelope: %s missing", member)
		}
	}
}
