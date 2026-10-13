package bench

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The benchmark receiver verifies the published signature independently of
// ProudAuth's webhook package. It keeps bounded in-flight observations and
// aggregate counters, never payloads or signing secrets in result JSON.
type webhookHub struct {
	mu     sync.RWMutex
	routes map[string]*webhookWorker
	server *http.Server
	done   chan error
	origin string
	now    func() time.Time
}

func (e *Env) getWebhookHub() (*webhookHub, error) {
	if e.webhookHub != nil {
		return e.webhookHub, nil
	}
	addr := e.WebhookListen
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	origin := e.WebhookURL
	if origin == "" {
		origin = "http://" + ln.Addr().String()
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		ln.Close()
		return nil, fmt.Errorf("webhook receiver URL must be an absolute http(s) base without credentials, query or fragment")
	}
	if e.WebhookURL == "" {
		host, _, _ := net.SplitHostPort(ln.Addr().String())
		if !net.ParseIP(host).IsLoopback() {
			ln.Close()
			return nil, fmt.Errorf("non-loopback webhook listener needs an explicit public --webhook-url")
		}
	}
	h := &webhookHub{routes: map[string]*webhookWorker{}, origin: strings.TrimSuffix(u.String(), "/"), now: time.Now, done: make(chan error, 1)}
	if e.Now != nil {
		h.now = e.Now
	}
	h.server = &http.Server{Handler: h, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	e.webhookHub = h
	go func() { h.done <- h.server.Serve(ln) }()
	return h, nil
}

func (h *webhookHub) add(suffix string, w *webhookWorker) string {
	u, _ := url.Parse(h.origin + suffix)
	h.mu.Lock()
	h.routes[u.Path] = w
	h.mu.Unlock()
	return u.String()
}
func (h *webhookHub) remove(destination string) {
	u, _ := url.Parse(destination)
	h.mu.Lock()
	delete(h.routes, u.Path)
	h.mu.Unlock()
}
func (h *webhookHub) closeIfEmpty(e *Env) error {
	h.mu.RLock()
	empty := len(h.routes) == 0
	h.mu.RUnlock()
	if !empty {
		return nil
	}
	err := h.server.Close()
	serveErr := <-h.done
	if serveErr == http.ErrServerClosed {
		serveErr = nil
	}
	e.webhookHub = nil
	if err != nil {
		return err
	}
	return serveErr
}
func (h *webhookHub) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	w := h.routes[r.URL.Path]
	h.mu.RUnlock()
	if w == nil {
		http.NotFound(rw, r)
		return
	}
	select {
	case <-w.ready:
	case <-r.Context().Done():
		return
	case <-time.After(4 * time.Second):
		rw.WriteHeader(503)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	valid := err == nil && len(body) <= 64<<10 && r.Method == "POST" && media == "application/json"
	for _, key := range []string{"Webhook-Id", "Webhook-Timestamp", "Webhook-Signature"} {
		valid = valid && len(r.Header.Values(key)) == 1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stats.Received++
	if !valid || !verifyWebhookHMAC(w.secret, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"), body, h.now()) {
		w.stats.Invalid++
		rw.WriteHeader(401)
		return
	}
	var event struct {
		ID          string    `json:"event_id"`
		Type        string    `json:"event_type"`
		Version     int       `json:"event_version"`
		Realm       string    `json:"realm_id"`
		Org         string    `json:"organization_id"`
		Correlation string    `json:"correlation_id"`
		Form        string    `json:"payload_form"`
		OccurredAt  time.Time `json:"occurred_at"`
		Data        struct {
			Member string `json:"membership_id"`
			User   string `json:"user_id"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &event) != nil || event.OccurredAt.IsZero() || event.ID == "" || event.ID != r.Header.Get("Webhook-Id") || event.Version != 2 || event.Form != "minimal" || event.Realm != w.realm || event.Org != w.org {
		w.stats.Invalid++
		rw.WriteHeader(422)
		return
	}
	cycle := w.pending[event.Correlation]
	if cycle == nil {
		// Old outbox events and work interrupted at a window boundary do
		// not prove a new operation. They still need a valid signature.
		w.stats.Ignored++
		rw.WriteHeader(204)
		return
	}
	if event.Data.User != w.user || event.Data.Member == "" || (event.Type != memberAdded && event.Type != memberRemoved) {
		cycle.bad = "invariant_wrong_event"
		w.stats.Invalid++
		rw.WriteHeader(422)
		return
	}
	seen := cycle.events[event.Type]
	ts, _ := strconv.ParseInt(r.Header.Get("Webhook-Timestamp"), 10, 64)
	digest := sha256.Sum256(body)
	if seen == nil {
		seen = &webhookReceipt{id: event.ID, member: event.Data.Member, firstTimestamp: ts, bodyHash: digest}
		cycle.events[event.Type] = seen
	} else if seen.id != event.ID || seen.member != event.Data.Member || seen.bodyHash != digest {
		cycle.bad = "invariant_changed_retry"
		w.stats.Invalid++
		rw.WriteHeader(422)
		return
	}
	seen.attempts++
	seen.lastTimestamp = ts
	if w.retry && seen.attempts == 1 {
		w.stats.Intentional503++
		if w.stats.FirstRetryAt.IsZero() {
			w.stats.FirstRetryAt = h.now().UTC()
		}
		w.stats.LastRetryAt = h.now().UTC()
		rw.WriteHeader(503)
		return
	}
	if w.retry && seen.firstTimestamp == ts {
		cycle.bad = "invariant_stale_retry_timestamp"
		w.stats.Invalid++
		rw.WriteHeader(422)
		return
	}
	seen.accepted = true
	w.stats.Accepted++
	if w.retry {
		w.stats.Recovered++
		w.stats.LastRecoveryAt = h.now().UTC()
	}
	rw.WriteHeader(204)
}

func verifyWebhookHMAC(key []byte, id, ts, header string, body []byte, now time.Time) bool {
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || id == "" || len(key) != 32 || now.Sub(time.Unix(seconds, 0)).Abs() > 5*time.Minute {
		return false
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(id + "." + ts + "."))
	_, _ = m.Write(body)
	want := "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
	for _, part := range strings.Fields(header) {
		if hmac.Equal([]byte(part), []byte(want)) {
			return true
		}
	}
	return false
}

type webhookStats struct {
	Received       int64     `json:"received"`
	Accepted       int64     `json:"accepted"`
	Intentional503 int64     `json:"intentional_503"`
	Recovered      int64     `json:"recovered"`
	Invalid        int64     `json:"invalid"`
	Ignored        int64     `json:"ignored_abandoned_or_old_events"`
	FirstRetryAt   time.Time `json:"first_retry_at"`
	LastRetryAt    time.Time `json:"last_retry_at"`
	LastRecoveryAt time.Time `json:"last_recovery_at"`
}
type webhookReceipt struct {
	id, member                    string
	bodyHash                      [32]byte
	firstTimestamp, lastTimestamp int64
	attempts                      int
	accepted                      bool
}
type webhookCycle struct {
	events map[string]*webhookReceipt
	bad    string
}
type webhookWorker struct {
	mu                                          sync.Mutex
	ready                                       chan struct{}
	secret                                      []byte
	realm, org, user, subscription, destination string
	retry                                       bool
	pending                                     map[string]*webhookCycle
	stats                                       webhookStats
}
