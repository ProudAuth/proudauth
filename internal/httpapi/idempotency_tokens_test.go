package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/clock"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/testutil"
)

// TestIdempotencyNeverStoresIssuedTokens covers QA-008 and API-006 (with
// API-005): a response carrying a refresh_token or an id_token is not stored
// in idempotency_records, and a retry with the same Idempotency-Key gets 409
// with original_status instead of the tokens, without running the handler
// again. No current route returns these members through the idempotency
// layer, so the middleware is driven directly; a secret-free response is
// stored and replayed as the control.
func TestIdempotencyNeverStoresIssuedTokens(t *testing.T) {
	db := testutil.NewDB(t)
	cfg := configuration.Defaults()
	a := &App{D: runtime.New(db, &cfg, clock.NewFake(time.Now()), keys.NewRandom(), nil)}
	p := &Principal{Realm: &realm.Realm{ID: ids.New(ids.Realm)}, Kind: "user", SubjectID: ids.New(ids.User)}
	ctx := context.Background()
	call := func(key, body string, calls *int) (*httptest.ResponseRecorder, error) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/realms/main/me/token-issuer", strings.NewReader(`{"n":1}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		w := httptest.NewRecorder()
		err := a.idempotent(w, r, p, func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			*calls++
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return nil
		})
		return w, err
	}
	record := func(key string) (stored, containsSecret bool) {
		t.Helper()
		if err := db.Pool.QueryRow(ctx, `SELECT response_body IS NOT NULL, contains_secret FROM idempotency_records
			WHERE realm_id=$1 AND actor_id=$2 AND key_digest=$3`, p.Realm.ID, p.SubjectID, secret.Digest(key)).Scan(&stored, &containsSecret); err != nil {
			t.Fatalf("idempotency record for %s: %v", key, err)
		}
		return stored, containsSecret
	}

	for _, member := range []string{"refresh_token", "id_token"} {
		key, value := "key-"+member, "issued-"+member+"-value"
		body := `{"` + member + `":"` + value + `","expires_in":300}`
		calls := 0
		w, err := call(key, body, &calls)
		if err != nil || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), value) {
			t.Fatalf("%s: first response %d %v %s", member, w.Code, err, w.Body)
		}
		if stored, containsSecret := record(key); stored || !containsSecret {
			t.Fatalf("%s: response stored %v, contains_secret %v", member, stored, containsSecret)
		}
		w, err = call(key, body, &calls)
		pe, ok := problem.As(err)
		if !ok || pe.Status != http.StatusConflict || pe.Extensions["original_status"] != http.StatusOK {
			t.Fatalf("%s: retry returned %v (status %d)", member, err, w.Code)
		}
		if calls != 1 || strings.Contains(w.Body.String(), value) {
			t.Fatalf("%s: retry ran the handler again (%d calls) or replayed the token: %s", member, calls, w.Body)
		}
	}

	// Control: a response without one-time secrets is stored and replayed.
	calls := 0
	if _, err := call("key-plain", `{"id":"org_1","expires_in":300}`, &calls); err != nil {
		t.Fatal(err)
	}
	if stored, containsSecret := record("key-plain"); !stored || containsSecret {
		t.Fatalf("plain response: stored %v, contains_secret %v", stored, containsSecret)
	}
	w, err := call("key-plain", `{"id":"org_1","expires_in":300}`, &calls)
	if err != nil || calls != 1 || w.Header().Get("Idempotent-Replayed") != "true" || !strings.Contains(w.Body.String(), "org_1") {
		t.Fatalf("plain response not replayed: %v, %d calls, %s", err, calls, w.Body)
	}
}
