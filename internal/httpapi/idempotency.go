package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/storage"
)

type captureWriter struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = 200
	}
	c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

// secretFields mark responses that carry one-time secrets. They are never replayed
// from the idempotency store (API-006).
var secretFields = []string{`"client_secret"`, `"client_secrets"`, `"token"`, `"api_key"`, `"signing_secret"`, `"setup_token"`, `"recovery_codes"`,
	`"invitation_secret"`, `"access_token"`, `"refresh_token"`, `"id_token"`, `"handoff_code"`, `"download_token"`, `"secret"`, `"webhook_secrets"`}

// idempotent wraps a POST handler with actor/realm/route-bound idempotency (API-005).
func (a *App) idempotent(w http.ResponseWriter, r *http.Request, p *Principal, h handlerFunc) error {
	key := r.Header.Get("Idempotency-Key")
	if r.Method != http.MethodPost || key == "" {
		return h(w, r, p)
	}
	if len(key) > 255 {
		return problem.ErrValidation.WithField("Idempotency-Key", "at most 255 characters")
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return problem.ErrTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	// The hash covers the target too: a key reused for another resource on
	// the same route is a mismatch, never a replay of the first response.
	hsh := sha256.New()
	hsh.Write([]byte(r.Method + " " + r.URL.Path + "\n"))
	hsh.Write(body)
	reqHash := hex.EncodeToString(hsh.Sum(nil))
	route := routeLabel(r.URL.Path)
	keyDigest := secret.Digest(key)
	ctx := r.Context()
	var storedHash string
	var status *int
	var resp []byte
	var containsSecret bool
	err = a.D.DB.Pool.QueryRow(ctx, `SELECT request_hash, status_code, response_body, contains_secret FROM idempotency_records
		WHERE realm_id=$1 AND actor_id=$2 AND route=$3 AND key_digest=$4 AND expires_at > $5`, p.Realm.ID, p.SubjectID, route, keyDigest, a.D.Now()).
		Scan(&storedHash, &status, &resp, &containsSecret)
	if err == nil {
		if storedHash != reqHash {
			return problem.ErrIdempotencyMismatch
		}
		if status == nil {
			return problem.ErrConflict.WithDetail("a request with this idempotency key is still in progress")
		}
		if containsSecret {
			return problem.ErrConflict.WithDetail("the original response contained a one-time secret and cannot be replayed").
				WithExtension("original_status", *status)
		}
		w.Header().Set("Idempotent-Replayed", "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(*status)
		_, _ = w.Write(resp)
		return nil
	}
	if !storage.IsNoRows(err) {
		return err
	}
	recID := ids.New(ids.Idempotency)
	if _, err := a.D.DB.Pool.Exec(ctx, `INSERT INTO idempotency_records (id, realm_id, actor_id, route, key_digest, request_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, recID, p.Realm.ID, p.SubjectID, route, keyDigest, reqHash, a.D.Now().Add(24*time.Hour)); err != nil {
		if storage.IsUniqueViolation(err) {
			return problem.ErrConflict.WithDetail("a request with this idempotency key is still in progress")
		}
		return err
	}
	cw := &captureWriter{ResponseWriter: w}
	herr := h(cw, r, p)
	if herr != nil || cw.status >= 400 || cw.status == 0 {
		_, _ = a.D.DB.Pool.Exec(ctx, `DELETE FROM idempotency_records WHERE id=$1`, recID)
		return herr
	}
	out := cw.buf.Bytes()
	hasSecret := false
	for _, f := range secretFields {
		if bytes.Contains(out, []byte(f)) {
			hasSecret = true
		}
	}
	var stored any = nil
	if !hasSecret && json.Valid(out) && len(out) > 0 {
		stored = json.RawMessage(out)
	}
	_, _ = a.D.DB.Pool.Exec(ctx, `UPDATE idempotency_records SET status_code=$2, response_body=$3, contains_secret=$4 WHERE id=$1`,
		recID, cw.status, stored, hasSecret)
	return nil
}

var _ = strings.TrimSpace
