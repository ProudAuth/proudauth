package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
)

// Deliver pushes due events of push streams (RFC 8935). A 2xx answer
// delivers; a 400 with an error code (the receiver rejected the token)
// fails the event without retry; anything else retries with backoff, up to
// maxAttempts. Events of paused streams wait.
func (s *Service) Deliver(ctx context.Context, realmByID func(ctx context.Context, id string) (*realm.Realm, error)) (int, error) {
	now := s.d.Now()
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE ssf_events e SET attempts=attempts+1, next_attempt_at=$2
		WHERE e.id IN (SELECT e2.id FROM ssf_events e2 JOIN ssf_streams st ON st.id=e2.stream_id
			WHERE e2.state='pending' AND e2.next_attempt_at <= $1 AND st.status='enabled' AND st.delivery_method='`+MethodPush+`'
			ORDER BY e2.next_attempt_at LIMIT 50 FOR UPDATE OF e2 SKIP LOCKED)
		RETURNING `+queuedCols, now, now.Add(time.Minute))
	if err != nil {
		return 0, err
	}
	list, err := scanQueued(rows)
	if err != nil {
		return 0, err
	}
	client := s.Egress.Client()
	for _, e := range list {
		rlm, err := realmByID(ctx, e.realm)
		if err != nil {
			continue
		}
		var endpoint, audience string
		var auth []byte
		if err := s.d.DB.Pool.QueryRow(ctx, `SELECT coalesce(endpoint_url,''), audience, authorization_ciphertext FROM ssf_streams WHERE id=$1`, e.stream).
			Scan(&endpoint, &audience, &auth); err != nil {
			continue
		}
		if !Enabled(rlm) {
			// Paused by the realm, not failed: the attempt is not counted
			// and delivery resumes when the transmitter is declared again.
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET attempts=attempts-1, next_attempt_at=$2, last_error='transmitter_disabled' WHERE id=$1`,
				e.id, now.Add(10*time.Minute))
			continue
		}
		tok, err := s.set(ctx, rlm, audience, e)
		if err != nil {
			s.retry(ctx, e, 0, "signing_failed")
			continue
		}
		code, err := s.push(ctx, client, e.stream, endpoint, auth, tok)
		switch {
		case err == nil:
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='delivered', delivered_at=$2, last_status_code=$3, last_error=NULL WHERE id=$1`, e.id, now, code)
		case errors.Is(err, errPermanent):
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='failed', last_status_code=$2, last_error=$3 WHERE id=$1`, e.id, code, err.Error())
		default:
			s.retry(ctx, e, code, err.Error())
		}
	}
	return len(list), nil
}

func (s *Service) push(ctx context.Context, client *http.Client, stream, endpoint string, auth []byte, tok string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(tok))
	if err != nil {
		return 0, errors.Join(errPermanent, errors.New("invalid_endpoint"))
	}
	req.Header.Set("Content-Type", "application/secevent+jwt")
	req.Header.Set("Accept", "application/json")
	if auth != nil {
		h, err := s.d.Keys.Decrypt(keys.PurposeWebhook, auth, []byte("ssf:"+stream))
		if err != nil {
			return 0, errors.New("authorization_unavailable")
		}
		req.Header.Set("Authorization", string(h))
	}
	res, err := client.Do(req)
	if err != nil {
		if errors.Is(err, egress.ErrForbiddenDestination) {
			return 0, errors.New("egress_denied")
		}
		return 0, errors.New("network_error")
	}
	body, _ := s.Egress.ReadLimited(res.Body)
	res.Body.Close()
	switch {
	case res.StatusCode >= 200 && res.StatusCode < 300:
		return res.StatusCode, nil
	case res.StatusCode == http.StatusBadRequest:
		// RFC 8935 §2.4: the receiver rejected this token; sending it
		// again does not help.
		var e struct {
			Err string `json:"err"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Err == "" {
			e.Err = "invalid_request"
		}
		return res.StatusCode, errors.Join(errPermanent, errors.New("rejected_"+e.Err))
	}
	return res.StatusCode, errors.New("http_" + http.StatusText(res.StatusCode))
}

func (s *Service) retry(ctx context.Context, e queued, code int, reason string) {
	var status *int
	if code != 0 {
		status = &code
	}
	if e.attempts >= maxAttempts {
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='failed', last_status_code=$2, last_error=$3 WHERE id=$1`, e.id, status, reason)
		return
	}
	backoff := time.Duration(1<<min(e.attempts, 10)) * 10 * time.Second
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET next_attempt_at=$2, last_status_code=$3, last_error=$4 WHERE id=$1`,
		e.id, s.d.Now().Add(backoff), status, reason)
}

// PollRequest is an RFC 8936 poll.
type PollRequest struct {
	Ack               []string                     `json:"ack"`
	SetErrs           map[string]map[string]string `json:"setErrs"`
	MaxEvents         *int                         `json:"maxEvents"`
	ReturnImmediately bool                         `json:"returnImmediately"`
}

// Poll acknowledges events and returns the next ones (RFC 8936). Returned
// events stay outstanding until acknowledged or reported as errors, and
// are returned again by later polls.
func (s *Service) Poll(ctx context.Context, rlm *realm.Realm, clientRef, id string, in PollRequest) (map[string]any, error) {
	st, err := s.Stream(ctx, rlm, clientRef, id)
	if err != nil {
		return nil, err
	}
	if st.Delivery.Method != MethodPoll {
		return nil, problem.ErrConflict.WithDetail("the stream uses push delivery")
	}
	if len(in.Ack) > 1000 || len(in.SetErrs) > 1000 {
		return nil, problem.ErrValidation.WithField("ack", "at most 1000 acknowledgements per poll")
	}
	limit := 50
	if in.MaxEvents != nil {
		if *in.MaxEvents < 0 {
			return nil, problem.ErrValidation.WithField("maxEvents", "zero or more")
		}
		limit = min(*in.MaxEvents, 100)
	}
	now := s.d.Now()
	if len(in.Ack) > 0 {
		if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='acknowledged', delivered_at=coalesce(delivered_at,$3)
			WHERE stream_id=$1 AND id = ANY($2) AND state IN ('pending','delivered')`, st.ID, in.Ack, now); err != nil {
			return nil, err
		}
	}
	for jti, e := range in.SetErrs {
		if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='failed', last_error=$3 WHERE stream_id=$1 AND id=$2 AND state IN ('pending','delivered')`,
			st.ID, jti, "receiver_"+truncate(e["err"], 60)); err != nil {
			return nil, err
		}
	}
	sets := map[string]string{}
	more := false
	if st.Status == "enabled" && Enabled(rlm) && limit > 0 {
		rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+queuedCols+` FROM ssf_events e WHERE e.stream_id=$1 AND e.state IN ('pending','delivered')
			ORDER BY e.occurred_at, e.id LIMIT $2`, st.ID, limit+1)
		if err != nil {
			return nil, err
		}
		list, err := scanQueued(rows)
		if err != nil {
			return nil, err
		}
		if len(list) > limit {
			list, more = list[:limit], true
		}
		for _, e := range list {
			tok, err := s.set(ctx, rlm, st.Audience, e)
			if err != nil {
				return nil, err
			}
			sets[e.id] = tok
			if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events SET state='delivered', delivered_at=coalesce(delivered_at,$2), attempts=attempts+1
				WHERE id=$1 AND state='pending'`, e.id, now); err != nil {
				return nil, err
			}
		}
	}
	return map[string]any{"sets": sets, "moreAvailable": more}, nil
}

// EventView is an administrator's view of a queued event (no token).
type EventView struct {
	ID             string     `json:"jti"`
	EventType      string     `json:"event_type"`
	State          string     `json:"state"`
	Attempts       int        `json:"attempts"`
	OccurredAt     time.Time  `json:"occurred_at"`
	DeliveredAt    *time.Time `json:"delivered_at,omitempty"`
	LastStatusCode *int       `json:"last_status_code,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
}

// Events lists a stream's recent events, newest first.
func (s *Service) Events(ctx context.Context, rlm *realm.Realm, id string) ([]EventView, error) {
	if _, err := s.Stream(ctx, rlm, "", id); err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, event_type, state, attempts, occurred_at, delivered_at, last_status_code, coalesce(last_error,'')
		FROM ssf_events WHERE stream_id=$1 ORDER BY occurred_at DESC, id DESC LIMIT 200`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventView{}
	for rows.Next() {
		var v EventView
		if err := rows.Scan(&v.ID, &v.EventType, &v.State, &v.Attempts, &v.OccurredAt, &v.DeliveredAt, &v.LastStatusCode, &v.LastError); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Prune expires events nobody collected within the retention window and
// removes finished events after it.
func (s *Service) Prune(ctx context.Context) (int64, error) {
	cutoff := s.d.Now().Add(-retention)
	// Pushed events that were delivered are done; only undelivered events,
	// and polled events never acknowledged, expire.
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE ssf_events e SET state='expired' WHERE e.occurred_at < $1 AND (e.state='pending'
		OR (e.state='delivered' AND EXISTS (SELECT 1 FROM ssf_streams st WHERE st.id=e.stream_id AND st.delivery_method='`+MethodPoll+`')))`, cutoff)
	if err != nil {
		return 0, err
	}
	n := tag.RowsAffected()
	tag, err = s.d.DB.Pool.Exec(ctx, `DELETE FROM ssf_events e WHERE e.occurred_at < $1 AND (e.state IN ('acknowledged','failed','expired')
		OR (e.state='delivered' AND EXISTS (SELECT 1 FROM ssf_streams st WHERE st.id=e.stream_id AND st.delivery_method='`+MethodPush+`')))`, cutoff.Add(-retention))
	if err != nil {
		return n, err
	}
	return n + tag.RowsAffected(), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
