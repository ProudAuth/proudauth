package e2e

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Race-condition scenarios (SEC-008): duplicate submission under one
// idempotency key, concurrent role-permission edits and concurrent
// required-action edits, each driven by real concurrent requests released
// together by a start barrier.

// raceRun runs fn(0..n-1) in n goroutines that are released at the same
// moment, and waits for all of them.
func raceRun(n int, fn func(i int)) {
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer done.Done()
			ready.Done()
			<-start
			fn(i)
		}(i)
	}
	ready.Wait()
	close(start)
	done.Wait()
}

// raceStrings converts a decoded JSON array into a sorted string slice.
func raceStrings(v any) []string {
	out := []string{}
	list, _ := v.([]any)
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// raceToggle returns list with item added when absent and removed when present, sorted.
func raceToggle(list []string, item string) []string {
	out := []string{}
	found := false
	for _, x := range list {
		if x == item {
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		out = append(out, item)
	}
	slices.Sort(out)
	return out
}

func raceCount(t *testing.T, h *Harness, query string, args ...any) int {
	t.Helper()
	var n int
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// raceInProgress reports whether a response is the idempotency layer's
// "still in progress" refusal (API-005).
func raceInProgress(r *Resp) bool {
	return r.Status == 409 && strings.Contains(r.Str("detail"), "idempotency key is still in progress")
}

// TestIdempotencyConcurrentSubmissions covers SEC-008 (duplicate submission),
// API-005 and API-006 under real concurrency: requests sharing an
// Idempotency-Key execute the operation exactly once. Every other request
// gets the stored result (marked Idempotent-Replayed), a 409 while the first
// is still in progress, or, with a different body, 422
// idempotency_key_reused; a secret-bearing response is never handed to a
// second caller.
func TestIdempotencyConcurrentSubmissions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=user.created&limit=1", nil), 200, "events")
	target := ev.Get("items").([]any)[0].(map[string]any)["id"].(string)
	// Audit corrections have no natural key: every execution records one
	// more correction event, so a duplicate execution is visible as a row.
	correct := func(key, reason string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/audit-events/" + target + "/corrections", Token: f.AdminToken,
			JSON: map[string]any{"reason": reason}, Headers: map[string]string{"Idempotency-Key": key}})
	}
	corrections := func() int {
		return raceCount(t, h, `SELECT count(*) FROM audit_events WHERE type='audit.correction' AND target_id=$1`, target)
	}
	const n = 8

	// The same request, submitted concurrently: one execution, the rest
	// replays or in-progress refusals. Rounds repeat until a request
	// overlapped the first execution.
	{
		overlapped := false
		for round := 0; round < 10 && !overlapped; round++ {
			before := corrections()
			key := fmt.Sprintf("race-same-%d", round)
			reason := fmt.Sprintf("ticket %d: duplicate submission race", round)
			res := make([]*Resp, n)
			raceRun(n, func(i int) { res[i] = correct(key, reason) })
			original, eventID := 0, ""
			for _, r := range res {
				if r.Status == 201 && r.Header.Get("Idempotent-Replayed") == "" {
					original++
					eventID = r.Str("event_id")
				}
			}
			if original != 1 {
				t.Fatalf("round %d: %d requests executed (want exactly 1)", round, original)
			}
			replayed, inProgress := 0, 0
			for i, r := range res {
				switch {
				case r.Status == 201 && r.Header.Get("Idempotent-Replayed") == "true":
					if r.Str("event_id") != eventID {
						t.Fatalf("round %d: replay %d returned another result: %s", round, i, r.Raw)
					}
					replayed++
				case raceInProgress(r):
					inProgress++
				case r.Status == 201:
				default:
					t.Fatalf("round %d: request %d: %d %s", round, i, r.Status, r.Raw)
				}
			}
			if got := corrections() - before; got != 1 {
				t.Fatalf("round %d: %d corrections recorded for one idempotency key", round, got)
			}
			t.Logf("round %d: 1 executed, %d replayed, %d refused in progress", round, replayed, inProgress)
			overlapped = inProgress > 0
		}
		if !overlapped {
			t.Fatal("no request overlapped the first execution in 10 rounds")
		}
	}

	// Different bodies under one key: one executes, the rest are refused.
	{
		before := corrections()
		res := make([]*Resp, n)
		raceRun(n, func(i int) { res[i] = correct("race-mixed", fmt.Sprintf("ticket %d: conflicting submission", i)) })
		winner := -1
		for i, r := range res {
			switch {
			case r.Status == 201 && r.Header.Get("Idempotent-Replayed") == "":
				if winner >= 0 {
					t.Fatalf("requests %d and %d both executed", winner, i)
				}
				winner = i
			case raceInProgress(r), r.Status == 422 && r.Str("code") == "idempotency_key_reused":
			default:
				t.Fatalf("request %d: %d %s", i, r.Status, r.Raw)
			}
		}
		if winner < 0 {
			t.Fatal("no request executed")
		}
		if got := corrections() - before; got != 1 {
			t.Fatalf("%d corrections recorded for one idempotency key", got)
		}
		// Afterwards the winner's body replays and every other body is a mismatch.
		again := correct("race-mixed", fmt.Sprintf("ticket %d: conflicting submission", winner))
		if again.Status != 201 || again.Header.Get("Idempotent-Replayed") != "true" || again.Str("event_id") != res[winner].Str("event_id") {
			t.Fatalf("winner's retry: %d %s", again.Status, again.Raw)
		}
		mustStatus(t, correct("race-mixed", fmt.Sprintf("ticket %d: conflicting submission", (winner+1)%n)), 422, "loser's retry")
	}

	// A secret-bearing creation: one caller gets the secret, nobody else.
	{
		body := map[string]any{"client_id": "race-client", "name": "Race", "client_type": "confidential", "redirect_uris": []string{"https://race.test/cb"}}
		res := make([]*Resp, n)
		raceRun(n, func(i int) {
			res[i] = h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/clients", Token: f.AdminToken, JSON: body,
				Headers: map[string]string{"Idempotency-Key": "race-client"}})
		})
		created := 0
		for i, r := range res {
			switch {
			case r.Status == 201:
				if r.Header.Get("Idempotent-Replayed") != "" {
					t.Fatalf("a secret-bearing response was replayed: %s", r.Raw)
				}
				created++
			case r.Status == 409:
				if strings.Contains(string(r.Raw), "client_secret\":\"") || r.Str("client_secret") != "" {
					t.Fatalf("request %d: refusal carries the secret: %s", i, r.Raw)
				}
				if !raceInProgress(r) && !strings.Contains(r.Str("detail"), "cannot be replayed") {
					t.Fatalf("request %d: %s", i, r.Raw)
				}
			default:
				t.Fatalf("request %d: %d %s", i, r.Status, r.Raw)
			}
		}
		if created != 1 {
			t.Fatalf("%d secret-bearing responses for one idempotency key", created)
		}
		if got := raceCount(t, h, `SELECT count(*) FROM clients WHERE realm_id=$1 AND client_id='race-client'`, h.Realm.ID); got != 1 {
			t.Fatalf("%d clients created", got)
		}
	}
}

// TestRolePermissionEditRace covers SEC-008 (role-edit races), API-010 and
// the competing-administrator part of TEST-050: concurrent permission edits
// of one role carrying the same If-Match entity tag have exactly one winner
// (200); every other edit gets 412 and changes nothing, so the role ends with
// exactly the winner's permissions. Edits without a precondition are applied
// one after the other and none is lost.
func TestRolePermissionEditRace(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "race-editor",
		"permissions": []string{"realm.users.read"}}), 201, "role").Str("id")
	perms := []string{"realm.clients.read", "realm.roles.read", "realm.audit.read", "realm.settings.read", "realm.organizations.read", "realm.resources.read"}
	edit := func(perm string, add bool, etag string) *Resp {
		body := map[string]any{"remove": []string{perm}}
		if add {
			body = map[string]any{"add": []string{perm}}
		}
		rq := Req{Method: "POST", Path: "/api/v1/realms/main/roles/" + role + "/permissions", Token: f.AdminToken, JSON: body}
		if etag != "" {
			rq.Headers = map[string]string{"If-Match": etag}
		}
		return h.Do(rq)
	}
	for round := 0; round < 4; round++ {
		cur := f.must(f.AdminAPI("GET", "/roles/"+role, nil), 200, "role")
		etag, have := cur.Header.Get("ETag"), raceStrings(cur.Get("permissions"))
		res := make([]*Resp, len(perms))
		raceRun(len(perms), func(i int) { res[i] = edit(perms[i], !slices.Contains(have, perms[i]), etag) })
		winner := -1
		for i, r := range res {
			switch r.Status {
			case 200:
				if winner >= 0 {
					t.Fatalf("round %d: edits %d and %d both won with the same If-Match", round, winner, i)
				}
				winner = i
			case 412:
			default:
				t.Fatalf("round %d: edit %d: %d %s", round, i, r.Status, r.Raw)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: no edit won", round)
		}
		want := raceToggle(have, perms[winner])
		after := f.must(f.AdminAPI("GET", "/roles/"+role, nil), 200, "role after")
		if got := raceStrings(after.Get("permissions")); !slices.Equal(got, want) {
			t.Fatalf("round %d: permissions %v, want the winner's %v", round, got, want)
		}
		if got := raceStrings(res[winner].Get("permissions")); !slices.Equal(got, want) {
			t.Fatalf("round %d: winner's response %v, want %v", round, got, want)
		}
		if after.Header.Get("ETag") != res[winner].Header.Get("ETag") || after.Get("version").(float64) != cur.Get("version").(float64)+1 {
			t.Fatalf("round %d: version moved by more than the winning edit: %v -> %v", round, cur.Get("version"), after.Get("version"))
		}
	}
	// Without a precondition every concurrent edit applies; none is lost.
	cur := f.must(f.AdminAPI("GET", "/roles/"+role, nil), 200, "role")
	have := raceStrings(cur.Get("permissions"))
	res := make([]*Resp, len(perms))
	raceRun(len(perms), func(i int) { res[i] = edit(perms[i], !slices.Contains(have, perms[i]), "") })
	want := have
	for i, r := range res {
		mustStatus(t, r, 200, fmt.Sprintf("unconditional edit %d", i))
		want = raceToggle(want, perms[i])
	}
	after := f.must(f.AdminAPI("GET", "/roles/"+role, nil), 200, "role after")
	if got := raceStrings(after.Get("permissions")); !slices.Equal(got, want) {
		t.Fatalf("unconditional edits lost an update: %v, want %v", got, want)
	}
	if after.Get("version").(float64) != cur.Get("version").(float64)+float64(len(perms)) {
		t.Fatalf("version %v after %d edits from %v", after.Get("version"), len(perms), cur.Get("version"))
	}
}

// TestRequiredActionEditRace covers SEC-008 and AUT-018 (threat model:
// concurrent required-action edits) and, for competing administrators with a
// stale ETag, TEST-050. POST /users/{user}/required-actions replaces the list
// only if it is still the one the request read (409 otherwise), and only if
// the account is still at the version named by If-Match (412 otherwise).
// Concurrent read-modify-write edits of different actions therefore never
// lose an update: each round has exactly one winner, and edits that retry
// after a refusal all land.
func TestRequiredActionEditRace(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	user := f.Users["bob"]
	actions := []string{"update_password", "verify_email", "configure_totp", "accept_terms", "complete_profile", "verify_contact"}
	path := "/api/v1/realms/main/users/" + user + "/required-actions"
	set := func(list []string, etag string) *Resp {
		rq := Req{Method: "POST", Path: path, Token: f.AdminToken, JSON: map[string]any{"actions": list}}
		if etag != "" {
			rq.Headers = map[string]string{"If-Match": etag}
		}
		return h.Do(rq)
	}
	read := func() ([]string, string) {
		u := f.must(f.AdminAPI("GET", "/users/"+user, nil), 200, "user")
		return raceStrings(u.Get("required_actions")), u.Header.Get("ETag")
	}
	audited := func() int {
		return raceCount(t, h, `SELECT count(*) FROM audit_events WHERE type='user.required_actions.set' AND subject_id=$1`, user)
	}

	{
		// Without If-Match the list check is the only guard: every request
		// either applies (204) or reports the concurrent change (409), the
		// final list is one of the applied lists, and every applied change
		// is audited.
		before := audited()
		res := make([]*Resp, len(actions))
		raceRun(len(actions), func(i int) { res[i] = set([]string{actions[i]}, "") })
		applied := [][]string{}
		for i, r := range res {
			switch r.Status {
			case 204:
				applied = append(applied, []string{actions[i]})
			case 409:
				if r.Str("detail") != "the required actions changed concurrently; retry" {
					t.Fatalf("request %d: %s", i, r.Raw)
				}
			default:
				t.Fatalf("request %d: %d %s", i, r.Status, r.Raw)
			}
		}
		t.Logf("blind replacements: %d applied, %d refused as concurrent", len(applied), len(actions)-len(applied))
		final, _ := read()
		if !slices.ContainsFunc(applied, func(l []string) bool { return slices.Equal(l, final) }) {
			t.Fatalf("final list %v is none of the applied lists %v", final, applied)
		}
		if got := audited() - before; got != len(applied) {
			t.Fatalf("%d audit events for %d applied changes", got, len(applied))
		}
	}

	// A write built from a stale read is refused instead of overwriting the
	// change made after that read; a malformed precondition never matches.
	{
		mustStatus(t, set([]string{"accept_terms", "verify_contact"}, ""), 204, "initial list")
		have, etag := read()
		first := set(raceToggle(have, "update_password"), etag)
		mustStatus(t, first, 204, "edit from a fresh read")
		mustStatus(t, set(raceToggle(have, "verify_email"), etag), 412, "edit from a stale read")
		mustStatus(t, set(raceToggle(have, "verify_email"), `W/"v0"`), 412, "version zero")
		final, now := read()
		if want := raceToggle(have, "update_password"); !slices.Equal(final, want) {
			t.Fatalf("stale edit changed the list: %v, want %v", final, want)
		}
		if now != first.Header.Get("ETag") || now == etag {
			t.Fatalf("ETag after the edit %s, response carried %s, read %s", now, first.Header.Get("ETag"), etag)
		}
	}

	// Read-modify-write edits from the same read, each toggling a different
	// action and naming the read version in If-Match.
	{
		for round := 0; round < 4; round++ {
			have, etag := read()
			res := make([]*Resp, len(actions))
			raceRun(len(actions), func(i int) { res[i] = set(raceToggle(have, actions[i]), etag) })
			winner := -1
			for i, r := range res {
				switch r.Status {
				case 204:
					if winner >= 0 {
						t.Fatalf("round %d: edits %d and %d both applied from the same read; one update is lost", round, winner, i)
					}
					winner = i
				case 409, 412:
				default:
					t.Fatalf("round %d: edit %d: %d %s", round, i, r.Status, r.Raw)
				}
			}
			if winner < 0 {
				t.Fatalf("round %d: no edit applied", round)
			}
			final, after := read()
			if want := raceToggle(have, actions[winner]); !slices.Equal(final, want) {
				t.Fatalf("round %d: list %v, want the winner's %v", round, final, want)
			}
			if after != res[winner].Header.Get("ETag") {
				t.Fatalf("round %d: ETag %s, winner returned %s", round, after, res[winner].Header.Get("ETag"))
			}
		}
	}

	// Edits that re-read and retry after 409 or 412 all land.
	{
		start, _ := read()
		res := make([]int, len(actions))
		raceRun(len(actions), func(i int) {
			for attempt := 0; attempt < 100; attempt++ {
				have, etag := read()
				r := set(raceToggle(have, actions[i]), etag)
				res[i] = r.Status
				if r.Status != 409 && r.Status != 412 {
					return
				}
			}
		})
		want := start
		for i, s := range res {
			if s != 204 {
				t.Fatalf("edit %d of %s ended with %d", i, actions[i], s)
			}
			want = raceToggle(want, actions[i])
		}
		if final, _ := read(); !slices.Equal(final, want) {
			t.Fatalf("an update was lost: %v, want %v", final, want)
		}
	}
}
