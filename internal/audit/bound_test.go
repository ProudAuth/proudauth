package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// captureQuerier records the arguments of the audit insert instead of
// writing it.
type captureQuerier struct{ args []any }

func (q *captureQuerier) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	q.args = args
	return pgconn.CommandTag{}, nil
}

func (q *captureQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) { panic("not used") }
func (q *captureQuerier) QueryRow(context.Context, string, ...any) pgx.Row        { panic("not used") }

// stored records ev and returns the actor, subject and target IDs the insert
// would store ("" for an absent subject or target).
func stored(t *testing.T, ev Event) (actor, subject, target string) {
	t.Helper()
	q := &captureQuerier{}
	r := &Recorder{Now: func() time.Time { return time.Unix(1700000000, 0) }}
	if _, err := r.Record(context.Background(), q, ev); err != nil {
		t.Fatal(err)
	}
	// $8 actor_id, $11 subject_id, $13 target_id.
	str := func(v any) string {
		if p, ok := v.(*string); ok && p != nil {
			return *p
		}
		if s, ok := v.(string); ok {
			return s
		}
		return ""
	}
	return str(q.args[7]), str(q.args[10]), str(q.args[12])
}

// digest is the suffix BoundID appends: "~" and the first 16 hexadecimal
// digits of the SHA-256 of the whole value.
func digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "~" + hex.EncodeToString(sum[:])[:16]
}

// TestRecordBoundsIdentifiers covers AUD-001 and SEC-006 (the finding
// httpapi-surface/unauth-audit-amplification): an unauthenticated request
// chose the actor ID of client.authentication.failed (the raw client_id or
// Basic user name, up to the 256 KiB body), stored unbounded in an indexed
// column for 400 days; past the index row limit the insert failed and raised
// a false audit_write_failed. Actor, subject and target IDs are now stored as
// at most 128 printable bytes, followed by a digest of the whole value when
// anything was cut or dropped, so the same junk always gives the same stored
// ID; control characters are never stored; identifiers ProudAuth issues are
// stored unchanged.
func TestRecordBoundsIdentifiers(t *testing.T) {
	huge := strings.Repeat("A", 10*1024)
	actor, _, _ := stored(t, Event{Type: "client.authentication.failed", Actor: Ref{Type: "client", ID: huge}, Outcome: Failure})
	if want := strings.Repeat("A", MaxIDBytes) + digest(huge); actor != want {
		t.Fatalf("10 KB actor ID stored as %q (%d bytes), want 128 bytes and the digest", actor[:min(len(actor), 40)], len(actor))
	}
	if again, _, _ := stored(t, Event{Type: "client.authentication.failed", Actor: Ref{Type: "client", ID: huge}}); again != actor {
		t.Fatal("the same actor ID is stored differently")
	}
	other := strings.Repeat("A", 10*1024-1) + "B"
	if o, _, _ := stored(t, Event{Type: "client.authentication.failed", Actor: Ref{Type: "client", ID: other}}); o == actor {
		t.Fatal("two actor IDs with the same first 128 bytes are stored alike")
	}

	// Control characters, format characters and invalid UTF-8 are dropped,
	// and the value is marked as altered.
	for _, id := range []string{"web-bff\nforged: line", "evil\x00client", "a‮b", "bad\xffutf8", "\x1b[31mred", "tab\there"} {
		got, _, _ := stored(t, Event{Type: "client.authentication.failed", Actor: Ref{Type: "client", ID: id}})
		if !strings.HasSuffix(got, digest(id)) || !utf8.ValidString(got) || strings.ContainsFunc(got, func(r rune) bool { return !unicode.IsPrint(r) }) {
			t.Errorf("actor ID %q stored as %q", id, got)
		}
	}

	// Subject and target IDs are bounded the same way; the caller's
	// references are not changed.
	subj, tgt := &Ref{Type: "user", ID: huge + "\n"}, &Ref{Type: "client", ID: "x\r\n" + huge}
	_, s, tg := stored(t, Event{Type: "test.bounded", Actor: Ref{Type: "user", ID: "usr_01J0000000000000000000000"}, Subject: subj, Target: tgt})
	if s != strings.Repeat("A", MaxIDBytes)+digest(huge+"\n") {
		t.Errorf("subject ID stored as %d bytes: %q", len(s), s[:min(len(s), 40)])
	}
	if tg != "x"+strings.Repeat("A", MaxIDBytes-1)+digest("x\r\n"+huge) {
		t.Errorf("target ID stored as %d bytes: %q", len(tg), tg[:min(len(tg), 40)])
	}
	if subj.ID != huge+"\n" || tgt.ID != "x\r\n"+huge {
		t.Error("Record changed the caller's references")
	}

	// Identifiers that are already bounded and printable are unchanged, a
	// multi-byte character is never split, and a 128-byte ID is not cut.
	for _, id := range []string{"usr_01J0000000000000000000000", "web-bff", "startup:host-1", "système", strings.Repeat("z", MaxIDBytes), "a b"} {
		if got, _, _ := stored(t, Event{Type: "test.bounded", Actor: Ref{Type: "client", ID: id}}); got != id {
			t.Errorf("actor ID %q stored as %q", id, got)
		}
	}
	wide := strings.Repeat("é", 100) // 200 bytes
	got := BoundID(wide)
	if prefix := strings.TrimSuffix(got, digest(wide)); prefix != strings.Repeat("é", 64) || !utf8.ValidString(got) {
		t.Errorf("multi-byte ID bounded to %q", got)
	}
	if a, _, _ := stored(t, Event{Type: "test.bounded"}); a != System.ID {
		t.Errorf("empty actor stored as %q", a)
	}
}

// TestQueryFilterUsesBoundIdentifiers covers AUD-011: a search by the
// original actor, subject or target ID finds the record that stored it
// bounded.
func TestQueryFilterUsesBoundIdentifiers(t *testing.T) {
	huge := strings.Repeat("Q", 4096)
	for _, f := range []Filter{{ActorID: huge}, {SubjectID: huge}, {TargetID: huge}} {
		f.RealmID = "rlm_1"
		q := &queryCapture{}
		_, _, _ = Query(context.Background(), q, f)
		if len(q.args) != 3 || q.args[1] != BoundID(huge) {
			got, _ := q.args[1].(string)
			t.Errorf("a %d-byte filter queried with a %d-byte value, want %q", len(huge), len(got), BoundID(huge)[:40]+"...")
		}
	}
}

// queryCapture records the arguments of an audit query and returns no rows.
type queryCapture struct{ args []any }

func (q *queryCapture) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("not used")
}

func (q *queryCapture) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	q.args = args
	return nil, errNoRows
}

func (q *queryCapture) QueryRow(context.Context, string, ...any) pgx.Row { panic("not used") }

var errNoRows = pgx.ErrNoRows
