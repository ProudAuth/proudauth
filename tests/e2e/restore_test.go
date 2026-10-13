package e2e

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/restore"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/testutil"
)

// TestRestoreReconciliation covers OPS-014: after a backup is restored, the
// independently exported revocation log is re-applied, so revoked sessions,
// a deleted account, a suspension, a removed membership with its roles and a
// superseded password do not come back, and a full invalidation revokes every
// session.
// Requirements: PRV-006 (post-backup deletions and revocations are re-applied
// after a restore).
func TestRestoreReconciliation(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	_ = lr
	dave := f.CreateUser("dave")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": dave}), 201, "dave member")

	// Take a physical backup (template copy) of the database.
	var dbName string
	if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	adminURL := testutil.DatabaseURL(t)
	backupName := dbName + "_bak"
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	var cerr error
	for i := 0; i < 20; i++ {
		f.H.App.D.DB.Pool.Reset()
		if _, cerr = admin.Exec(ctx, "CREATE DATABASE "+backupName+" TEMPLATE "+dbName); cerr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if cerr != nil {
		t.Skipf("could not snapshot database: %v", cerr)
	}
	defer admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+backupName+" WITH (FORCE)")
	since := f.H.Clock.Now().Add(-time.Second)

	// Security-relevant changes after the backup.
	bobAcct := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, f.H.API("POST", "/me/sessions/revoke-all", bobAcct, nil), 200, "bob logs out everywhere")
	f.must(f.AdminAPI("DELETE", "/users/"+dave, nil), 204, "delete dave")
	f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "compromise"}), 200, "suspend carol")
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"], nil), 204, "remove bob from globex")
	aliceAcct := f.AccountToken("alice").Tokens.Str("access_token")
	newPw := "Correct-Horse-Battery-77"
	mustStatus(t, f.H.API("POST", "/me/password", aliceAcct, map[string]any{"current_password": f.H.passwords["alice@example.test"], "new_password": newPw}), 200, "alice changes password")
	var log bytes.Buffer
	if _, err := restore.Export(ctx, f.H.App.D.DB, since, &log); err != nil {
		t.Fatal(err)
	}

	// "Restore" the backup and show what would be resurrected without reconciliation.
	bak, err := storage.Open(ctx, testutil.DSNFor(adminURL, backupName), storage.Options{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer bak.Close()
	count := func(sql string, args ...any) int {
		var n int
		if err := bak.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, f.Users["bob"]) == 0 {
		t.Fatal("precondition: backup should contain bob's old sessions")
	}
	if count(`SELECT count(*) FROM user_identifiers WHERE user_id=$1`, dave) == 0 {
		t.Fatal("precondition: backup should contain dave")
	}
	rep, err := restore.Reconcile(ctx, bak, &log, restore.Options{}, time.Now().UTC(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Applied["revocation"] == 0 || rep.Applied["tombstone"] == 0 {
		t.Fatalf("nothing reconciled: %+v", rep)
	}
	if n := count(`SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, f.Users["bob"]); n != 0 {
		t.Fatalf("revoked sessions resurrected after restore: %d", n)
	}
	if n := count(`SELECT count(*) FROM user_identifiers WHERE user_id=$1`, dave); n != 0 {
		t.Fatal("deleted account resurrected after restore")
	}
	if n := count(`SELECT count(*) FROM memberships WHERE user_id=$1 AND state='active'`, dave); n != 0 {
		t.Fatal("deleted account kept memberships")
	}
	if n := count(`SELECT count(*) FROM users WHERE id=$1 AND state='suspended'`, f.Users["carol"]); n != 1 {
		t.Fatal("suspension not re-applied")
	}
	if n := count(`SELECT count(*) FROM memberships WHERE id=$1 AND state='active'`, f.MemberGlobex["bob"]); n != 0 {
		t.Fatal("removed membership resurrected")
	}
	if n := count(`SELECT count(*) FROM role_assignments WHERE membership_id=$1`, f.MemberGlobex["bob"]); n != 0 {
		t.Fatal("removed membership kept its roles")
	}
	// Alice's pre-change password from the backup must not work again.
	if n := count(`SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, f.Users["alice"]); n != 0 {
		t.Fatal("superseded password usable after restore")
	}
	if n := count(`SELECT count(*) FROM users WHERE id=$1 AND 'update_password' = ANY(required_actions)`, f.Users["alice"]); n != 1 {
		t.Fatal("password reset not required after restore")
	}
	// Idempotent: running it twice changes nothing further.
	if _, err := restore.Reconcile(ctx, bak, bytes.NewReader(log.Bytes()), restore.Options{InvalidateAllSessions: true}, time.Now().UTC(), nil); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM sessions WHERE state='active'`); n != 0 {
		t.Fatal("full invalidation left active sessions")
	}
}
