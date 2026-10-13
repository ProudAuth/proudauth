package storage

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestAfterCommit: hooks run once after a commit, never for a rolled back or
// retried attempt, and at once outside a transaction.
func TestAfterCommit(t *testing.T) {
	url := os.Getenv("PROUDAUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PROUDAUTH_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := Open(ctx, url, Options{MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ran := 0
	attempts := 0
	if err := db.Tx(ctx, func(tx pgx.Tx) error {
		attempts++
		AfterCommit(tx, func() { ran++ })
		if attempts == 1 {
			// A serialization failure: the attempt is retried.
			_, err := tx.Exec(ctx, `DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '40001'; END $$`)
			return err
		}
		if ran != 0 {
			t.Error("hook ran before commit")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || ran != 1 {
		t.Fatalf("attempts=%d hooks=%d", attempts, ran)
	}
	boom := errors.New("boom")
	if err := db.Tx(ctx, func(tx pgx.Tx) error {
		AfterCommit(tx, func() { ran++ })
		return boom
	}); !errors.Is(err, boom) || ran != 1 {
		t.Fatalf("rolled back hook ran: %v %d", err, ran)
	}
	AfterCommit(db.Pool, func() { ran++ })
	if ran != 2 {
		t.Fatal("hook outside a transaction did not run")
	}
}
