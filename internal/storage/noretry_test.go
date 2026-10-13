package storage_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/testutil"
)

// TestTransactionRetries covers DB-014: serialization failures are retried a
// bounded number of times, except for work marked NoRetry, which runs once so
// external calls made inside it are never repeated.
func TestTransactionRetries(t *testing.T) {
	db := testutil.NewDB(t)
	run := func(ctx context.Context) int {
		attempts := 0
		_ = db.Tx(ctx, func(tx pgx.Tx) error {
			attempts++
			return &pgconn.PgError{Code: "40001"}
		})
		return attempts
	}
	if n := run(context.Background()); n != 4 {
		t.Fatalf("retryable failure attempts: %d", n)
	}
	if n := run(storage.NoRetry(context.Background())); n != 1 {
		t.Fatalf("NoRetry work ran %d times", n)
	}
}
