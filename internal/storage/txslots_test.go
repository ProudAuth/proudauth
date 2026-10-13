package storage

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestTxSlots(t *testing.T) {
	for _, c := range []struct {
		conns int32
		want  int
	}{{0, 1}, {1, 1}, {2, 1}, {3, 2}, {4, 3}, {8, 6}, {20, 15}, {100, 75}} {
		if got := TxSlots(c.conns); got != c.want {
			t.Errorf("TxSlots(%d) = %d, want %d", c.conns, got, c.want)
		}
	}
}

// TestTransactionsLeaveConnectionsForSideStatements: transactions whose
// code also runs a statement outside the transaction (on another pool
// connection, as lookups, rate-limit counters and signing keys do) complete
// when more of them run at once than the pool has connections. Without the
// bound on open transactions, every connection was held by a transaction
// waiting for another connection, and they stalled until their deadline
// (found with identity-bench: token issuance, refresh and sign-in stopped at
// 20 concurrent requests with the default storage.max_conns of 20).
func TestTransactionsLeaveConnectionsForSideStatements(t *testing.T) {
	url := os.Getenv("PROUDAUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PROUDAUTH_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	db, err := Open(ctx, url, Options{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const n = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- db.Tx(ctx, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SELECT pg_sleep(0.05)`); err != nil {
					return err
				}
				// A statement outside the transaction, on another connection.
				var one int
				return db.Pool.QueryRow(ctx, `SELECT 1`).Scan(&one)
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("transaction with a side statement: %v (all connections held by waiting transactions?)", err)
		}
	}
}
