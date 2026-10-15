package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

type unavailableGrantQuery struct{ storage.Querier }

func (unavailableGrantQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	return unavailableGrantRow{}
}

type unavailableGrantRow struct{}

func (unavailableGrantRow) Scan(...any) error { return errors.New("grant store unavailable") }

// TestAccessGrantFailsClosed covers SES-023: a valid token cannot retain online
// authority when its grant cannot be read. A missing link must also fail without
// consulting a store or trying to fall back to session-only authorization.
func TestAccessGrantFailsClosed(t *testing.T) {
	s := &Service{d: &runtime.Deps{Clock: clock.NewFake(time.Now())}}
	if s.AccessGrantActive(context.Background(), unavailableGrantQuery{}, "rlm_1", "agr_1", "usr_1", "cli_1") {
		t.Fatal("grant-store failure preserved online authority")
	}
	if s.AccessGrantActive(context.Background(), nil, "rlm_1", "", "usr_1", "cli_1") {
		t.Fatal("missing grant link preserved online authority")
	}
}
