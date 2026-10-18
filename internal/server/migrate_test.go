package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/storage"
)

// TestWarnOutOfOrder covers OPS-008: identity-server -migrate and
// migrate_on_start log a warning for each migration they applied out of
// order, naming it and the newest migration applied before, and nothing for
// the others.
func TestWarnOutOfOrder(t *testing.T) {
	var buf bytes.Buffer
	warnOutOfOrder(slog.New(slog.NewTextHandler(&buf, nil)), []storage.MigrationPlanItem{
		{Name: "0050_backport.sql", Compat: "expand", OutOfOrder: true, NewestApplied: "0087_restore_marker.sql"},
		{Name: "0090_next.sql", Compat: "expand"},
	})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], "migration=0050_backport.sql") ||
		!strings.Contains(lines[0], "newest_applied=0087_restore_marker.sql") || !strings.Contains(lines[0], "out of order") {
		t.Fatalf("log: %q", buf.String())
	}
}
