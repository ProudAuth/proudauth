package main

import (
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/storage"
)

// TestMigratePlanLine covers OPS-008: migrate -plan marks a pending
// migration that sorts before the newest applied one as out of order and
// names that migration, and migrate warns when it applies one; other
// migrations are listed with their class only.
func TestMigratePlanLine(t *testing.T) {
	backport := storage.MigrationPlanItem{Name: "0050_backport.sql", Compat: "expand", NoTransaction: true,
		OutOfOrder: true, NewestApplied: "0087_restore_marker.sql"}
	if got := planLine(backport); !strings.HasPrefix(got, "0050_backport.sql ") ||
		!strings.HasSuffix(got, " expand, no-transaction, out-of-order (sorts before 0087_restore_marker.sql, already applied)") {
		t.Fatalf("plan line %q", got)
	}
	if got := planLine(storage.MigrationPlanItem{Name: "0090_next.sql", Compat: "contract"}); !strings.HasSuffix(got, " contract") || strings.Contains(got, "order") {
		t.Fatalf("plan line %q", got)
	}
	w := outOfOrderWarning(backport)
	for _, want := range []string{"warning: migration 0050_backport.sql was applied out of order", "sorts before 0087_restore_marker.sql", "-- proudauth:allow-out-of-order: <reason>"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning %q does not say %q", w, want)
		}
	}
}
