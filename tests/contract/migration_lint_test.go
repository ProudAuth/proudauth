package contract

import (
	"io/fs"
	"os"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/migrations"
)

// lintBaselineLast is the newest migration the lint baseline may name: the
// last one that shipped before the lint existed. Later migrations avoid
// their findings or carry the marker that allows them.
const lintBaselineLast = "0087_restore_marker.sql"

func readLintBaseline(t *testing.T) []storage.LintBaselineEntry {
	t.Helper()
	b, err := os.ReadFile("../../migrations/lint-baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := storage.ParseLintBaseline(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return baseline
}

// TestMigrationLint covers OPS-008, DEP-012 and TEST-061: the embedded
// migrations pass the migration lint (internal/storage/migrationlint.go),
// so no migration blocks a hot table's queries with a plain index build, a
// table rewrite or a volatile default, and no migration drops, renames or
// narrows schema older binaries use without compat=contract or a
// reviewed-expand reason. Findings of migrations that shipped before the
// lint are explained by migrations/lint-baseline.txt, which is exact and
// history only. The subtests show the check failing: a new file with a
// plain CREATE INDEX on an existing table, a baseline without one of its
// entries, and a baseline entry that names no finding.
func TestMigrationLint(t *testing.T) {
	baseline := readLintBaseline(t)
	unexplained, stale, err := storage.LintMigrations(migrations.Files, baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range unexplained {
		t.Errorf("%s\n(fix the migration or add the marker that allows it, see CONTRIBUTING.md; migrations/lint-baseline.txt is for migrations up to %s only)", f, lintBaselineLast)
	}
	for _, e := range stale {
		t.Errorf("%s names no finding: remove it", e)
	}
	for _, e := range baseline {
		if e.File > lintBaselineLast {
			t.Errorf("%s: the baseline is history only; %s must avoid the finding or carry the marker that allows it", e, e.File)
		}
	}
	files, err := fs.Glob(migrations.Files, "*.sql")
	if err != nil || len(files) < 72 || !slices.Contains(files, lintBaselineLast) {
		t.Fatalf("embedded migrations: %d files, %v", len(files), err)
	}

	t.Run("new blocking index", func(t *testing.T) {
		src := fstest.MapFS{}
		for _, name := range files {
			b, err := fs.ReadFile(migrations.Files, name)
			if err != nil {
				t.Fatal(err)
			}
			src[name] = &fstest.MapFile{Data: b}
		}
		src["0088_seeded_index.sql"] = &fstest.MapFile{Data: []byte("-- Seeded by TestMigrationLint.\nCREATE INDEX IF NOT EXISTS sessions_seeded ON sessions (user_id);\n")}
		unexplained, stale, err := storage.LintMigrations(src, baseline)
		if err != nil || len(stale) != 0 || len(unexplained) != 1 ||
			unexplained[0].File != "0088_seeded_index.sql" || unexplained[0].Rule != "blocking-index" || unexplained[0].Subject != "sessions_seeded" {
			t.Fatalf("seeded file: unexplained %v, stale %v, %v", unexplained, stale, err)
		}
	})
	t.Run("every baseline entry is needed", func(t *testing.T) {
		for i, e := range baseline {
			without := slices.Delete(slices.Clone(baseline), i, i+1)
			unexplained, stale, err := storage.LintMigrations(migrations.Files, without)
			if err != nil || len(stale) != 0 || len(unexplained) != 1 ||
				unexplained[0].File != e.File || unexplained[0].Rule != e.Rule || unexplained[0].Subject != e.Subject {
				t.Fatalf("without %s: unexplained %v, stale %v, %v", e, unexplained, stale, err)
			}
		}
	})
	t.Run("an entry without a finding", func(t *testing.T) {
		extra := storage.LintBaselineEntry{File: "0045_cleanup_indexes.sql", Rule: "drop-table", Subject: "sessions", Reason: "never happened", Line: 999}
		unexplained, stale, err := storage.LintMigrations(migrations.Files, append(slices.Clone(baseline), extra))
		if err != nil || len(unexplained) != 0 || len(stale) != 1 || stale[0] != extra {
			t.Fatalf("unexplained %v, stale %v, %v", unexplained, stale, err)
		}
	})
}
