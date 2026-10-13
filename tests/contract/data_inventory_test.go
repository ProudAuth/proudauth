package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestDataInventoryCoversTables keeps the field-level data inventory complete
// (PRV-001): every table a migration creates is described in
// docs/operations/data-inventory.md, either with its personal-data and secret
// columns or in the list of tables without personal data.
func TestDataInventoryCoversTables(t *testing.T) {
	inventory, err := os.ReadFile("../../docs/operations/data-inventory.md")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v", err)
	}
	create := regexp.MustCompile(`(?i)CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)`)
	seen := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range create.FindAllStringSubmatch(string(src), -1) {
			table := m[1]
			if seen[table] {
				continue
			}
			seen[table] = true
			if !regexp.MustCompile("`" + table + "[`.]").Match(inventory) {
				t.Errorf("%s (created in %s) is missing from docs/operations/data-inventory.md", table, filepath.Base(f))
			}
		}
	}
	if len(seen) < 100 {
		t.Fatalf("found only %d tables; the migration format changed", len(seen))
	}
}
