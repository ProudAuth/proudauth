package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/configuration"
)

// TestAuditCategoriesKnown keeps privacy.audit_retention_by_category honest:
// every category literal recorded by the code must be a configurable
// category, so retention can name it.
func TestAuditCategoriesKnown(t *testing.T) {
	re := regexp.MustCompile(`Category: *"([a-z_]+)"`)
	err := filepath.Walk("../../internal", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			if !slices.Contains(configuration.AuditCategories, m[1]) {
				t.Errorf("%s records audit category %q, which is missing from configuration.AuditCategories", path, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
