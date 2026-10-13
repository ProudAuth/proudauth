package authorization

import (
	"encoding/json"
	"os"
	"testing"
)

// The server applies the same protected/write classification as the SDK
// SupportGuard: both read the shared table (IMP-012, IMP-013).
func TestSupportClassificationMatchesSDKTable(t *testing.T) {
	raw, err := os.ReadFile("../../tests/fixtures/sdk-contracts/support-operations/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		ClassificationOnly []struct {
			Operation string `json:"operation"`
			Protected bool   `json:"protected"`
			Write     bool   `json:"write"`
		} `json:"classification_only"`
		Cases []struct {
			Operation string `json:"operation"`
			Protected bool   `json:"protected"`
			Write     bool   `json:"write"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	n := 0
	check := func(op string, protected, write bool) {
		n++
		if got := IsSupportForbidden(op); got != protected {
			t.Errorf("IsSupportForbidden(%q) = %v, want %v", op, got, protected)
		}
		if got := IsWriteAction(op); got != write {
			t.Errorf("IsWriteAction(%q) = %v, want %v", op, got, write)
		}
	}
	for _, c := range table.ClassificationOnly {
		check(c.Operation, c.Protected, c.Write)
	}
	for _, c := range table.Cases {
		check(c.Operation, c.Protected, c.Write)
	}
	if n < 20 {
		t.Fatalf("only %d cases read from the shared table", n)
	}
}
