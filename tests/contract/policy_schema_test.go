package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/realm"
)

// TestConfigDocumentPolicyMembers keeps the configuration-document schema's
// realm policy in step with realm.Policy: an exported document always
// validates against the published schema (SDK-012, MIG-014).
func TestConfigDocumentPolicyMembers(t *testing.T) {
	raw, err := os.ReadFile("../../api/schemas/config-document.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	props := doc.Defs["Policy"].Properties
	typ := reflect.TypeOf(realm.Policy{})
	for i := 0; i < typ.NumField(); i++ {
		name, _, _ := strings.Cut(typ.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		if _, ok := props[name]; !ok {
			t.Errorf("realm.Policy member %q is missing from $defs.Policy in config-document.schema.json", name)
		}
	}
}
