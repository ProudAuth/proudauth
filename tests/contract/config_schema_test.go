package contract

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/configuration"
)

// TestConfigSchemaMatchesStructs keeps api/schemas/config.schema.json in step
// with the deployment configuration (DEP-020): every YAML key the server
// accepts is documented, and the schema documents no key the server rejects.
func TestConfigSchemaMatchesStructs(t *testing.T) {
	raw, err := os.ReadFile("../../api/schemas/config.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]any `json:"properties"`
		Defs       map[string]struct {
			Properties map[string]any `json:"properties"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	seen := map[reflect.Type]bool{}
	var check func(typ reflect.Type, props map[string]any, where string)
	check = func(typ reflect.Type, props map[string]any, where string) {
		if seen[typ] {
			return
		}
		seen[typ] = true
		keys := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			fld := typ.Field(i)
			tag := strings.Split(fld.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			keys[tag] = true
			if _, ok := props[tag]; !ok {
				t.Errorf("%s.%s is accepted by the server but missing from config.schema.json", where, tag)
			}
			ft := fld.Type
			for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct && ft.PkgPath() == typ.PkgPath() {
				if def, ok := schema.Defs[ft.Name()]; ok && def.Properties != nil {
					check(ft, def.Properties, where+"."+tag)
				}
			}
		}
		for k := range props {
			if !keys[k] {
				t.Errorf("%s.%s is documented in config.schema.json but the server rejects it", where, k)
			}
		}
	}
	check(reflect.TypeOf(configuration.Config{}), schema.Properties, "config")
}
