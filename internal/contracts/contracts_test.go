package contracts_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/contracts"
	"github.com/proudbase/proudauth/internal/contracts/schemacheck"
	"github.com/proudbase/proudauth/internal/webhooks"
)

const apiDir = "../../api"

func loadEvents(t *testing.T) *schemacheck.Set {
	t.Helper()
	set, err := schemacheck.Load(filepath.Join(apiDir, "events"))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func examples(t *testing.T, set *schemacheck.Set, file string) []map[string]any {
	t.Helper()
	doc, _ := set.Doc(file).(map[string]any)
	var out []map[string]any
	for _, ex := range doc["examples"].([]any) {
		out = append(out, ex.(map[string]any))
	}
	return out
}

// TestEventVersionsRegistered: every webhook event version the server serves
// has an envelope schema and a schema per subscribable event type (EXT-018).
func TestEventVersionsRegistered(t *testing.T) {
	set := loadEvents(t)
	for _, v := range contracts.Supported(contracts.WebhookEvents) {
		suffix := ".v" + itoa(v) + ".json"
		if !set.Has("envelope" + suffix) {
			t.Errorf("event version %d has no envelope schema", v)
		}
		for _, typ := range webhooks.EventTypes {
			if !set.Has(typ + suffix) {
				t.Errorf("event %s has no schema for version %d", typ, v)
			}
		}
	}
	if d := contracts.Default(contracts.WebhookEvents); d != 1 {
		t.Fatalf("the default event version must stay 1 while v1 is supported, got %d", d)
	}
}

// TestPublishedExamplesValidate checks every embedded example against its own
// schema and the envelope of its version, so the validator and the schemas
// agree before they judge server output.
func TestPublishedExamplesValidate(t *testing.T) {
	set := loadEvents(t)
	n := 0
	for _, f := range set.Files() {
		for _, ex := range examples(t, set, f) {
			if err := set.Validate(f, ex); err != nil {
				t.Errorf("example does not validate: %v", err)
			}
			n++
		}
	}
	if n < 60 {
		t.Fatalf("only %d examples checked", n)
	}
}

// TestRenderEveryVersion renders every v1 example (as stored in the outbox) in
// every supported version and payload form and validates the result against
// that version's schema (EXT-008, EXT-018). v1 rendering must be
// byte-identical, so a server upgrade never changes what an existing
// subscription receives.
func TestRenderEveryVersion(t *testing.T) {
	set := loadEvents(t)
	for _, typ := range webhooks.EventTypes {
		for _, ex := range examples(t, set, typ+".v1.json") {
			raw, _ := json.Marshal(ex)
			for _, v := range contracts.Supported(contracts.WebhookEvents) {
				for _, form := range []string{"minimal", "standard"} {
					out, err := contracts.RenderEvent(raw, v, form)
					if err != nil {
						t.Fatalf("%s v%d: %v", typ, v, err)
					}
					if v == 1 && string(out) != string(raw) {
						t.Fatalf("%s: v1 rendering changed the payload", typ)
					}
					file := typ + ".v" + itoa(v) + ".json"
					if err := set.ValidateBytes(file, out); err != nil {
						t.Errorf("rendered %s %s: %v", form, file, err)
					}
					var m map[string]any
					_ = json.Unmarshal(out, &m)
					if v == 2 && (m["org_id"] != nil || m["payload_form"] != form) {
						t.Errorf("%s v2 envelope: %s", typ, out)
					}
				}
			}
		}
	}
	if _, err := contracts.RenderEvent([]byte(`{}`), 99, "minimal"); err == nil {
		t.Fatal("an unsupported version rendered")
	}
}

// TestValidatorRejects keeps the validator honest: payloads a consumer would
// choke on must fail.
func TestValidatorRejects(t *testing.T) {
	set := loadEvents(t)
	ex := examples(t, set, "organization.membership.removed.v1.json")[0]
	bad := func(mut func(m map[string]any)) map[string]any {
		b, _ := json.Marshal(ex)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		mut(m)
		return m
	}
	cases := map[string]map[string]any{
		"missing data member":   bad(func(m map[string]any) { delete(m["data"].(map[string]any), "membership_id") }),
		"unknown data member":   bad(func(m map[string]any) { m["data"].(map[string]any)["email"] = "x@example.com" }),
		"wrong version":         bad(func(m map[string]any) { m["event_version"] = 2 }),
		"v2 member in v1":       bad(func(m map[string]any) { m["payload_form"] = "minimal" }),
		"malformed identifier":  bad(func(m map[string]any) { m["data"].(map[string]any)["user_id"] = "alice" }),
		"missing organization":  bad(func(m map[string]any) { delete(m, "org_id") }),
		"wrong envelope member": bad(func(m map[string]any) { m["organization_id"] = m["org_id"]; delete(m, "org_id") }),
	}
	for name, doc := range cases {
		if err := set.Validate("organization.membership.removed.v1.json", doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestContractRegistry: defaults are supported versions, names are unique and
// every contract with more than one version names the default explicitly.
func TestContractRegistry(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range contracts.Registry {
		if seen[c.Name] {
			t.Fatalf("duplicate contract %s", c.Name)
		}
		seen[c.Name] = true
		if !contracts.IsSupported(c.Name, contracts.Default(c.Name)) || !contracts.IsSupported(c.Name, contracts.Current(c.Name)) {
			t.Fatalf("%s: default or current version is not supported", c.Name)
		}
		if c.Versions[len(c.Versions)-1].Status != "current" {
			t.Fatalf("%s: the newest version must be current", c.Name)
		}
	}
	if got := contracts.SupportedList(contracts.WebhookEvents); got != "1 or 2" {
		t.Fatalf("SupportedList = %q", got)
	}
}

// TestSchemaFilesDeclareDraft: new schema directories follow the api/events
// conventions ($schema, $id under auth.proudbase.com, examples that validate).
func TestSchemaFilesDeclareDraft(t *testing.T) {
	for _, dir := range []string{"hooks", "plugins", "workflows"} {
		set, err := schemacheck.Load(filepath.Join(apiDir, dir))
		if err != nil {
			t.Fatal(err)
		}
		if len(set.Files()) == 0 {
			t.Fatalf("api/%s has no schemas", dir)
		}
		for _, f := range set.Files() {
			doc := set.Doc(f).(map[string]any)
			if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
				t.Errorf("%s: $schema", f)
			}
			if id, _ := doc["$id"].(string); !strings.HasPrefix(id, "https://auth.proudbase.com/schemas/"+dir+"/") || !strings.HasSuffix(id, "/"+f) {
				t.Errorf("%s: $id %q", f, id)
			}
			exs, _ := doc["examples"].([]any)
			if len(exs) == 0 && !strings.HasPrefix(f, "common.") {
				t.Errorf("%s: no examples", f)
			}
			for _, ex := range exs {
				if err := set.Validate(f, ex); err != nil {
					t.Errorf("%s example: %v", f, err)
				}
			}
		}
	}
	if _, err := os.Stat(filepath.Join(apiDir, "hooks", "README.md")); err != nil {
		t.Error("api/hooks/README.md is missing")
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
