package workflow

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/contracts/schemacheck"
)

// TestPublishedExamplesParse keeps the Go validator and the published
// definition schema in step (EXT-018): every example in
// api/workflows/definition.v1.json is accepted by Parse, and the canonical
// form Parse stores validates against the schema again.
func TestPublishedExamplesParse(t *testing.T) {
	set, err := schemacheck.Load(filepath.Join("..", "..", "api", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	doc := set.Doc("definition.v1.json").(map[string]any)
	for i, ex := range doc["examples"].([]any) {
		raw, _ := json.Marshal(ex)
		def, canon, hash, err := Parse(raw)
		if err != nil {
			t.Fatalf("example %d rejected: %v", i, err)
		}
		if len(hash) != 64 || def.SchemaVersion != 1 {
			t.Fatalf("example %d: hash %q", i, hash)
		}
		if err := set.ValidateBytes("definition.v1.json", canon); err != nil {
			t.Fatalf("canonical form of example %d: %v", i, err)
		}
		// Parsing the canonical form is stable (revisions compare by hash).
		if _, _, again, err := Parse(canon); err != nil || again != hash {
			t.Fatalf("example %d is not canonical: %v", i, err)
		}
	}
}

// TestUpgradeFixturesStillParse guards the support window: definitions
// stored under schema version 1 must keep parsing while version 1 is
// supported.
func TestUpgradeFixturesStillParse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "definition.v1.stored.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []json.RawMessage
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	set, err := schemacheck.Load(filepath.Join("..", "..", "api", "workflows"))
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range fixtures {
		if _, _, _, err := Parse(f); err != nil {
			t.Fatalf("stored v1 definition %d no longer parses: %v", i, err)
		}
		if err := set.ValidateBytes("definition.v1.json", f); err != nil {
			t.Fatalf("stored v1 definition %d no longer matches the schema: %v", i, err)
		}
	}
}

// TestParseRejects: definitions are decoded strictly and bounded. Among the
// refusals, a member that could carry logic (an expression) is rejected, so a
// workflow cannot embed code for the server to run (EXT-013; ProudAuth has no
// embedded execution to sandbox, ADR 0021).
func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"empty":           ``,
		"not an object":   `[1]`,
		"future version":  `{"schema_version":2,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"end"}]}`,
		"unknown member":  `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"end"}],"expression":"1"}`,
		"foreign member":  `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"end","duration":"1h"}]}`,
		"no triggers":     `{"schema_version":1,"triggers":[],"steps":[{"id":"x","type":"end"}]}`,
		"two schedules":   `{"schema_version":1,"triggers":[{"type":"schedule","every":"24h","select":{"type":"organization_members","organization_id":"org_00000000000000000000000000"}},{"type":"schedule","every":"24h","select":{"type":"organization_members","organization_id":"org_00000000000000000000000000"}}],"steps":[{"id":"x","type":"end"}]}`,
		"selector org":    `{"schema_version":1,"triggers":[{"type":"schedule","every":"24h","select":{"type":"organization_members"}}],"steps":[{"id":"x","type":"end"}]}`,
		"approval expiry": `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"approval","approvers":["usr_00000000000000000000000000"],"expires_in":"1000h"}]}`,
		"dup approvers":   `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"approval","approvers":["usr_00000000000000000000000000","usr_00000000000000000000000000"],"expires_in":"1h"}]}`,
		"role scope":      `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"assign_role","role_id":"rol_00000000000000000000000000","scope":"project"}]}`,
		"role expiry":     `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"assign_role","role_id":"rol_00000000000000000000000000","scope":"realm","expires_in":"9000h"}]}`,
		"remove access":   `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"remove_access","access":"everything"}]}`,
		"call timeout":    `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"call_webhook","subscription_id":"whk_00000000000000000000000000","timeout_ms":60000}]}`,
		"template":        `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"notify","template":"password_reset","notice":"welcome"}]}`,
		"reason":          `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"x","type":"suspend_user","reason":"because I said so"}]}`,
		"bad id":          `{"schema_version":1,"triggers":[{"type":"manual"}],"steps":[{"id":"X Y","type":"end"}]}`,
	}
	for name, raw := range cases {
		if _, _, _, err := Parse(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCompensationAndPolicy(t *testing.T) {
	d := &Definition{Retry: &RetryPolicy{MaxAttempts: 4, Backoff: "5s"}}
	for typ, want := range map[string]string{StepAssignRole: CompUndo, StepAddToGroup: CompUndo, StepRemove: CompNone, StepSuspend: CompNone,
		StepNotify: CompImpossible, StepCallWebhook: CompImpossible, StepWait: CompNone, StepApproval: CompNone, StepEnd: CompNone} {
		if got := (Step{Type: typ}).Compensation(); got != want {
			t.Errorf("%s: compensation %s, want %s", typ, got, want)
		}
	}
	if (Step{Type: StepCallWebhook, Compensate: true}).Compensation() != CompNotifyEndpoint {
		t.Error("compensating endpoint step")
	}
	if n, b := d.Policy(Step{Type: StepNotify}); n != 4 || b != 5*time.Second {
		t.Errorf("definition retry: %d %v", n, b)
	}
	if n, _ := d.Policy(Step{Type: StepNotify, Retry: &RetryPolicy{MaxAttempts: 2, Backoff: "1s"}}); n != 2 {
		t.Errorf("step retry: %d", n)
	}
	if n, _ := d.Policy(Step{Type: StepApproval}); n != 1 {
		t.Errorf("approvals are not retried: %d", n)
	}
	for attempt := 1; attempt <= 20; attempt++ {
		if b := backoff(time.Second, attempt); b <= 0 || b > 6*time.Hour {
			t.Fatalf("backoff(%d) = %v", attempt, b)
		}
	}
	if b := backoff(10*time.Second, 2); b < 20*time.Second || b > 24*time.Second {
		t.Fatalf("backoff doubles with bounded jitter: %v", b)
	}
}
