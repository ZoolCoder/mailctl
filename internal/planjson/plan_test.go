package planjson

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/plan"
)

func TestFromPlanProjectsEveryFieldExceptDo(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{
		{
			Op: plan.OpCreate, Resource: "dns", Domain: "example.com",
			Provider: "purelymail", Detail: "MX example.com -> mail.example.net",
			Do: func(context.Context) error { return nil },
		},
		{
			Op: plan.OpManual, Resource: "dkim", Domain: "example.com",
			Detail: "read the CNAME targets from the admin portal",
		},
	}}

	got := FromPlan(in)

	if got.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", got.SchemaVersion)
	}
	if len(got.Actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(got.Actions))
	}
	first := got.Actions[0]
	if first.Op != "CREATE" || first.Resource != "dns" || first.Domain != "example.com" {
		t.Errorf("first action = %+v", first)
	}
	if first.Provider != "purelymail" || first.Detail == "" {
		t.Errorf("first action lost provider or detail: %+v", first)
	}
	if first.Manual {
		t.Error("a CREATE action must not be marked manual")
	}
	if first.ID != "0" {
		t.Errorf("first action ID = %q, want %q", first.ID, "0")
	}
	if !got.Actions[1].Manual {
		t.Error("an OpManual action must be marked manual; it renders but never executes")
	}
	if got.Actions[1].ID != "1" {
		t.Errorf("second action ID = %q, want %q", got.Actions[1].ID, "1")
	}
}

// The JSON is a description of intent. If a capability ever leaks into it, that
// is a security regression, not a formatting one.
func TestPlanJSONCarriesNoExecutableField(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{{
		Op: plan.OpDelete, Resource: "mailbox", Domain: "example.com",
		Detail: "delete contact@example.com",
		Do:     func(context.Context) error { return nil },
	}}}

	raw, err := json.Marshal(FromPlan(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"Do", "\"do\"", "func"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("serialised plan contains %q: %s", forbidden, raw)
		}
	}
}

// Provider is optional on actions like DNS records that have no unique provider.
// An empty provider must not appear in JSON so a consumer can safely assume its
// presence means a provider is required to execute this action.
func TestEmptyProviderSerialisesAsOmitted(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{{
		Op: plan.OpCreate, Resource: "dns", Domain: "example.com",
		Detail: "add MX record",
		// Provider is deliberately empty
	}}}

	raw, err := json.Marshal(FromPlan(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(`"provider"`)) {
		t.Errorf("empty provider serialised in JSON: %s", raw)
	}
}

// An empty plan must serialise as an empty array, not null: a consumer doing
// `for (const a of plan.actions)` would crash on null, and "no changes" is a
// normal, frequent outcome.
func TestEmptyPlanSerialisesAsAnEmptyArray(t *testing.T) {
	raw, err := json.Marshal(FromPlan(plan.Plan{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"actions":[]`)) {
		t.Errorf("empty plan = %s, want an empty actions array", raw)
	}
}

func TestPlanSchemaMatchesTheGoldenFile(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{{
		Op: plan.OpCreate, Resource: "mailbox", Domain: "example.com",
		Provider: "purelymail", Detail: "create contact@example.com",
	}}}

	got, err := json.MarshalIndent(FromPlan(in), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimRight(string(want), "\n") {
		t.Errorf("schema changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
