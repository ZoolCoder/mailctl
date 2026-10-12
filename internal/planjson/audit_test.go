package planjson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/audit"
)

func TestFromReportCarriesTheOverallVerdict(t *testing.T) {
	// OK() is a method, so it does not serialise on its own. The UI colours a
	// domain by it, so it has to be an explicit field.
	failing := audit.Report{Domain: "example.com", Checks: []audit.Check{
		{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true},
		{Name: "SPF", Want: "v=spf1 include:example.net ~all", Got: "", OK: false},
	}}

	got := FromReport(failing)

	if got.OK {
		t.Error("OK = true although one check failed")
	}
	if len(got.Checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(got.Checks))
	}
	if got.Checks[1].Name != "SPF" || got.Checks[1].OK {
		t.Errorf("second check = %+v, want the failing SPF check", got.Checks[1])
	}

	passing := audit.Report{Domain: "example.com", Checks: []audit.Check{
		{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true},
	}}
	if !FromReport(passing).OK {
		t.Error("OK = false although every check passed")
	}
}

func TestReportWithNoChecksOrNotesSerialisesAsEmptyArrays(t *testing.T) {
	raw, err := json.Marshal(FromReport(audit.Report{Domain: "example.com"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"checks":[]`, `"notes":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report = %s, want %s rather than null", raw, want)
		}
	}
}

func TestAuditSchemaMatchesTheGoldenFile(t *testing.T) {
	in := audit.Report{
		Domain: "example.com",
		Checks: []audit.Check{{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true}},
		Notes:  []string{"DKIM targets are taken from config"},
	}

	got, err := json.MarshalIndent(FromReport(in), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/audit.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimRight(string(want), "\n") {
		t.Errorf("schema changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
