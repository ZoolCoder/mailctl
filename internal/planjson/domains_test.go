package planjson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
)

func TestDomainsSchemaMatchesTheGoldenFile(t *testing.T) {
	in := []config.Domain{{
		Name: "example.com",
		Mail: config.Mail{Providers: []string{"purelymail"}},
		Mailboxes: []config.Mailbox{
			{Address: "contact@example.com", PasswordEnv: "CONTACT_PW", Recovery: []config.Recovery{{Type: "email", Target: "owner@example.net"}}},
			{Address: "sales@example.com"},
		},
		Aliases:  []config.Alias{{Match: "info", To: []string{"contact@example.com"}}},
		CatchAll: &config.CatchAll{To: []string{"contact@example.com"}},
		Deliverability: config.Deliverability{
			SPFIncludes: []string{"_spf.example.net"},
			DMARC:       &config.DMARC{Policy: "quarantine", Pct: 100, RUA: "mailto:dmarc@example.com"},
			MTASts:      &config.MTASts{Mode: "testing", MaxAge: 86400},
		},
	}}

	got, err := json.MarshalIndent(FromDomains(in), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/domains.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimRight(string(want), "\n") {
		t.Errorf("schema changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestDomainsNeverCarryACredentialValue(t *testing.T) {
	t.Setenv("CONTACT_PW", "s3cret-value")
	in := []config.Domain{{Name: "example.com", Mailboxes: []config.Mailbox{{Address: "contact@example.com", PasswordEnv: "CONTACT_PW"}}}}
	raw, err := json.Marshal(FromDomains(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "s3cret-value") {
		t.Errorf("domains JSON carries the credential: %s", raw)
	}
	if !strings.Contains(string(raw), `"passwordEnv":"CONTACT_PW"`) {
		t.Errorf("domains JSON lost the variable name: %s", raw)
	}
}
