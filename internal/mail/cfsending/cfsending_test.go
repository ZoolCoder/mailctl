package cfsending

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

type stubZones struct{}

func (stubZones) Zone(_ context.Context, name string) (dns.Zone, error) {
	return dns.Zone{ID: "z1", Name: name}, nil
}
func (stubZones) Records(context.Context, string) ([]dns.Existing, error) { return nil, nil }
func (stubZones) Create(context.Context, string, dns.Record) error        { return nil }
func (stubZones) Delete(context.Context, string, string) error            { return nil }

func serve(t *testing.T, routes map[string]string) (*Client, *[]string) {
	t.Helper()
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		paths = append(paths, r.Method+" "+r.URL.Path)
		body, ok := routes[r.URL.Path]
		if !ok {
			body = `{"success":true,"errors":[],"result":null}`
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return NewClient(cfapi.New(server.URL, "tok")), &paths
}

func sendingDomain() config.Domain {
	return config.Domain{
		Name:     "a.com",
		ZoneName: "a.com",
		Mail:     config.Mail{Providers: []string{"cfsending"}},
	}
}

func TestSubdomainsListsEnabledState(t *testing.T) {
	client, paths := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[
			{"id":"s1","name":"a.com","enabled":true}
		],"result_info":{"page":1,"total_pages":1}}`,
	})

	got, err := client.Subdomains(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Subdomains: %v", err)
	}
	if len(got) != 1 || got[0].ID != "s1" || !got[0].Enabled {
		t.Errorf("subdomains = %+v", got)
	}
	if (*paths)[0] != "GET /zones/z1/email/sending/subdomains" {
		t.Errorf("path = %q", (*paths)[0])
	}
}

func TestRequiredDNSIsSubdomainScoped(t *testing.T) {
	client, paths := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains/s1/dns": `{"success":true,"errors":[],"result":[
			{"type":"TXT","name":"cf2024-1._domainkey.a.com","content":"v=DKIM1; p=abc","ttl":1},
			{"type":"CNAME","name":"_cf-bounce.a.com","content":"bounce.cloudflare.net","ttl":1}
		],"result_info":{"page":1,"total_pages":1}}`,
	})

	records, err := client.RequiredDNS(context.Background(), "z1", "s1")
	if err != nil {
		t.Fatalf("RequiredDNS: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want two", records)
	}
	if (*paths)[0] != "GET /zones/z1/email/sending/subdomains/s1/dns" {
		t.Errorf("path = %q", (*paths)[0])
	}
}

func TestDisableRemovesSubdomain(t *testing.T) {
	client, paths := serve(t, map[string]string{})

	err := client.Disable(context.Background(), "z1", "s1")
	if err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if (*paths)[0] != "DELETE /zones/z1/email/sending/subdomains/s1" {
		t.Errorf("path = %q", (*paths)[0])
	}
}

func TestDesiredDNSMarksDKIMKind(t *testing.T) {
	client, _ := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[
			{"id":"s1","name":"a.com","enabled":true}
		],"result_info":{"page":1,"total_pages":1}}`,
		"/zones/z1/email/sending/subdomains/s1/dns": `{"success":true,"errors":[],"result":[
			{"type":"TXT","name":"cf2024-1._domainkey.a.com","content":"v=DKIM1; p=abc","ttl":1}
		],"result_info":{"page":1,"total_pages":1}}`,
	})
	provider := &Provider{client: client, zones: stubZones{}}

	records, err := provider.DesiredDNS(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 1 || records[0].Kind != dns.KindDKIM {
		t.Errorf("records = %+v, want one DKIM record", records)
	}
}

func TestDesiredDNSIsEmptyBeforeSendingIsEnabled(t *testing.T) {
	client, _ := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`,
	})
	provider := &Provider{client: client, zones: stubZones{}}

	records, err := provider.DesiredDNS(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("records = %+v; Cloudflare cannot name the DKIM selector until sending is enabled, so the first run publishes nothing and the second run publishes the records", records)
	}
}

func TestPlanEnablesSending(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}

	actions, err := provider.Plan(sendingDomain(), mail.State{}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpCreate || actions[0].Resource != "domain" {
		t.Fatalf("actions = %+v, want one enable action", actions)
	}
}

func TestPlanIsEmptyOnceEnabled(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}

	actions, err := provider.Plan(sendingDomain(), mail.State{DomainExists: true},
		mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none", actions)
	}
}

func TestPlanRejectsMailboxesAliasesAndCatchAll(t *testing.T) {
	tests := []struct {
		name string
		make func(config.Domain) config.Domain
	}{
		{
			name: "mailboxes",
			make: func(d config.Domain) config.Domain {
				d.Mailboxes = []config.Mailbox{{Address: "admin@a.com", PasswordEnv: "ADMIN_PW"}}
				return d
			},
		},
		{
			name: "aliases",
			make: func(d config.Domain) config.Domain {
				d.Aliases = []config.Alias{{Match: "info", To: []string{"x@example.com"}}}
				return d
			},
		},
		{
			name: "catch-all",
			make: func(d config.Domain) config.Domain {
				d.CatchAll = &config.CatchAll{To: []string{"all@example.com"}}
				return d
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &Provider{client: nil, zones: stubZones{}}
			d := tt.make(sendingDomain())

			_, err := provider.Plan(d, mail.State{DomainExists: true}, mail.Options{Secrets: secret.NewResolver(nil)})
			if err == nil || !strings.Contains(err.Error(), "cfsending") {
				t.Fatalf("err = %v, want a refusal naming the provider; cfsending is outbound only", err)
			}
		})
	}
}

func TestPlanAllowsAliasesWhenPairedWithCfrouting(t *testing.T) {
	// [cfrouting, cfsending]: the aliases belong to cfrouting, not to
	// cfsending, so cfsending's Plan must not refuse them (C2).
	provider := &Provider{client: nil, zones: stubZones{}}
	d := sendingDomain()
	d.Mail.Providers = []string{"cfrouting", "cfsending"}
	d.Aliases = []config.Alias{{Match: "info", To: []string{"x@example.com"}}}
	d.CatchAll = &config.CatchAll{To: []string{"all@example.com"}}

	actions, err := provider.Plan(d, mail.State{DomainExists: true}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v, want cfsending paired with cfrouting to plan cleanly despite aliases/catch-all", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none once sending is enabled", actions)
	}
}

func TestPlanAllowsMailboxesWhenPairedWithPurelymail(t *testing.T) {
	// [purelymail, cfsending]: the mailboxes belong to purelymail, not to
	// cfsending, so cfsending's Plan must not refuse them (C2).
	provider := &Provider{client: nil, zones: stubZones{}}
	d := sendingDomain()
	d.Mail.Providers = []string{"purelymail", "cfsending"}
	d.Mailboxes = []config.Mailbox{{Address: "admin@a.com", PasswordEnv: "ADMIN_PW"}}

	actions, err := provider.Plan(d, mail.State{DomainExists: true}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v, want cfsending paired with purelymail to plan cleanly despite mailboxes", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none once sending is enabled", actions)
	}
}

func TestPlanActionEnablesViaAPI(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method == "POST" && r.URL.Path == "/zones/z1/email/sending/subdomains" {
			fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"s2","name":"a.com","enabled":true}}`)
		} else {
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
		}
	}))
	t.Cleanup(server.Close)

	client := NewClient(cfapi.New(server.URL, "tok"))
	provider := &Provider{client: client, zones: stubZones{}}

	// Simulate engine calling zone() first
	_, err := provider.zone(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("zone: %v", err)
	}

	// Now call Plan
	actions, err := provider.Plan(sendingDomain(), mail.State{}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %+v, want one", actions)
	}

	// Invoke the action's Do closure
	err = actions[0].Do(context.Background())
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	// Verify the POST was made to the subdomains endpoint
	if len(paths) < 1 {
		t.Fatalf("paths = %+v, want at least 1 request", paths)
	}
	// The POST from Do()
	if paths[0] != "POST /zones/z1/email/sending/subdomains" {
		t.Errorf("path = %q, want POST to subdomains", paths[0])
	}
}

func TestProviderIsRegistered(t *testing.T) {
	for _, name := range mail.Registered() {
		if name == "cfsending" {
			return
		}
	}
	t.Fatal("cfsending should register itself in an init function")
}

var _ = json.Marshal

// Actual reports whether Email Sending is live. The subtlety is that a
// subdomain can exist while still being disabled, and treating "found" as
// "enabled" would report outbound mail as working when Cloudflare has not
// turned it on yet.
func TestActualRequiresTheSubdomainToBeEnabledNotMerelyPresent(t *testing.T) {
	client, _ := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[
			{"id":"s1","name":"a.com","enabled":false}
		],"result_info":{"page":1,"total_pages":1}}`,
	})
	provider := &Provider{client: client, zones: stubZones{}}

	state, err := provider.Actual(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if state.DomainExists {
		t.Error("DomainExists = true for a subdomain that is present but disabled")
	}
	if len(state.Notes) == 0 || !strings.Contains(strings.Join(state.Notes, " "), "not enabled yet") {
		t.Errorf("Notes = %v, want an explanation that Email Sending is not enabled yet", state.Notes)
	}
}

func TestActualReportsEnabledWithoutANote(t *testing.T) {
	client, _ := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[
			{"id":"s1","name":"a.com","enabled":true}
		],"result_info":{"page":1,"total_pages":1}}`,
	})
	provider := &Provider{client: client, zones: stubZones{}}

	state, err := provider.Actual(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if !state.DomainExists {
		t.Error("DomainExists = false although the subdomain is enabled")
	}
	if len(state.Notes) != 0 {
		t.Errorf("Notes = %v, want none once Email Sending is live", state.Notes)
	}
}

func TestActualTreatsAnAbsentSubdomainAsNotEnabled(t *testing.T) {
	client, _ := serve(t, map[string]string{
		"/zones/z1/email/sending/subdomains": `{"success":true,"errors":[],"result":[],
			"result_info":{"page":1,"total_pages":1}}`,
	})
	provider := &Provider{client: client, zones: stubZones{}}

	state, err := provider.Actual(context.Background(), sendingDomain())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if state.DomainExists {
		t.Error("DomainExists = true although no subdomain exists")
	}
	if len(state.Notes) == 0 {
		t.Error("want a note explaining that Email Sending is not enabled yet")
	}
}
