package resend

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// serve answers "METHOD /path" with canned JSON and records each call.
func serve(t *testing.T, responses map[string]string) (*Provider, *[]string) {
	t.Helper()
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer key" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		calls = append(calls, strings.TrimSpace(key+" "+string(body)))
		response, ok := responses[key]
		if !ok {
			response = `{}`
		}
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	return &Provider{client: NewClient(server.URL, "key")}, &calls
}

const listed = `{"data":[{"id":"d1","name":"a.com","status":"pending"}]}`

const detail = `{"id":"d1","name":"a.com","status":"pending","records":[
 {"record":"DKIM","name":"resend._domainkey","type":"TXT","value":"p=KEY","ttl":"Auto","status":"not_started"},
 {"record":"SPF","name":"send","type":"MX","value":"feedback-smtp.us-east-1.amazonses.com","priority":10,"ttl":"Auto"},
 {"record":"SPF","name":"send.a.com","type":"TXT","value":"v=spf1 include:amazonses.com ~all","ttl":"Auto"}]}`

func domain(providers ...string) config.Domain {
	return config.Domain{Name: "a.com", Mail: config.Mail{Providers: providers}}
}

func TestDesiredDNSQualifiesNamesAndSetsKinds(t *testing.T) {
	provider, _ := serve(t, map[string]string{"GET /domains": listed, "GET /domains/d1": detail})

	records, err := provider.DesiredDNS(context.Background(), domain("purelymail", "resend"))
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	want := []dns.Record{
		{Type: "TXT", Name: "resend._domainkey.a.com", Content: "p=KEY", Kind: dns.KindDKIM},
		{Type: "MX", Name: "send.a.com", Content: "feedback-smtp.us-east-1.amazonses.com", Priority: 10, Kind: dns.KindOther},
		{Type: "TXT", Name: "send.a.com", Content: "v=spf1 include:amazonses.com ~all", Kind: dns.KindSPF},
	}
	if len(records) != len(want) {
		t.Fatalf("got %d records, want %d: %+v", len(records), len(want), records)
	}
	for i := range want {
		if records[i].Type != want[i].Type || records[i].Name != want[i].Name || records[i].Content != want[i].Content ||
			records[i].Priority != want[i].Priority || records[i].Kind != want[i].Kind {
			t.Errorf("record %d = %+v, want %+v", i, records[i], want[i])
		}
	}
}

func TestDesiredDNSIsEmptyBeforeTheDomainExists(t *testing.T) {
	provider, _ := serve(t, map[string]string{"GET /domains": `{"data":[]}`})
	records, err := provider.DesiredDNS(context.Background(), domain("resend"))
	if err != nil || len(records) != 0 {
		t.Fatalf("DesiredDNS = %v, %v; want nothing", records, err)
	}
}

func TestPlanAddsAMissingDomainInItsRegion(t *testing.T) {
	provider, calls := serve(t, map[string]string{"GET /domains": `{"data":[]}`})
	d := domain("resend")
	d.Mail.Resend = &config.Resend{Region: "eu-west-1"}

	actual, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpCreate || actions[0].Resource != "domain" {
		t.Fatalf("actions = %+v, want one domain create", actions)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	last := (*calls)[len(*calls)-1]
	if !strings.HasPrefix(last, "POST /domains") || !strings.Contains(last, `"region":"eu-west-1"`) {
		t.Errorf("last call = %q, want a create in eu-west-1", last)
	}
}

func TestPlanVerifiesAPendingDomainAndStopsOnceVerified(t *testing.T) {
	provider, calls := serve(t, map[string]string{"GET /domains": listed, "GET /domains/d1": detail})
	d := domain("resend")

	actual, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, mail.Options{})
	if err != nil || len(actions) != 1 || actions[0].Op != plan.OpUpdate {
		t.Fatalf("Plan = %+v, %v; want one verify", actions, err)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if last := (*calls)[len(*calls)-1]; last != "POST /domains/d1/verify" {
		t.Errorf("last call = %q", last)
	}

	actual.Verified = true
	if actions, _ := provider.Plan(d, actual, mail.Options{}); len(actions) != 0 {
		t.Errorf("verified domain planned %+v", actions)
	}
}

func TestPlanRefusesMailboxesWhenResendIsAlone(t *testing.T) {
	provider, _ := serve(t, nil)
	d := domain("resend")
	d.Aliases = []config.Alias{{Match: "info", To: []string{"x@b.com"}}}
	if _, err := provider.Plan(d, mail.State{}, mail.Options{}); err == nil {
		t.Fatal("Plan accepted an alias on a resend-only domain")
	}
}

func TestQualify(t *testing.T) {
	for in, want := range map[string]string{
		"@": "a.com", "": "a.com", "a.com.": "a.com", "send": "send.a.com", "Send.A.com": "send.a.com",
	} {
		if got := qualify(in, "a.com"); got != want {
			t.Errorf("qualify(%q) = %q, want %q", in, got, want)
		}
	}
}
