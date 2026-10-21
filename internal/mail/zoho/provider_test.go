package zoho

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
	"github.com/zoolcoder/mailctl/internal/secret"
)

// serve fakes both the accounts host and the Mail API. Responses are keyed
// "METHOD /path" with the query dropped; each API call is recorded with its
// body.
func serve(t *testing.T, responses map[string]string) (*Provider, *[]string, *int) {
	t.Helper()
	var calls []string
	tokens := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/v2/token" {
			tokens++
			if r.URL.Query().Get("refresh_token") != "refresh" {
				t.Errorf("token query = %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Zoho-oauthtoken tok" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		calls = append(calls, strings.TrimSpace(key+" "+string(body)))
		response, ok := responses[key]
		if !ok {
			response = `{"status":{"code":200,"description":"success"},"data":{}}`
		}
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	provider := &Provider{
		deps:  mail.Deps{ZohoBaseURL: server.URL, ZohoAccountsURL: server.URL},
		creds: Credentials{ClientID: "id", ClientSecret: "secret", RefreshToken: "refresh", OrgID: "9"},
	}
	return provider, &calls, &tokens
}

func ok(data string) string {
	return `{"status":{"code":200,"description":"success"},"data":` + data + `}`
}

const (
	domainsPath  = "GET /api/organization/9/domains"
	domainPath   = "GET /api/organization/9/domains/a.com"
	accountsPath = "GET /api/organization/9/accounts"
)

func listed() string { return ok(`{"domainVO":[{"domainName":"a.com"}]}`) }

func verifiedDomain() string {
	return ok(`{"domainName":"a.com","verificationStatus":true,"CNAMEVerificationCode":"zb123",
		"mailHostingEnabled":true,"mxstatus":"true","spfstatus":false,
		"dkimDetailList":[{"dkimId":77,"selector":"zmail","publicKey":"v=DKIM1; k=rsa; p=KEY","isVerified":true}]}`)
}

func domainConfig() config.Domain {
	return config.Domain{
		Name:      "a.com",
		Mail:      config.Mail{Providers: []string{"zoho"}},
		Mailboxes: []config.Mailbox{{Address: "me@a.com", DisplayName: "Me"}},
		Aliases:   []config.Alias{{Match: "info", To: []string{"me@a.com"}}},
		CatchAll:  &config.CatchAll{To: []string{"me@a.com"}},
	}
}

func TestDesiredDNSPublishesOnlyOwnershipUntilVerified(t *testing.T) {
	provider, _, _ := serve(t, map[string]string{
		domainsPath: listed(),
		domainPath:  ok(`{"domainName":"a.com","verificationStatus":false,"CNAMEVerificationCode":"zb123"}`),
	})
	records, err := provider.DesiredDNS(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 1 || records[0].Kind != dns.KindOwnership ||
		records[0].Content != "zoho-verification=zb123.zmverify.zoho.com" {
		t.Fatalf("records = %+v, want only the ownership TXT", records)
	}
}

func TestDesiredDNSPublishesRegionHostsOnceVerified(t *testing.T) {
	provider, _, _ := serve(t, map[string]string{domainsPath: listed(), domainPath: verifiedDomain()})
	d := domainConfig()
	d.Mail.Zoho = &config.Zoho{Region: "eu"}

	records, err := provider.DesiredDNS(context.Background(), d)
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	got := map[string]bool{}
	for _, r := range records {
		got[fmt.Sprintf("%s %s %s %d", r.Type, r.Name, r.Content, r.Priority)] = true
	}
	for _, want := range []string{
		"TXT a.com zoho-verification=zb123.zmverify.zoho.eu 0",
		"MX a.com mx.zoho.eu 10",
		"MX a.com mx2.zoho.eu 20",
		"MX a.com mx3.zoho.eu 50",
		"TXT a.com v=spf1 include:zoho.eu ~all 0",
		"TXT zmail._domainkey.a.com v=DKIM1; k=rsa; p=KEY 0",
	} {
		if !got[want] {
			t.Errorf("missing record %q in %v", want, got)
		}
	}
}

func TestPlanAddsAMissingDomainOnly(t *testing.T) {
	provider, calls, _ := serve(t, map[string]string{domainsPath: ok(`{"domainVO":[]}`)})
	d := domainConfig()
	actual, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil || len(actions) != 1 || actions[0].Op != plan.OpCreate || actions[0].Resource != "domain" {
		t.Fatalf("Plan = %+v, %v; want one domain create", actions, err)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if last := (*calls)[len(*calls)-1]; last != `POST /api/organization/9/domains {"domainName":"a.com"}` {
		t.Errorf("last call = %q", last)
	}
}

func TestPlanVerifyReportsZohoRefusal(t *testing.T) {
	provider, calls, _ := serve(t, map[string]string{
		domainsPath: listed(),
		domainPath:  ok(`{"domainName":"a.com","verificationStatus":false,"CNAMEVerificationCode":"zb123"}`),
		"PUT /api/organization/9/domains/a.com": ok(`{"status":false,"error":"TXT not found"}`),
	})
	d := domainConfig()
	actual, _ := provider.Actual(context.Background(), d)
	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil || len(actions) != 1 || actions[0].Op != plan.OpUpdate {
		t.Fatalf("Plan = %+v, %v; want one verify", actions, err)
	}
	err = actions[0].Do(context.Background())
	if err == nil || !strings.Contains(err.Error(), "TXT not found") {
		t.Fatalf("Do err = %v, want Zoho's refusal", err)
	}
	if n := len(*calls); !strings.Contains((*calls)[n-1], `"mode":"verifyDomainByTXT"`) {
		t.Errorf("last call = %q", (*calls)[n-1])
	}
}

func TestPlanOnVerifiedDomainCreatesMailboxAliasAndCatchAll(t *testing.T) {
	provider, calls, tokens := serve(t, map[string]string{
		domainsPath:  listed(),
		domainPath:   verifiedDomain(),
		accountsPath: ok(`[]`),
	})
	d := domainConfig()
	ctx := context.Background()
	if _, err := provider.DesiredDNS(ctx, d); err != nil {
		t.Fatal(err)
	}
	actual, err := provider.Actual(ctx, d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "pw-1" })}
	actions, err := provider.Plan(d, actual, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	want := []string{"create mailbox", "create alias", "update catchall"}
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %+v", len(actions), len(want), actions)
	}
	for i, w := range want {
		if got := string(actions[i].Op) + " " + actions[i].Resource; !strings.EqualFold(got, w) {
			t.Errorf("action %d = %q, want %q", i, got, w)
		}
		if strings.Contains(actions[i].Detail, "pw-1") {
			t.Fatalf("detail leaked the credential: %q", actions[i].Detail)
		}
	}
	if err := actions[0].Do(ctx); err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	if last := (*calls)[len(*calls)-1]; !strings.Contains(last, `"primaryEmailAddress":"me@a.com"`) || !strings.Contains(last, `"displayName":"Me"`) {
		t.Errorf("create call = %q", last)
	}
	if *tokens != 1 {
		t.Errorf("token requests = %d, want 1 (cached)", *tokens)
	}
}

func TestPlanIsEmptyWhenConverged(t *testing.T) {
	provider, _, _ := serve(t, map[string]string{
		domainsPath: listed(),
		domainPath: ok(`{"domainName":"a.com","verificationStatus":true,"mailHostingEnabled":true,"catchAllAddress":"me@a.com",
			"dkimDetailList":[{"dkimId":77,"selector":"zmail","publicKey":"p=KEY","isVerified":true}]}`),
		accountsPath: ok(`[{"zuid":5,"primaryEmailAddress":"me@a.com","emailAddress":[
			{"mailId":"me@a.com","isAlias":false},{"mailId":"info@a.com","isAlias":true}]}]`),
	})
	d := domainConfig()
	actual, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, mail.Options{Prune: true, PruneMailboxes: true, Secrets: secret.NewResolver(nil)})
	if err != nil || len(actions) != 0 {
		t.Fatalf("Plan = %+v, %v; want nothing", actions, err)
	}
}

func TestPlanMovesAnAliasAndPrunesOnlyWhenAsked(t *testing.T) {
	provider, calls, _ := serve(t, map[string]string{
		domainsPath: listed(),
		domainPath:  verifiedDomain(),
		accountsPath: ok(`[
			{"zuid":5,"primaryEmailAddress":"me@a.com","emailAddress":[{"mailId":"old@a.com","isAlias":true}]},
			{"zuid":6,"primaryEmailAddress":"you@a.com","emailAddress":[{"mailId":"info@a.com","isAlias":"true"}]}]`),
	})
	d := domainConfig()
	d.CatchAll = nil
	ctx := context.Background()
	actual, err := provider.Actual(ctx, d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	actions, _ := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete then create of info@", actions)
	}
	for _, a := range actions {
		if err := a.Do(ctx); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	got := strings.Join((*calls)[len(*calls)-2:], "\n")
	if !strings.Contains(got, "PUT /api/organization/9/accounts/6") || !strings.Contains(got, "deleteEmailAlias") ||
		!strings.Contains(got, "PUT /api/organization/9/accounts/5") || !strings.Contains(got, "addEmailAlias") {
		t.Errorf("alias calls = %s", got)
	}

	pruned, _ := provider.Plan(d, actual, mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if len(pruned) != 3 || !strings.Contains(pruned[2].Detail, "old@a.com") {
		t.Errorf("prune actions = %+v, want old@a.com removed too", pruned)
	}
}

func TestEnvelopeErrorSurfaces(t *testing.T) {
	provider, _, _ := serve(t, map[string]string{
		domainsPath: `{"status":{"code":500,"description":"Invalid Input"},"data":{"moreInfo":"bad zoid"}}`,
	})
	_, err := provider.Actual(context.Background(), domainConfig())
	if err == nil || !strings.Contains(err.Error(), "bad zoid") {
		t.Fatalf("err = %v, want the envelope error", err)
	}
}
