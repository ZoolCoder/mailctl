package purelymail

import (
	"context"
	"encoding/json"
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

// routes serves canned responses keyed by endpoint name and records every
// request body it received, keyed the same way.
type routes struct {
	responses map[string]string
	calls     []string
	bodies    map[string][]map[string]any
}

func newRoutes(responses map[string]string) *routes {
	return &routes{responses: responses, bodies: map[string][]map[string]any{}}
}

func (r *routes) client(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		endpoint := strings.TrimPrefix(req.URL.Path, "/api/v0/")
		raw, _ := io.ReadAll(req.Body)
		body := map[string]any{}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decode request body: %v", err)
			}
		}

		r.calls = append(r.calls, endpoint)
		r.bodies[endpoint] = append(r.bodies[endpoint], body)

		response, ok := r.responses[endpoint]
		if !ok {
			response = `{"type":"success","result":null}`
		}
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "tok")
}

func domainConfig() config.Domain {
	return config.Domain{
		Name:     "a.com",
		ZoneName: "a.com",
		Mail:     config.Mail{Providers: []string{"purelymail"}},
		Mailboxes: []config.Mailbox{
			{Address: "contact@a.com", PasswordEnv: "PW"},
		},
		Aliases:  []config.Alias{{Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &config.CatchAll{To: []string{"contact@a.com"}},
	}
}

func TestDesiredDNSCoversMXSPFOwnershipDKIMDMARC(t *testing.T) {
	r := newRoutes(map[string]string{
		"getOwnershipCode": `{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`,
	})
	provider := &Provider{client: r.client(t)}

	records, err := provider.DesiredDNS(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}

	byKind := map[dns.Kind][]dns.Record{}
	for _, rec := range records {
		byKind[rec.Kind] = append(byKind[rec.Kind], rec)
	}

	if got := byKind[dns.KindMX]; len(got) != 1 || got[0].Content != "mailserver.purelymail.com" || got[0].Priority != 50 {
		t.Errorf("MX = %+v, want one record to mailserver.purelymail.com priority 50", got)
	}
	if got := byKind[dns.KindSPF]; len(got) != 1 || !strings.Contains(got[0].Content, "include:_spf.purelymail.com") {
		t.Errorf("SPF = %+v, want the purelymail include", got)
	}
	if got := byKind[dns.KindOwnership]; len(got) != 1 || got[0].Content != "purelymail_ownership_proof=abc" {
		t.Errorf("ownership = %+v, want the code from the API", got)
	}
	if got := byKind[dns.KindDKIM]; len(got) != 3 {
		t.Errorf("DKIM = %+v, want three CNAMEs", got)
	}
	if got := byKind[dns.KindDMARC]; len(got) != 1 || got[0].Type != "CNAME" {
		t.Errorf("DMARC = %+v, want the dmarcroot CNAME", got)
	}
	for _, rec := range byKind[dns.KindDKIM] {
		if rec.Proxied == nil || *rec.Proxied {
			t.Errorf("DKIM record %s must be DNS-only, not proxied", rec.Name)
		}
	}
}

func TestDesiredDNSOmitsDMARCCNAMEWhenConfigManagesDMARC(t *testing.T) {
	r := newRoutes(map[string]string{
		"getOwnershipCode": `{"type":"success","result":{"code":"code"}}`,
	})
	provider := &Provider{client: r.client(t)}

	d := domainConfig()
	d.Deliverability.DMARC = &config.DMARC{Policy: "reject", Pct: 100}

	records, err := provider.DesiredDNS(context.Background(), d)
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	for _, rec := range records {
		if rec.Kind == dns.KindDMARC {
			t.Fatalf("provider must not publish a DMARC record when the config declares one; got %+v", rec)
		}
	}
}

func TestActualReadsDomainMailboxesAndRules(t *testing.T) {
	r := newRoutes(map[string]string{
		"listDomains": `{"type":"success","result":{"domains":[
			{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,
			 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":true,"passesDmarc":false}}]}}`,
		"listUser":          `{"type":"success","result":{"users":["contact@a.com","other@b.com"]}}`,
		"listPasswordReset": `{"type":"success","result":{"methods":[{"id":"1","type":"email","target":"fallback@example.com","description":"personal"}]}}`,
		"listRoutingRules": `{"type":"success","result":{"rules":[
			{"id":7,"domainName":"a.com","matchUser":"info","prefix":false,"targetAddresses":["contact@a.com"],"catchall":false},
			{"id":8,"domainName":"a.com","matchUser":"","prefix":false,"targetAddresses":["contact@a.com"],"catchall":true},
			{"id":9,"domainName":"b.com","matchUser":"x","prefix":false,"targetAddresses":["y@b.com"],"catchall":false}]}}`,
	})
	provider := &Provider{client: r.client(t)}

	state, err := provider.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if !state.DomainExists {
		t.Error("DomainExists = false, want true")
	}
	if len(state.Mailboxes) != 1 || state.Mailboxes[0].Address != "contact@a.com" {
		t.Errorf("mailboxes = %+v, want only the a.com mailbox", state.Mailboxes)
	}
	if len(state.Mailboxes[0].Recovery) != 1 || state.Mailboxes[0].Recovery[0].Target != "fallback@example.com" {
		t.Errorf("recovery = %+v, want the one listed method", state.Mailboxes[0].Recovery)
	}
	if len(state.Aliases) != 1 || state.Aliases[0].Match != "info" {
		t.Errorf("aliases = %+v, want only the a.com alias", state.Aliases)
	}
	if state.CatchAll == nil || state.CatchAll.ID != "8" {
		t.Errorf("catchAll = %+v, want rule 8", state.CatchAll)
	}
	if len(state.Notes) == 0 || !strings.Contains(state.Notes[0], "dmarc=false") {
		t.Errorf("notes = %v, want the DNS summary", state.Notes)
	}
}

func TestActualOmitsNoteWhenDNSFullyConverged(t *testing.T) {
	r := newRoutes(map[string]string{
		"listDomains": `{"type":"success","result":{"domains":[
			{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,
			 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":true,"passesDmarc":true}}]}}`,
		"listUser":         `{"type":"success","result":{"users":[]}}`,
		"listRoutingRules": `{"type":"success","result":{"rules":[]}}`,
	})
	provider := &Provider{client: r.client(t)}

	state, err := provider.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if len(state.Notes) != 0 {
		t.Errorf("notes = %v, want none; a fully converged domain has nothing to tell the operator", state.Notes)
	}
}

func TestActualSurfacesNoteWhenAnyDNSFlagIsFalse(t *testing.T) {
	r := newRoutes(map[string]string{
		"listDomains": `{"type":"success","result":{"domains":[
			{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,
			 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":true,"passesDmarc":false}}]}}`,
		"listUser":         `{"type":"success","result":{"users":[]}}`,
		"listRoutingRules": `{"type":"success","result":{"rules":[]}}`,
	})
	provider := &Provider{client: r.client(t)}

	state, err := provider.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if len(state.Notes) != 1 || !strings.Contains(state.Notes[0], "dmarc=false") {
		t.Errorf("notes = %v, want one note naming the failing DMARC check", state.Notes)
	}
}

func TestPlanOnEmptyProviderCreatesEverything(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "value-1" })}

	actions, err := provider.Plan(domainConfig(), mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	want := []struct {
		op       plan.Op
		resource string
	}{
		{plan.OpCreate, "domain"},
		{plan.OpCreate, "mailbox"},
		{plan.OpCreate, "alias"},
		{plan.OpCreate, "catchall"},
	}
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %+v", len(actions), len(want), actions)
	}
	for i, w := range want {
		if actions[i].Op != w.op || actions[i].Resource != w.resource {
			t.Errorf("action %d = %s %s, want %s %s", i, actions[i].Op, actions[i].Resource, w.op, w.resource)
		}
	}
	for _, a := range actions {
		if strings.Contains(a.Detail, "value-1") {
			t.Fatalf("action detail leaked a credential: %q", a.Detail)
		}
	}
}

func TestPlanIsEmptyWhenConverged(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none", actions)
	}
}

func TestPlanReplacesAliasWhenTargetsDrift(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "info", To: []string{"stale@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete then create for the drifted alias", actions)
	}
}

func TestPlanLeavesUnmanagedObjectsAloneWithoutPrune(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com"},
			{Address: "legacy@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; legacy@a.com is unmanaged, not deletable", actions)
	}
}

func TestPlanPruneDeletesUnmanagedMailbox(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com"},
			{Address: "legacy@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	// Deleting a mailbox destroys mail, so it needs both -prune and
	// -prune-mailboxes (Finding 1); -prune alone is exercised by
	// TestPlanNeverDeletesAMailboxWithoutBothFlags below.
	actions, err := provider.Plan(domainConfig(), actual,
		mail.Options{Prune: true, PruneMailboxes: true, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpDelete || !strings.Contains(actions[0].Detail, "legacy@a.com") {
		t.Fatalf("actions = %+v, want one delete naming legacy@a.com", actions)
	}
}

// TestPlanNeverDeletesAMailboxWithoutBothFlags is the Finding 1 regression
// test: mailboxes carry mail, so purelymail must require -prune AND
// -prune-mailboxes together, matching the ms365 provider's semantics (which
// the shared mail.Options doc comment already promised for every provider).
// Aliases and the catch-all carry no mail, so they stay gated on -prune
// alone and are asserted unaffected here.
func TestPlanNeverDeletesAMailboxWithoutBothFlags(t *testing.T) {
	newActual := func() mail.State {
		return mail.State{
			DomainExists: true,
			Mailboxes: []mail.Mailbox{
				{Address: "contact@a.com"},
				{Address: "legacy@a.com"},
			},
			Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}, {ID: "9", Match: "stale", To: []string{"contact@a.com"}}},
			CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
		}
	}

	cases := []struct {
		name            string
		opts            mail.Options
		wantMailboxDels int
	}{
		{"neither", mail.Options{Secrets: secret.NewResolver(nil)}, 0},
		{"prune only", mail.Options{Prune: true, Secrets: secret.NewResolver(nil)}, 0},
		{"prune-mailboxes only", mail.Options{PruneMailboxes: true, Secrets: secret.NewResolver(nil)}, 0},
		{"both", mail.Options{Prune: true, PruneMailboxes: true, Secrets: secret.NewResolver(nil)}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &Provider{client: newRoutes(nil).client(t)}
			actions, err := provider.Plan(domainConfig(), newActual(), tc.opts)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			mailboxDels := 0
			aliasDels := 0
			for _, a := range actions {
				if a.Op != plan.OpDelete {
					continue
				}
				switch a.Resource {
				case "mailbox":
					mailboxDels++
				case "alias":
					aliasDels++
				}
			}
			if mailboxDels != tc.wantMailboxDels {
				t.Fatalf("mailbox deletes = %d, want %d: %+v", mailboxDels, tc.wantMailboxDels, actions)
			}
			// The stale alias "stale" is unmanaged in every case; it must
			// keep pruning on Prune alone regardless of PruneMailboxes,
			// since only a mailbox needs the second opt-in.
			wantAliasDels := 0
			if tc.opts.Prune {
				wantAliasDels = 1
			}
			if aliasDels != wantAliasDels {
				t.Fatalf("alias deletes = %d, want %d: %+v", aliasDels, wantAliasDels, actions)
			}
		})
	}
}

func TestPlanReconcilesRecoveryMethods(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	d.Mailboxes[0].Recovery = []config.Recovery{
		{Type: "email", Target: "new@example.com", Description: "personal"},
	}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{{
			Address:  "contact@a.com",
			Recovery: []mail.Recovery{{ID: "m1", Type: "email", Target: "old@example.com"}},
		}},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %+v, want 2 recovery actions (create new, delete old)", actions)
	}
	if actions[0].Op != plan.OpCreate || actions[0].Resource != "recovery" {
		t.Errorf("action 0 = %s %s, want CREATE recovery", actions[0].Op, actions[0].Resource)
	}
	if !strings.Contains(actions[0].Detail, "new@example.com") {
		t.Errorf("action 0 detail = %q, want the new target named", actions[0].Detail)
	}
	if actions[1].Op != plan.OpDelete || actions[1].Resource != "recovery" {
		t.Errorf("action 1 = %s %s, want DELETE recovery", actions[1].Op, actions[1].Resource)
	}
	if !strings.Contains(actions[1].Detail, "old@example.com") {
		t.Errorf("action 1 detail = %q, want the old target named", actions[1].Detail)
	}
}

func TestPlanLeavesRecoveryAloneWhenNotDeclared(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	// No recovery block in config
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{{
			Address:  "contact@a.com",
			Recovery: []mail.Recovery{{ID: "m1", Type: "email", Target: "fallback@example.com"}},
		}},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range actions {
		if a.Resource == "recovery" {
			t.Fatalf("should not manage recovery when config declares none; got %+v", a)
		}
	}
}

func TestPlanConvergesIdenticalRecoveryMethod(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	d.Mailboxes[0].Recovery = []config.Recovery{
		{Type: "email", Target: "backup@example.com", Description: "primary"},
	}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{{
			Address:  "contact@a.com",
			Recovery: []mail.Recovery{{ID: "m1", Type: "email", Target: "backup@example.com"}},
		}},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range actions {
		if a.Resource == "recovery" {
			t.Fatalf("should not plan changes when recovery is converged; got %+v", a)
		}
	}
}

func TestGeneratedCredentialIsNotReportedWhenCreateUserFails(t *testing.T) {
	r := newRoutes(map[string]string{
		"createUser": `{"type":"error","code":"SOME_ERROR","message":"nope"}`,
	})
	d := domainConfig()
	d.Mailboxes[0].PasswordEnv = "" // force generation instead of an env lookup
	provider := &Provider{client: r.client(t)}
	secrets := secret.NewResolver(func(string) string { return "" })
	opts := mail.Options{Secrets: secrets}

	actions, err := provider.Plan(d, mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, a := range actions {
		if a.Resource != "mailbox" {
			continue
		}
		if err := a.Do(context.Background()); err == nil {
			t.Fatal("expected CreateUser to fail")
		}
	}

	if applied := secrets.Applied(); len(applied) != 0 {
		t.Errorf("Applied() = %v, want none; the mailbox was never actually created", applied)
	}
}

func TestGeneratedCredentialIsReportedWhenCreateUserSucceeds(t *testing.T) {
	r := newRoutes(nil)
	d := domainConfig()
	d.Mailboxes[0].PasswordEnv = "" // force generation instead of an env lookup
	provider := &Provider{client: r.client(t)}
	secrets := secret.NewResolver(func(string) string { return "" })
	opts := mail.Options{Secrets: secrets}

	actions, err := provider.Plan(d, mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, a := range actions {
		if a.Resource == "mailbox" {
			if err := a.Do(context.Background()); err != nil {
				t.Fatalf("Do mailbox create: %v", err)
			}
		}
	}

	applied := secrets.Applied()
	if len(applied) != 1 {
		t.Fatalf("Applied() = %v, want exactly one address", applied)
	}
	if _, ok := applied["contact@a.com"]; !ok {
		t.Errorf("Applied() = %v, want contact@a.com", applied)
	}
}

func TestApplyingPlanCallsTheRightEndpoints(t *testing.T) {
	r := newRoutes(nil)
	provider := &Provider{client: r.client(t)}
	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "value-1" })}

	actions, err := provider.Plan(domainConfig(), mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do %s %s: %v", a.Op, a.Resource, err)
		}
	}

	wantCalls := []string{"addDomain", "createUser", "createRoutingRule", "createRoutingRule"}
	if len(r.calls) != len(wantCalls) {
		t.Fatalf("calls = %v, want %v", r.calls, wantCalls)
	}
	for i, want := range wantCalls {
		if r.calls[i] != want {
			t.Errorf("call %d = %s, want %s", i, r.calls[i], want)
		}
	}
	if got := r.bodies["createRoutingRule"][1]["catchall"]; got != true {
		t.Errorf("second routing rule catchall = %v, want true", got)
	}
}

func TestPlanDomainSettingsDrift(t *testing.T) {
	r := newRoutes(nil)
	provider := &Provider{client: r.client(t)}

	d := domainConfig()
	d.Mail.Settings.AllowAccountReset = &[]bool{true}[0]
	d.Mail.Settings.SymbolicSubaddressing = &[]bool{false}[0]
	actual := mail.State{
		DomainExists: true,
		Settings: mail.Settings{
			AllowAccountReset:     false,
			SymbolicSubaddressing: true,
		},
		Mailboxes: []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:   []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll:  &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	updateCount := 0
	for _, a := range actions {
		if a.Op == plan.OpUpdate && a.Resource == "domain" {
			updateCount++
			if !strings.Contains(a.Detail, "true") || !strings.Contains(a.Detail, "false") {
				t.Errorf("update detail should name the requested values; got %q", a.Detail)
			}
		}
	}
	if updateCount != 1 {
		t.Errorf("expected 1 domain update, got %d; actions = %+v", updateCount, actions)
	}

	// Execute and verify the endpoint was called
	for _, a := range actions {
		if a.Op == plan.OpUpdate && a.Resource == "domain" {
			if err := a.Do(context.Background()); err != nil {
				t.Fatalf("Do domain update: %v", err)
			}
		}
	}
	found := false
	for _, call := range r.calls {
		if call == "updateDomainSettings" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("updateDomainSettings should have been called; calls = %v", r.calls)
	}
}

func TestPlanDomainSettingsConverged(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	d.Mail.Settings.AllowAccountReset = &[]bool{true}[0]
	actual := mail.State{
		DomainExists: true,
		Settings: mail.Settings{
			AllowAccountReset: true,
		},
		Mailboxes: []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:   []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll:  &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, a := range actions {
		if a.Op == plan.OpUpdate && a.Resource == "domain" {
			t.Fatalf("should not update domain when settings converged; got %+v", a)
		}
	}
}

func TestPlanDomainSettingsNilMeansLeaveAlone(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	// Leave both settings unconfigured (nil pointers)
	actual := mail.State{
		DomainExists: true,
		Settings: mail.Settings{
			AllowAccountReset:     true,
			SymbolicSubaddressing: true,
		},
		Mailboxes: []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:   []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll:  &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, a := range actions {
		if a.Op == plan.OpUpdate && a.Resource == "domain" {
			t.Fatalf("nil settings should mean 'leave alone', not 'set false'; got %+v", a)
		}
	}
}

func TestPlanPruneDeletesUnmanagedAlias(t *testing.T) {
	r := newRoutes(nil)
	provider := &Provider{client: r.client(t)}

	d := domainConfig()
	// Config has no aliases
	d.Aliases = nil
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "legacy", To: []string{"contact@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	deleteCount := 0
	for _, a := range actions {
		if a.Op == plan.OpDelete && a.Resource == "alias" {
			deleteCount++
			if !strings.Contains(a.Detail, "legacy") {
				t.Errorf("delete detail should name the alias; got %q", a.Detail)
			}
		}
	}
	if deleteCount != 1 {
		t.Errorf("expected 1 alias delete, got %d; actions = %+v", deleteCount, actions)
	}

	// Execute and verify the endpoint was called with the unmanaged alias's rule ID
	for _, a := range actions {
		if a.Op == plan.OpDelete && a.Resource == "alias" {
			if err := a.Do(context.Background()); err != nil {
				t.Fatalf("Do alias delete: %v", err)
			}
		}
	}
	if len(r.bodies["deleteRoutingRule"]) == 0 {
		t.Fatalf("deleteRoutingRule should have been called; calls = %v", r.calls)
	}
	// The unmanaged alias has ID "7"; verify it was deleted, not the managed one
	if got := r.bodies["deleteRoutingRule"][0]["routingRuleId"]; got != float64(7) {
		t.Errorf("deleted routing rule ID = %v, want 7 (the unmanaged alias)", got)
	}
}

func TestPlanDoesNotPruneAliasByDefault(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	// Config has no aliases
	d.Aliases = nil
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "legacy", To: []string{"contact@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Prune: false, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	for _, a := range actions {
		if a.Op == plan.OpDelete && a.Resource == "alias" {
			t.Fatalf("should not delete unmanaged alias when Prune=false; got %+v", a)
		}
	}
}

func TestPlanNewMailboxWithRecoveryMethods(t *testing.T) {
	r := newRoutes(nil)
	provider := &Provider{client: r.client(t)}

	d := domainConfig()
	d.Mailboxes[0].Recovery = []config.Recovery{
		{Type: "email", Target: "backup1@example.com", Description: "primary"},
		{Type: "email", Target: "backup2@example.com", Description: "secondary"},
	}
	actual := mail.State{
		DomainExists: true,
		// Mailbox does not exist
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "password" })}
	actions, err := provider.Plan(d, actual, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Count mailbox create and recovery creates
	mailboxCreateCount := 0
	recoveryCreateCount := 0
	recoveryDeleteCount := 0
	for _, a := range actions {
		if a.Op == plan.OpCreate && a.Resource == "mailbox" {
			mailboxCreateCount++
		} else if a.Op == plan.OpCreate && a.Resource == "recovery" {
			recoveryCreateCount++
		} else if a.Op == plan.OpDelete && a.Resource == "recovery" {
			recoveryDeleteCount++
		}
	}

	if mailboxCreateCount != 1 {
		t.Errorf("expected 1 mailbox create, got %d", mailboxCreateCount)
	}
	if recoveryCreateCount != 2 {
		t.Errorf("expected 2 recovery creates, got %d; actions = %+v", recoveryCreateCount, actions)
	}
	if recoveryDeleteCount != 0 {
		t.Errorf("expected 0 recovery deletes (nothing provider-side), got %d", recoveryDeleteCount)
	}
}

func TestProviderIsRegistered(t *testing.T) {
	for _, name := range mail.Registered() {
		if name == "purelymail" {
			return
		}
	}
	t.Fatal("purelymail should register itself in an init function")
}
