package ms365

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/graphapi"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

// fakeGraph serves the token endpoint and the Graph paths the provider uses.
// handlers is keyed by "METHOD /path"; a missing key is a 404, which is what
// Graph returns for a domain that is not in the tenant.
func fakeGraph(t *testing.T, handlers map[string]func(w http.ResponseWriter, r *http.Request)) *Provider {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 3600})
			return
		}
		if handler, ok := handlers[r.Method+" "+r.URL.Path]; ok {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"Request_ResourceNotFound","message":"not found"}}`))
	}))
	t.Cleanup(server.Close)

	client, err := graphapi.New(graphapi.Config{
		TenantID: "t", ClientID: "c", ClientSecret: "s",
		GraphBaseURL: server.URL, LoginBaseURL: server.URL,
	})
	if err != nil {
		t.Fatalf("graphapi.New: %v", err)
	}
	return &Provider{
		client:   client,
		skus:     map[string]map[string]licenceInfo{},
		skuNames: map[string]map[string]string{},
	}
}

func domainConfig(boxes ...config.Mailbox) config.Domain {
	return config.Domain{
		Name:     "example.com",
		ZoneName: "example.com",
		Mail: config.Mail{
			Providers: []string{"ms365"},
			MS365:     &config.MS365{License: "BUSINESS_BASIC", UsageLocation: "DE"},
		},
		Mailboxes: boxes,
	}
}

func json200(payload string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(payload)) }
}

func TestActualReportsAnAbsentDomain(t *testing.T) {
	p := fakeGraph(t, nil)
	state, err := p.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if state.DomainExists {
		t.Fatal("DomainExists = true, want false for a 404")
	}
	if !containsSubstring(state.Notes, "added to the tenant") {
		t.Errorf("Notes = %v, want one explaining the two-pass flow", state.Notes)
	}
}

func TestActualReadsDomainUsersAndSeats(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com": json200(`{"id":"example.com","isVerified":true,"supportedServices":["Email"]}`),
		"GET /domains/example.com/domainNameReferences/microsoft.graph.user": json200(
			`{"value":[{"id":"u1","mail":"a@example.com","userPrincipalName":"a@example.com"}]}`),
		"GET /subscribedSkus": json200(
			`{"value":[{"skuId":"sku-basic","skuPartNumber":"BUSINESS_BASIC","consumedUnits":1,"prepaidUnits":{"enabled":5}}]}`),
	})

	state, err := p.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if !state.DomainExists {
		t.Fatal("DomainExists = false")
	}
	if len(state.Mailboxes) != 1 || state.Mailboxes[0].Address != "a@example.com" {
		t.Fatalf("Mailboxes = %+v", state.Mailboxes)
	}
	if len(state.Aliases) != 0 || state.CatchAll != nil {
		t.Error("aliases and catch-all must always be empty for ms365")
	}
	if !containsSubstring(state.Notes, "BUSINESS_BASIC") {
		t.Errorf("Notes = %v, want a seat line naming the SKU", state.Notes)
	}
	if !containsSubstring(state.Notes, "per domain") {
		t.Errorf("Notes = %v, want the seat line to disclose it is per domain, "+
			"not per tenant (Finding 2)", state.Notes)
	}
}

func TestPlanCreatesTheDomainFirstAndNothingElse(t *testing.T) {
	p := fakeGraph(t, nil)
	d := domainConfig(config.Mailbox{Address: "a@example.com"})

	actions, err := p.Plan(d, mail.State{}, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("got %d actions, want 1; mailboxes must wait for verification: %v", len(actions), render(actions))
	}
	if actions[0].Op != plan.OpCreate || !strings.Contains(actions[0].Detail, "add domain") {
		t.Fatalf("action = %+v", actions[0])
	}
}

func TestPlanVerifiesBeforeAnythingElse(t *testing.T) {
	p := fakeGraph(t, nil)
	d := domainConfig(config.Mailbox{Address: "a@example.com"})

	actions, err := p.Plan(d, mail.State{DomainExists: true}, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || !strings.Contains(actions[0].Detail, "verify") {
		t.Fatalf("actions = %v, want only a verify action", render(actions))
	}
}

func TestPlanOrdersServicesThenMailboxes(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{
		"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5},
	}
	d := domainConfig(
		config.Mailbox{Address: "a@example.com"},
		config.Mailbox{Address: "b@example.com"},
	)
	state := mail.State{DomainExists: true, Verified: true}

	actions, err := p.Plan(d, state, mail.Options{Secrets: nil})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	got := render(actions)
	if len(got) != 3 {
		t.Fatalf("actions = %v, want update-services then two mailboxes", got)
	}
	if !strings.Contains(got[0], "supportedServices") {
		t.Errorf("first action = %q, want the services update first", got[0])
	}
	for i, want := range []string{"a@example.com", "b@example.com"} {
		if !strings.Contains(got[i+1], want) {
			t.Errorf("action %d = %q, want %s", i+1, got[i+1], want)
		}
	}
}

func TestPlanRefusesWhenSeatsAreShort(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{
		"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 1},
	}
	d := domainConfig(
		config.Mailbox{Address: "a@example.com"},
		config.Mailbox{Address: "b@example.com"},
	)
	_, err := p.Plan(d, mail.State{DomainExists: true, Verified: true, SupportedServices: []string{"Email"}}, mail.Options{})
	if err == nil {
		t.Fatal("want an error: two mailboxes need two seats and only one is free")
	}
	if !strings.Contains(err.Error(), "BUSINESS_BASIC") {
		t.Errorf("error = %q, want it to name the SKU", err)
	}
}

// TestPlanMailboxHasThreeStates covers all three states a configured mailbox
// can be in relative to the tenant: absent (create both the user and its
// licence), present but not carrying the resolved licence's skuId (assign
// only the licence — the user already exists and must not be recreated), and
// present and already licensed (nothing to do). The middle case is the whole
// point: without it, a licence failure during create leaves a user stranded
// forever, since a later plan finds the address present and reports nothing
// to do.
func TestPlanMailboxHasThreeStates(t *testing.T) {
	var calledCreateUser bool
	var assignLicenseHits []string
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /users": func(w http.ResponseWriter, r *http.Request) {
			calledCreateUser = true
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "new-user-id"})
		},
		"POST /users/u1/assignLicense": func(w http.ResponseWriter, r *http.Request) {
			assignLicenseHits = append(assignLicenseHits, "u1")
		},
	})
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5}}

	d := domainConfig(
		config.Mailbox{Address: "absent@example.com"},
		config.Mailbox{Address: "unlicensed@example.com"},
		config.Mailbox{Address: "licensed@example.com"},
	)
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{
			{ID: "u1", Address: "unlicensed@example.com"},
			{ID: "u2", Address: "licensed@example.com", AssignedSkuIDs: []string{"sku-basic"}},
		},
	}
	resolver := secret.NewResolver(func(string) string { return "" })

	actions, err := p.Plan(d, state, mail.Options{Secrets: resolver})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %v, want exactly one create (absent) and one licence-only update (unlicensed); "+
			"the already-licensed mailbox must produce nothing", render(actions))
	}

	var create, update *plan.Action
	for i := range actions {
		switch actions[i].Op {
		case plan.OpCreate:
			create = &actions[i]
		case plan.OpUpdate:
			update = &actions[i]
		}
	}
	if create == nil || !strings.Contains(create.Detail, "absent@example.com") {
		t.Fatalf("create action = %+v, want one naming the absent mailbox", create)
	}
	if update == nil || !strings.Contains(update.Detail, "unlicensed@example.com") || !strings.Contains(update.Detail, "BUSINESS_BASIC") {
		t.Fatalf("update action = %+v, want one naming the unlicensed mailbox and its SKU", update)
	}

	if err := update.Do(context.Background()); err != nil {
		t.Fatalf("update.Do: %v", err)
	}
	if calledCreateUser {
		t.Error("the licence-only update must not call POST /users; the account already exists")
	}
	if len(assignLicenseHits) != 1 {
		t.Fatalf("assignLicense hits = %v, want exactly one call for the unlicensed user's own id", assignLicenseHits)
	}
}

// TestPlanCountsUnlicensedMailboxesAgainstSeats proves the seat check treats
// an unlicensed-but-present mailbox the same as an absent one: both consume a
// seat, so a shortfall must fail Plan rather than let one succeed and the
// other silently wait forever.
func TestPlanCountsUnlicensedMailboxesAgainstSeats(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 1}}
	d := domainConfig(
		config.Mailbox{Address: "absent@example.com"},
		config.Mailbox{Address: "unlicensed@example.com"},
	)
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{ID: "u1", Address: "unlicensed@example.com"}},
	}

	_, err := p.Plan(d, state, mail.Options{})
	if err == nil {
		t.Fatal("want an error: the absent mailbox and the unlicensed one both need a BUSINESS_BASIC seat, and only one is free")
	}
	if !strings.Contains(err.Error(), "BUSINESS_BASIC") {
		t.Errorf("error = %q, want it to name the SKU", err)
	}
}

// TestAssignLicenseSendsEmptyRemoveLicensesNotNull asserts the wire format
// directly: Microsoft's assignLicense reference requires removeLicenses as a
// (possibly empty) collection, never null, and every published example sends
// []. Decoding into the Go request struct would not catch a missing
// omitempty regression; only the JSON on the wire proves this.
func TestAssignLicenseSendsEmptyRemoveLicensesNotNull(t *testing.T) {
	var body []byte
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /users/u1/assignLicense": func(w http.ResponseWriter, r *http.Request) {
			body, _ = io.ReadAll(r.Body)
		},
	})
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5}}
	d := domainConfig(config.Mailbox{Address: "unlicensed@example.com"})
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{ID: "u1", Address: "unlicensed@example.com"}},
	}

	actions, err := p.Plan(d, state, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want exactly one licence-only update", render(actions))
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decoding the assignLicense request body: %v", err)
	}
	if string(raw["removeLicenses"]) != "[]" {
		t.Errorf("removeLicenses = %s, want [] not null", raw["removeLicenses"])
	}
	var addLicenses []map[string]json.RawMessage
	if err := json.Unmarshal(raw["addLicenses"], &addLicenses); err != nil {
		t.Fatalf("decoding addLicenses: %v", err)
	}
	if len(addLicenses) != 1 {
		t.Fatalf("addLicenses = %v, want exactly one entry", addLicenses)
	}
	if string(addLicenses[0]["disabledPlans"]) != "[]" {
		t.Errorf("disabledPlans = %s, want [] not null", addLicenses[0]["disabledPlans"])
	}
}

// TestPlanMatchesTenantUserByEitherIdentityField is the I3 regression test:
// a tenant user whose displayed mail differs from its userPrincipalName, with
// config naming the userPrincipalName, must be recognised as the same
// mailbox rather than producing both a create (for the "absent" address
// config named) and a delete (for the "unmanaged" address Actual displayed).
func TestPlanMatchesTenantUserByEitherIdentityField(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5}}
	d := domainConfig(config.Mailbox{Address: "ghost@example.com"}) // config names the userPrincipalName
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{
			ID:               "u1",
			Address:          "ghost@old.example", // Graph's preferred mail attribute
			AlternateAddress: "ghost@example.com", // the account's userPrincipalName
			AssignedSkuIDs:   []string{"sku-basic"},
		}},
	}

	actions, err := p.Plan(d, state, mail.Options{Prune: true, PruneMailboxes: true})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf("actions = %v, want none: config named the account's userPrincipalName even though "+
			"its displayed mail differs, so this is neither a new mailbox nor an unmanaged one", render(actions))
	}
}

func TestPlanNeverDeletesAMailboxWithoutBothFlags(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "s", Available: 5}}
	d := domainConfig() // config declares no mailboxes
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{ID: "ghost-id", Address: "ghost@example.com"}},
	}

	cases := []struct {
		name        string
		opts        mail.Options
		wantDeletes int
	}{
		{"no flags", mail.Options{}, 0},
		{"prune only", mail.Options{Prune: true}, 0},
		{"prune-mailboxes only", mail.Options{PruneMailboxes: true}, 0},
		{"both", mail.Options{Prune: true, PruneMailboxes: true}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actions, err := p.Plan(d, state, tc.opts)
			if err != nil {
				t.Fatalf("Plan: %v", err)
			}
			deletes := 0
			for _, a := range actions {
				if a.Op == plan.OpDelete {
					deletes++
				}
			}
			if deletes != tc.wantDeletes {
				t.Fatalf("deletes = %d, want %d: %v", deletes, tc.wantDeletes, render(actions))
			}
		})
	}
}

// TestPlanDeleteMailboxTargetsTheGraphObjectIDNotTheAddress proves the delete
// action addresses Graph's object id, not the mailbox address. Graph resolves
// /users/{...} by id or userPrincipalName, never by an arbitrary mail
// attribute, so this fixture deliberately gives the user a mail address that
// differs from its userPrincipalName: if the delete ever targeted either
// string instead of the id, this test would fail (a same-string fixture would
// prove nothing).
func TestPlanDeleteMailboxTargetsTheGraphObjectIDNotTheAddress(t *testing.T) {
	const objectID = "11111111-1111-1111-1111-111111111111"
	var gotPath string
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com": json200(`{"id":"example.com","isVerified":true,"supportedServices":["Email"]}`),
		"GET /domains/example.com/domainNameReferences/microsoft.graph.user": json200(
			`{"value":[{"id":"` + objectID + `","mail":"ghost@example.com","userPrincipalName":"ghost@tenant.onmicrosoft.com"}]}`),
		"GET /subscribedSkus": json200(`{"value":[]}`),
		"DELETE /users/" + objectID: func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
		},
	})

	d := domainConfig() // config declares no mailboxes; the tenant's user is unmanaged
	actual, err := p.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if len(actual.Mailboxes) != 1 || actual.Mailboxes[0].ID != objectID {
		t.Fatalf("Mailboxes = %+v, want the object id captured from Graph", actual.Mailboxes)
	}

	actions, err := p.Plan(d, actual, mail.Options{Prune: true, PruneMailboxes: true})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpDelete {
		t.Fatalf("actions = %v, want exactly one delete", render(actions))
	}
	if !strings.Contains(actions[0].Detail, "ghost@example.com") {
		t.Errorf("Detail = %q, want it to name the address the operator recognises", actions[0].Detail)
	}

	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	want := "/users/" + objectID
	if gotPath != want {
		t.Fatalf("delete request path = %q, want %q (the Graph object id, not the address or UPN)", gotPath, want)
	}
}

func TestPlanRefusesToDeleteAMailboxWithNoObjectID(t *testing.T) {
	p := fakeGraph(t, nil)
	d := domainConfig() // config declares no mailboxes
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{Address: "ghost@example.com"}}, // no ID
	}

	_, err := p.Plan(d, state, mail.Options{Prune: true, PruneMailboxes: true})
	if err == nil {
		t.Fatal("want an error: mailctl must not guess a delete target when Graph gave no object id")
	}
	if !strings.Contains(err.Error(), "ghost@example.com") {
		t.Errorf("error = %q, want it to name the address", err)
	}
}

func TestDesiredDNSReturnsOnlyDKIMBeforeTheDomainExists(t *testing.T) {
	p := fakeGraph(t, nil)
	d := domainConfig()
	d.Mail.MS365.DKIMCnames = []string{"t1.dkim.mail.microsoft", "t2.dkim.mail.microsoft"}

	records, err := p.DesiredDNS(context.Background(), d)
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want only the two DKIM CNAMEs: %+v", len(records), records)
	}
}

func TestDesiredDNSReadsGraphOnceTheDomainExists(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com/verificationDnsRecords": json200(
			`{"value":[{"@odata.type":"#microsoft.graph.domainDnsTxtRecord","label":"example.com","text":"MS=ms1","supportedService":"Email"}]}`),
		"GET /domains/example.com/serviceConfigurationRecords": json200(
			`{"value":[{"@odata.type":"#microsoft.graph.domainDnsMxRecord","label":"example.com","mailExchange":"example-com.mail.protection.outlook.com","preference":0,"supportedService":"Email"}]}`),
	})

	records, err := p.DesiredDNS(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %+v, want the ownership TXT and the MX", records)
	}
}

// TestPlanCreateMailboxMarksCredentialAppliedBeforeLicenseFails is the
// load-bearing safety test the brief calls for: POST /users succeeds and sets
// a real password on a real account, then assignLicense fails. The generated
// credential must still show up in opts.Secrets.Applied(), because the
// operator has to be told about a password that is already live even when
// the mailbox ends up unlicensed. If MarkApplied moved to after the
// assignLicense call, this test would fail.
func TestPlanCreateMailboxMarksCredentialAppliedBeforeLicenseFails(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /users": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user-1"})
		},
		"POST /users/user-1/assignLicense": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"ServiceError","message":"licence assignment failed"}}`))
		},
	})
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5}}

	d := domainConfig(config.Mailbox{Address: "a@example.com"})
	state := mail.State{DomainExists: true, Verified: true, SupportedServices: []string{"Email"}}
	resolver := secret.NewResolver(func(string) string { return "" })
	opts := mail.Options{Secrets: resolver}

	actions, err := p.Plan(d, state, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want exactly one mailbox create", render(actions))
	}

	err = actions[0].Do(context.Background())
	if err == nil {
		t.Fatal("want an error: assignLicense fails in this test")
	}
	if !strings.Contains(err.Error(), "a@example.com") || !strings.Contains(err.Error(), "BUSINESS_BASIC") {
		t.Errorf("error = %q, want it to name the user and the licence", err)
	}

	applied := resolver.Applied()
	if _, ok := applied["a@example.com"]; !ok {
		// Deliberately not printing the map: it holds a live credential, and
		// test output must stay as free of credentials as stdout does.
		t.Fatal("Applied() missing a@example.com; want it marked applied even though " +
			"assignLicense failed — POST /users already set its password")
	}
}

// TestPlanLicenseOnlyUpdateHasNoLicenseKeepsExistingText locks down the
// has-no-licence branch's wording exactly as it read before Finding 3: an
// AssignedSkuIDs-empty mailbox genuinely has no mailbox yet (Exchange Online
// provisions one on licence assignment), so this phrasing must not change.
func TestPlanLicenseOnlyUpdateHasNoLicenseKeepsExistingText(t *testing.T) {
	p := fakeGraph(t, nil)
	p.skus["example.com"] = map[string]licenceInfo{"BUSINESS_BASIC": {SkuID: "sku-basic", Available: 5}}
	d := domainConfig(config.Mailbox{Address: "unlicensed@example.com"})
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{{ID: "u1", Address: "unlicensed@example.com"}}, // no AssignedSkuIDs
	}

	actions, err := p.Plan(d, state, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want exactly one licence-only update", render(actions))
	}
	want := "assign the BUSINESS_BASIC licence to unlicensed@example.com (the user exists but has no mailbox)"
	if actions[0].Detail != want {
		t.Errorf("Detail = %q, want %q unchanged from before Finding 3", actions[0].Detail, want)
	}
}

// TestPlanLicenseChangeDoesNotClaimNoMailboxAndNotesBothSKUs is the Finding 3
// regression test: a mailbox already holding a different licence must not be
// described as having no mailbox (it demonstrably has one, since it is
// already licensed), and the Detail must name both the SKU being added and
// the one already present so the operator is not surprised by double
// billing. The action must not remove the held licence — RemoveLicenses stays
// empty, never carrying the held SKU.
func TestPlanLicenseChangeDoesNotClaimNoMailboxAndNotesBothSKUs(t *testing.T) {
	var body []byte
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"POST /users/u1/assignLicense": func(w http.ResponseWriter, r *http.Request) {
			body, _ = io.ReadAll(r.Body)
		},
	})
	p.skus["example.com"] = map[string]licenceInfo{
		"BUSINESS_BASIC":    {SkuID: "sku-basic", Available: 5},
		"BUSINESS_STANDARD": {SkuID: "sku-standard", Available: 5},
	}
	p.skuNames["example.com"] = map[string]string{
		"sku-basic":    "BUSINESS_BASIC",
		"sku-standard": "BUSINESS_STANDARD",
	}
	d := domainConfig(config.Mailbox{Address: "sales@example.com", License: "BUSINESS_STANDARD"})
	state := mail.State{
		DomainExists: true, Verified: true, SupportedServices: []string{"Email"},
		Mailboxes: []mail.Mailbox{
			{ID: "u1", Address: "sales@example.com", AssignedSkuIDs: []string{"sku-basic"}},
		},
	}

	actions, err := p.Plan(d, state, mail.Options{})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("actions = %v, want exactly one licence-only update", render(actions))
	}
	detail := actions[0].Detail
	if strings.Contains(detail, "no mailbox") {
		t.Errorf("Detail = %q, must not claim the mailbox has no mailbox — it already holds a licence", detail)
	}
	if !strings.Contains(detail, "BUSINESS_STANDARD") || !strings.Contains(detail, "BUSINESS_BASIC") {
		t.Errorf("Detail = %q, want it to name both the added (BUSINESS_STANDARD) and held (BUSINESS_BASIC) SKUs", detail)
	}

	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decoding the assignLicense request body: %v", err)
	}
	if string(raw["removeLicenses"]) != "[]" {
		t.Errorf("removeLicenses = %s, want [] — the held licence must not be removed automatically", raw["removeLicenses"])
	}
}

// TestActualNotesALicenseChangeWithoutRemoval is the Finding 3 Actual-side
// regression test: a mailbox holding a different licence than config wants
// must produce a State.Notes line naming the mailbox, the SKU it holds, and
// the SKU config wants, so an operator reading notes learns about the double
// billing even before looking at the plan action.
func TestActualNotesALicenseChangeWithoutRemoval(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com": json200(`{"id":"example.com","isVerified":true,"supportedServices":["Email"]}`),
		"GET /domains/example.com/domainNameReferences/microsoft.graph.user": json200(
			`{"value":[{"id":"u1","mail":"sales@example.com","userPrincipalName":"sales@example.com",` +
				`"assignedLicenses":[{"skuId":"sku-basic"}]}]}`),
		"GET /subscribedSkus": json200(
			`{"value":[` +
				`{"skuId":"sku-basic","skuPartNumber":"BUSINESS_BASIC","consumedUnits":1,"prepaidUnits":{"enabled":5}},` +
				`{"skuId":"sku-standard","skuPartNumber":"BUSINESS_STANDARD","consumedUnits":0,"prepaidUnits":{"enabled":5}}` +
				`]}`),
	})
	d := domainConfig(config.Mailbox{Address: "sales@example.com", License: "BUSINESS_STANDARD"})

	state, err := p.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if !containsSubstring(state.Notes, "sales@example.com") ||
		!containsSubstring(state.Notes, "BUSINESS_BASIC") ||
		!containsSubstring(state.Notes, "BUSINESS_STANDARD") {
		t.Errorf("Notes = %v, want a line naming the mailbox, the held SKU, and the wanted SKU", state.Notes)
	}
}

// TestOpenRefusesANilGetenvInsteadOfPanicking mirrors purelymail's guard:
// mail.Open("ms365", mail.Deps{}) must return an error, not panic on a nil
// deps.Getenv, even though cmd/mailctl always supplies one in practice.
func TestOpenRefusesANilGetenvInsteadOfPanicking(t *testing.T) {
	_, err := mail.Open("ms365", mail.Deps{})
	if err == nil {
		t.Fatal("want an error for a nil Getenv, not a panic")
	}
	if !strings.Contains(err.Error(), "no environment accessor supplied") {
		t.Errorf("error = %q, want it to mention a missing environment accessor", err)
	}
}

// TestPlanRefusesANilMS365BlockInsteadOfPanicking is Plan's counterpart to
// DesiredDNS's existing nil guard: config validation makes a nil
// mail.ms365 block unreachable through config.Load, but Plan must not panic
// on one anyway.
func TestPlanRefusesANilMS365BlockInsteadOfPanicking(t *testing.T) {
	p := fakeGraph(t, nil)
	d := config.Domain{
		Name:      "example.com",
		ZoneName:  "example.com",
		Mail:      config.Mail{Providers: []string{"ms365"}},
		Mailboxes: []config.Mailbox{{Address: "a@example.com"}},
	}

	_, err := p.Plan(d, mail.State{DomainExists: true, Verified: true, SupportedServices: []string{"Email"}}, mail.Options{})
	if err == nil {
		t.Fatal("want an error for a nil mail.ms365 block, not a panic")
	}
	if !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "mail.ms365 is required") {
		t.Errorf("error = %q, want it to name the domain and say mail.ms365 is required", err)
	}
}

// TestActualNotesAReferencedLicenseTheTenantDoesNotSubscribeTo is the
// no-pending-creates case: a typo'd licence with no mailbox needing it must
// still surface at plan time, not only when checkSeats errors on an actual
// mailbox creation.
func TestActualNotesAReferencedLicenseTheTenantDoesNotSubscribeTo(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com": json200(`{"id":"example.com","isVerified":true,"supportedServices":["Email"]}`),
		"GET /domains/example.com/domainNameReferences/microsoft.graph.user": json200(
			`{"value":[{"id":"u1","mail":"a@example.com","userPrincipalName":"a@example.com",` +
				`"assignedLicenses":[{"skuId":"sku-basic"}]}]}`),
		"GET /subscribedSkus": json200(
			`{"value":[{"skuId":"sku-basic","skuPartNumber":"BUSINESS_BASIC","consumedUnits":1,"prepaidUnits":{"enabled":5}}]}`),
	})
	d := domainConfig(config.Mailbox{Address: "a@example.com", License: "TYPO_SKU"})

	state, err := p.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if !containsSubstring(state.Notes, "TYPO_SKU") {
		t.Errorf("Notes = %v, want a note naming the unsubscribed licence TYPO_SKU", state.Notes)
	}
	if !containsSubstring(state.Notes, "does not subscribe") {
		t.Errorf("Notes = %v, want the note to say the tenant does not subscribe to it", state.Notes)
	}
}

// TestEffectiveLicenseHandlesANilMS365Block is the regression test for the
// nil dereference effectiveLicense used to have: a nil mail.ms365 block
// must resolve to "", not panic, and a per-mailbox override must still win
// without ever touching the domain default.
func TestEffectiveLicenseHandlesANilMS365Block(t *testing.T) {
	d := config.Domain{Name: "example.com", Mail: config.Mail{Providers: []string{"ms365"}}}

	if got := effectiveLicense(d, config.Mailbox{Address: "a@example.com"}); got != "" {
		t.Errorf("effectiveLicense = %q, want empty for a nil mail.ms365 block and no override", got)
	}
	if got := effectiveLicense(d, config.Mailbox{Address: "a@example.com", License: "BUSINESS_BASIC"}); got != "BUSINESS_BASIC" {
		t.Errorf("effectiveLicense = %q, want the per-mailbox override even though mail.ms365 is nil", got)
	}
}

// TestActualDoesNotPanicWithANilMS365BlockAndAnAlreadyLicensedMailbox
// reproduces the caller Plan's nil guard does not reach: Actual's
// billing-hazard loop calls effectiveLicense with no guard of its own, so a
// nil mail.ms365 block plus a mailbox the tenant already licensed used to
// panic there.
func TestActualDoesNotPanicWithANilMS365BlockAndAnAlreadyLicensedMailbox(t *testing.T) {
	p := fakeGraph(t, map[string]func(http.ResponseWriter, *http.Request){
		"GET /domains/example.com": json200(`{"id":"example.com","isVerified":true,"supportedServices":["Email"]}`),
		"GET /domains/example.com/domainNameReferences/microsoft.graph.user": json200(
			`{"value":[{"id":"u1","mail":"a@example.com","userPrincipalName":"a@example.com",` +
				`"assignedLicenses":[{"skuId":"sku-basic"}]}]}`),
		"GET /subscribedSkus": json200(
			`{"value":[{"skuId":"sku-basic","skuPartNumber":"BUSINESS_BASIC","consumedUnits":1,"prepaidUnits":{"enabled":5}}]}`),
	})
	d := config.Domain{
		Name:      "example.com",
		ZoneName:  "example.com",
		Mail:      config.Mail{Providers: []string{"ms365"}},
		Mailboxes: []config.Mailbox{{Address: "a@example.com"}},
	}

	if _, err := p.Actual(context.Background(), d); err != nil {
		t.Fatalf("Actual: %v", err)
	}
}

func render(actions []plan.Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, a.Detail)
	}
	return out
}

func containsSubstring(list []string, want string) bool {
	for _, item := range list {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}
