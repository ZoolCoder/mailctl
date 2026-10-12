package cfrouting

import (
	"context"
	"net/http"
	"strings"
	"testing"

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

func routingDomain() config.Domain {
	return config.Domain{
		Name:     "a.com",
		ZoneName: "a.com",
		Mail:     config.Mail{Providers: []string{"cfrouting"}},
		Aliases:  []config.Alias{{Match: "info", To: []string{"dest@example.com"}}},
		CatchAll: &config.CatchAll{To: []string{"dest@example.com"}},
	}
}

func TestDesiredDNSComesFromCloudflare(t *testing.T) {
	client, _ := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":[
			{"type":"MX","name":"a.com","content":"route1.mx.cloudflare.net","priority":18,"ttl":1},
			{"type":"TXT","name":"a.com","content":"v=spf1 include:_spf.mx.cloudflare.net ~all","ttl":1}
		],"result_info":{"page":1,"total_pages":1}}`
	})
	provider := &Provider{client: client, zones: stubZones{}}

	records, err := provider.DesiredDNS(context.Background(), routingDomain())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want the two Cloudflare records", records)
	}
	if records[0].Kind != dns.KindMX {
		t.Errorf("MX record kind = %q, want %q so the diff applies MX conflict rules", records[0].Kind, dns.KindMX)
	}
	if records[1].Kind != dns.KindSPF {
		t.Errorf("SPF record kind = %q, want %q so the merge collapses it", records[1].Kind, dns.KindSPF)
	}
}

func TestPlanEnablesRoutingWhenDisabled(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}
	actual := mail.State{DomainExists: false}

	actions, err := provider.Plan(routingDomain(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) == 0 || actions[0].Resource != "domain" || actions[0].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want enabling routing first", actions)
	}
}

func TestPlanCreatesAliasAndCatchAll(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}
	actual := mail.State{DomainExists: true}

	actions, err := provider.Plan(routingDomain(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var resources []string
	for _, a := range actions {
		resources = append(resources, string(a.Op)+" "+a.Resource)
	}
	joined := strings.Join(resources, ", ")
	if !strings.Contains(joined, "CREATE alias") || !strings.Contains(joined, "CREATE catchall") {
		t.Errorf("actions = %s, want an alias and a catch-all", joined)
	}
}

func TestPlanReportsUnverifiedDestinationAsManual(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}
	actual := mail.State{
		DomainExists: true,
		Aliases:      []mail.Alias{{ID: "t1", Match: "info", To: []string{"dest@example.com"}}},
		CatchAll:     &mail.CatchAll{ID: "catch", To: []string{"dest@example.com"}},
		Notes:        []string{"destination dest@example.com is not verified"},
	}
	provider.unverified = map[string]bool{"dest@example.com": true}

	actions, err := provider.Plan(routingDomain(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpManual {
		t.Fatalf("actions = %+v, want one MANUAL entry for the unverified destination", actions)
	}
	if actions[0].Do != nil {
		t.Error("a MANUAL action must not be executable")
	}
}

func TestActualParsesRulesCatchAllAndDestinations(t *testing.T) {
	client, _ := serve(t, func(c *capture) string {
		switch {
		case strings.HasSuffix(c.path, "/rules/catch_all"):
			return `{"success":true,"errors":[],"result":{
				"tag":"catch","name":"catch-all","enabled":true,
				"matchers":[{"type":"all"}],
				"actions":[{"type":"forward","value":["dest@example.com","pending@example.com"]}]
			}}`
		case strings.HasSuffix(c.path, "/email/routing/rules"):
			return `{"success":true,"errors":[],"result":[
				{"tag":"t1","name":"info","enabled":true,
				 "matchers":[{"type":"literal","field":"to","value":"info@a.com"}],
				 "actions":[{"type":"forward","value":["dest@example.com"]}]}
			],"result_info":{"page":1,"total_pages":1}}`
		case strings.HasSuffix(c.path, "/email/routing/addresses"):
			return `{"success":true,"errors":[],"result":[
				{"tag":"d1","email":"dest@example.com","verified":"2026-01-01T00:00:00Z"},
				{"tag":"d2","email":"pending@example.com","verified":null}
			],"result_info":{"page":1,"total_pages":1}}`
		case strings.HasSuffix(c.path, "/email/routing"):
			return `{"success":true,"errors":[],"result":{"enabled":true,"name":"a.com","status":"unlocked"}}`
		default:
			t.Fatalf("unexpected request to %s", c.path)
			return ""
		}
	})
	provider := &Provider{client: client, zones: stubZones{}}

	d := routingDomain()
	d.Aliases = []config.Alias{{Match: "info", To: []string{"dest@example.com"}}}
	d.CatchAll = &config.CatchAll{To: []string{"pending@example.com", "ghost@example.com"}}

	state, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if !state.DomainExists {
		t.Fatal("DomainExists = false, want true")
	}
	if len(state.Aliases) != 1 || state.Aliases[0].ID != "t1" || state.Aliases[0].Match != "info" ||
		len(state.Aliases[0].To) != 1 || state.Aliases[0].To[0] != "dest@example.com" {
		t.Errorf("aliases = %+v, want one info -> dest@example.com aliased to tag t1", state.Aliases)
	}
	if state.CatchAll == nil || state.CatchAll.ID != "catch" || len(state.CatchAll.To) != 2 ||
		state.CatchAll.To[0] != "dest@example.com" || state.CatchAll.To[1] != "pending@example.com" {
		t.Errorf("catch-all = %+v, want tag catch forwarding to dest@example.com and pending@example.com", state.CatchAll)
	}

	if !provider.unverified["pending@example.com"] {
		t.Error("pending@example.com is known to Cloudflare but unverified; it should be marked unverified")
	}
	if provider.unverified["dest@example.com"] {
		t.Error("dest@example.com is verified and must not be marked unverified")
	}
	if !provider.missing["ghost@example.com"] {
		t.Error("ghost@example.com does not exist in Cloudflare's destination list; it should be marked missing")
	}
	if provider.missing["dest@example.com"] || provider.missing["pending@example.com"] {
		t.Error("destinations Cloudflare already knows about must not be marked missing")
	}
}

func TestPlanDeleteThenCreateActionsHitTheRightEndpoints(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"tag":"new-tag"}}`
	})
	provider := &Provider{client: client, zones: stubZones{}, zoneID: "z1"}

	d := routingDomain()
	actual := mail.State{
		DomainExists: true,
		Aliases:      []mail.Alias{{ID: "old-tag", Match: "info", To: []string{"old@example.com"}}},
		CatchAll:     &mail.CatchAll{ID: "catch", To: []string{"dest@example.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var deleteAction, createAction *plan.Action
	for i := range actions {
		switch {
		case actions[i].Op == plan.OpDelete && actions[i].Resource == "alias":
			deleteAction = &actions[i]
		case actions[i].Op == plan.OpCreate && actions[i].Resource == "alias":
			createAction = &actions[i]
		}
	}
	if deleteAction == nil || createAction == nil {
		t.Fatalf("actions = %+v, want a delete then a create for the drifted alias", actions)
	}

	if err := deleteAction.Do(context.Background()); err != nil {
		t.Fatalf("delete Do: %v", err)
	}
	if got.method != http.MethodDelete || got.path != "/zones/z1/email/routing/rules/old-tag" {
		t.Errorf("delete request = %s %s, want DELETE /zones/z1/email/routing/rules/old-tag", got.method, got.path)
	}

	if err := createAction.Do(context.Background()); err != nil {
		t.Fatalf("create Do: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/zones/z1/email/routing/rules" {
		t.Errorf("create request = %s %s, want POST /zones/z1/email/routing/rules", got.method, got.path)
	}
	matchers := got.body["matchers"].([]any)
	first := matchers[0].(map[string]any)
	if first["value"] != "info@a.com" {
		t.Errorf("matcher value = %v, want info@a.com", first["value"])
	}
}

func TestPlanCreatesMissingDestinationBeforeAskingToVerify(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"tag":"d3"}}`
	})
	provider := &Provider{client: client, zones: stubZones{}}
	provider.missing = map[string]bool{"dest@example.com": true}

	actual := mail.State{
		DomainExists: true,
		Aliases:      []mail.Alias{{ID: "t1", Match: "info", To: []string{"dest@example.com"}}},
		CatchAll:     &mail.CatchAll{ID: "catch", To: []string{"dest@example.com"}},
	}

	actions, err := provider.Plan(routingDomain(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var createAction, manualAction *plan.Action
	for i := range actions {
		switch {
		case actions[i].Op == plan.OpCreate && actions[i].Resource == "destination":
			createAction = &actions[i]
		case actions[i].Op == plan.OpManual && actions[i].Resource == "destination":
			manualAction = &actions[i]
		}
	}
	if createAction == nil || manualAction == nil {
		t.Fatalf("actions = %+v, want a create and a manual entry for the missing destination", actions)
	}
	if manualAction.Do != nil {
		t.Error("the manual entry must not be executable")
	}

	if err := createAction.Do(context.Background()); err != nil {
		t.Fatalf("create Do: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/accounts/acc-1/email/routing/addresses" {
		t.Errorf("create request = %s %s, want POST /accounts/acc-1/email/routing/addresses", got.method, got.path)
	}
	if got.body["email"] != "dest@example.com" {
		t.Errorf("email = %v, want dest@example.com", got.body["email"])
	}
}

func TestActualFillsDestinationsEvenWhenRoutingNotYetEnabled(t *testing.T) {
	// Destinations is account-scoped, so a not-yet-enabled zone must still
	// populate missing/unverified (I1); otherwise Plan's destination loop is
	// a no-op and it emits an alias rule pointing at nothing Cloudflare has
	// ever heard of.
	client, _ := serve(t, func(c *capture) string {
		switch {
		case strings.HasSuffix(c.path, "/email/routing/addresses"):
			return `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`
		case strings.HasSuffix(c.path, "/email/routing"):
			return `{"success":true,"errors":[],"result":{"enabled":false,"name":"a.com","status":"unlocked"}}`
		default:
			t.Fatalf("unexpected request to %s", c.path)
			return ""
		}
	})
	provider := &Provider{client: client, zones: stubZones{}}

	d := routingDomain()
	state, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if state.DomainExists {
		t.Fatal("DomainExists = true, want false (routing not yet enabled)")
	}
	if !provider.missing["dest@example.com"] {
		t.Error("dest@example.com should be marked missing even though routing is not yet enabled")
	}

	actions, err := provider.Plan(d, state, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var destinationIndex, aliasIndex = -1, -1
	for i, a := range actions {
		if a.Op == plan.OpCreate && a.Resource == "destination" && destinationIndex == -1 {
			destinationIndex = i
		}
		if a.Op == plan.OpCreate && a.Resource == "alias" && aliasIndex == -1 {
			aliasIndex = i
		}
	}
	if destinationIndex == -1 {
		t.Fatalf("actions = %+v, want a destination registration", actions)
	}
	if aliasIndex == -1 {
		t.Fatalf("actions = %+v, want an alias create", actions)
	}
	if destinationIndex > aliasIndex {
		t.Errorf("destination registration at %d comes after alias create at %d; it must come first", destinationIndex, aliasIndex)
	}
}

func TestPlanPrunesStaleAliasOnlyWithPrune(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}, zoneID: "z1"}
	d := routingDomain() // declares only the "info" alias

	actual := mail.State{
		DomainExists: true,
		Aliases: []mail.Alias{
			{ID: "t1", Match: "info", To: []string{"dest@example.com"}},
			{ID: "stale-tag", Match: "old", To: []string{"gone@example.com"}},
		},
		CatchAll: &mail.CatchAll{ID: "catch", To: []string{"dest@example.com"}},
	}

	withoutPrune, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range withoutPrune {
		if a.Op == plan.OpDelete && strings.Contains(a.Detail, "old") {
			t.Fatalf("actions = %+v, want the stale alias untouched without -prune", withoutPrune)
		}
	}

	withPrune, err := provider.Plan(d, actual, mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pruneAction *plan.Action
	for i := range withPrune {
		if withPrune[i].Op == plan.OpDelete && withPrune[i].Resource == "alias" && strings.Contains(withPrune[i].Detail, "old") {
			pruneAction = &withPrune[i]
		}
	}
	if pruneAction == nil {
		t.Fatalf("actions = %+v, want a delete naming the stale alias with -prune", withPrune)
	}
	if pruneAction.Do == nil {
		t.Fatal("prune delete action must be executable")
	}
}

// TestPlanNeverPrunesCatchAllOmittedFromConfig is the regression guard for
// the critical prune-deletes-a-live-catch-all bug: omitting catchAll:
// entirely means "leave whatever exists untouched" (mailctl.example.yaml,
// validate.go's own error text), not "delete it." *CatchAll is a plain
// pointer, so "never declared" and "explicitly wants none" both collapse to
// nil, and -prune must never fire on that ambiguity. routingDomain() always
// declares CatchAll, which is exactly why this branch went unexercised.
func TestPlanNeverPrunesCatchAllOmittedFromConfig(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}, zoneID: "z1"}
	d := routingDomain()
	d.CatchAll = nil // never declared, not "explicitly none"

	actual := mail.State{
		DomainExists: true,
		Aliases:      []mail.Alias{{ID: "t1", Match: "info", To: []string{"dest@example.com"}}},
		CatchAll:     &mail.CatchAll{ID: "catch", To: []string{"dest@example.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range actions {
		if a.Resource == "catchall" {
			t.Fatalf("actions = %+v, want zero catch-all actions when config omits catchAll", actions)
		}
	}
}

func TestPlanRejectsMailboxes(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}

	d := routingDomain()
	d.Mailboxes = []config.Mailbox{{Address: "box@a.com"}}

	_, err := provider.Plan(d, mail.State{DomainExists: true}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err == nil || !strings.Contains(err.Error(), "cfrouting") {
		t.Fatalf("err = %v, want a refusal naming the provider", err)
	}
}

func TestProviderIsRegistered(t *testing.T) {
	for _, name := range mail.Registered() {
		if name == "cfrouting" {
			return
		}
	}
	t.Fatal("cfrouting should register itself in an init function")
}
