package cfrouting

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

type capture struct {
	method string
	path   string
	body   map[string]any
}

func serve(t *testing.T, handler func(*capture) string) (*Client, *capture) {
	t.Helper()
	got := &capture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got.method, got.path = r.Method, r.URL.Path
		got.body = map[string]any{}
		json.Unmarshal(raw, &got.body)
		fmt.Fprint(w, handler(got))
	}))
	t.Cleanup(server.Close)
	return NewClient(cfapi.New(server.URL, "tok"), "acc-1"), got
}

func TestRequiredDNSReadsCloudflaresOwnRecords(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":[
			{"type":"MX","name":"a.com","content":"route1.mx.cloudflare.net","priority":18,"ttl":1},
			{"type":"TXT","name":"a.com","content":"v=spf1 include:_spf.mx.cloudflare.net ~all","ttl":1}
		],"result_info":{"page":1,"total_pages":1}}`
	})

	records, err := client.RequiredDNS(context.Background(), "z1")
	if err != nil {
		t.Fatalf("RequiredDNS: %v", err)
	}
	if got.path != "/zones/z1/email/routing/dns" {
		t.Errorf("path = %q", got.path)
	}
	if len(records) != 2 || records[0].Priority != 18 {
		t.Errorf("records = %+v, want the two records with priority preserved", records)
	}
}

func TestRulesDecodesMatchersAndActions(t *testing.T) {
	client, _ := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":[
			{"tag":"t1","name":"info","enabled":true,"priority":0,
			 "matchers":[{"type":"literal","field":"to","value":"info@a.com"}],
			 "actions":[{"type":"forward","value":["dest@example.com"]}]}
		],"result_info":{"page":1,"total_pages":1}}`
	})

	rules, err := client.Rules(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Tag != "t1" || rules[0].Matchers[0].Value != "info@a.com" {
		t.Errorf("rule = %+v", rules[0])
	}
	if len(rules[0].Actions[0].Value) != 1 || rules[0].Actions[0].Value[0] != "dest@example.com" {
		t.Errorf("actions = %+v", rules[0].Actions)
	}
}

func TestCreateRulePostsMatcherAndForwardAction(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"tag":"t2"}}`
	})

	err := client.CreateRule(context.Background(), "z1", Rule{
		Name:     "info",
		Enabled:  true,
		Matchers: []Matcher{{Type: "literal", Field: "to", Value: "info@a.com"}},
		Actions:  []Action{{Type: "forward", Value: []string{"dest@example.com"}}},
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	if got.method != http.MethodPost || got.path != "/zones/z1/email/routing/rules" {
		t.Errorf("%s %s, want POST /zones/z1/email/routing/rules", got.method, got.path)
	}
	matchers := got.body["matchers"].([]any)
	first := matchers[0].(map[string]any)
	if first["value"] != "info@a.com" || first["field"] != "to" {
		t.Errorf("matcher = %v", first)
	}
	actions := got.body["actions"].([]any)
	action := actions[0].(map[string]any)
	if action["type"] != "forward" {
		t.Errorf("action type = %v, want forward", action["type"])
	}
	values := action["value"].([]any)
	if len(values) != 1 || values[0] != "dest@example.com" {
		t.Errorf("action value = %v, want [dest@example.com]", values)
	}
}

func TestSetCatchAllUsesTheAllMatcher(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"tag":"catch"}}`
	})

	if err := client.SetCatchAll(context.Background(), "z1", []string{"dest@example.com"}, true); err != nil {
		t.Fatalf("SetCatchAll: %v", err)
	}

	if got.method != http.MethodPut || got.path != "/zones/z1/email/routing/rules/catch_all" {
		t.Errorf("%s %s, want PUT on the catch_all endpoint", got.method, got.path)
	}
	matchers := got.body["matchers"].([]any)
	if matchers[0].(map[string]any)["type"] != "all" {
		t.Errorf("catch-all matcher = %v, want type all", matchers[0])
	}
	if got.body["enabled"] != true {
		t.Errorf("enabled = %v, want true", got.body["enabled"])
	}
}

func TestDestinationsIsAccountScoped(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":[
			{"tag":"d1","email":"dest@example.com","verified":"2026-01-01T00:00:00Z"},
			{"tag":"d2","email":"pending@example.com","verified":null}
		],"result_info":{"page":1,"total_pages":1}}`
	})

	destinations, err := client.Destinations(context.Background())
	if err != nil {
		t.Fatalf("Destinations: %v", err)
	}
	if got.path != "/accounts/acc-1/email/routing/addresses" {
		t.Errorf("path = %q, want the account-scoped endpoint", got.path)
	}
	if len(destinations) != 2 {
		t.Fatalf("got %d destinations, want 2", len(destinations))
	}
	if !destinations[0].Verified() {
		t.Error("a destination with a verified timestamp must report verified")
	}
	if destinations[1].Verified() {
		t.Error("a destination with a null timestamp must report unverified")
	}
}

func TestEnableHitsTheEnableEndpoint(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"enabled":true}}`
	})

	if err := client.Enable(context.Background(), "z1"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/zones/z1/email/routing/enable" {
		t.Errorf("%s %s, want POST /zones/z1/email/routing/enable", got.method, got.path)
	}
}

func TestSettingsReportsEnabledState(t *testing.T) {
	client, _ := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"enabled":false,"name":"a.com","status":"unlocked"}}`
	})

	settings, err := client.Settings(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if settings.Enabled {
		t.Error("Enabled = true, want false")
	}
}

func TestDeleteRuleUsesTheCorrectMethod(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[]}`
	})

	if err := client.DeleteRule(context.Background(), "z1", "rule-tag"); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if got.method != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", got.method)
	}
	if got.path != "/zones/z1/email/routing/rules/rule-tag" {
		t.Errorf("path = %q, want /zones/z1/email/routing/rules/rule-tag", got.path)
	}
}

func TestCatchAllDecodesTheRule(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{
			"tag":"catch","name":"catch-all","enabled":true,"priority":0,
			"matchers":[{"type":"all"}],
			"actions":[{"type":"forward","value":["dest@example.com","other@example.com"]}]
		}}`
	})

	rule, err := client.CatchAll(context.Background(), "z1")
	if err != nil {
		t.Fatalf("CatchAll: %v", err)
	}
	if got.path != "/zones/z1/email/routing/rules/catch_all" {
		t.Errorf("path = %q", got.path)
	}
	if rule.Tag != "catch" {
		t.Errorf("tag = %q, want catch", rule.Tag)
	}
	if !rule.Enabled {
		t.Error("enabled = false, want true")
	}
	if len(rule.Matchers) != 1 || rule.Matchers[0].Type != "all" {
		t.Errorf("matchers = %+v, want single all matcher", rule.Matchers)
	}
	if len(rule.Actions[0].Value) != 2 || rule.Actions[0].Value[0] != "dest@example.com" {
		t.Errorf("action targets = %v, want [dest@example.com other@example.com]", rule.Actions[0].Value)
	}
}

func TestCreateDestinationPostsToAccountEndpoint(t *testing.T) {
	client, got := serve(t, func(*capture) string {
		return `{"success":true,"errors":[],"result":{"tag":"d1"}}`
	})

	if err := client.CreateDestination(context.Background(), "newdest@example.com"); err != nil {
		t.Fatalf("CreateDestination: %v", err)
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/accounts/acc-1/email/routing/addresses" {
		t.Errorf("path = %q, want /accounts/acc-1/email/routing/addresses", got.path)
	}
	if got.body["email"] != "newdest@example.com" {
		t.Errorf("email = %q, want newdest@example.com", got.body["email"])
	}
}
