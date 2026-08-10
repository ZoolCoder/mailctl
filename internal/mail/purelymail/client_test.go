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
)

// recorder captures the last request and replies with a canned body.
type recorder struct {
	path    string
	body    map[string]any
	headers http.Header
}

func serve(t *testing.T, rec *recorder, response string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec.path = r.URL.Path
		rec.headers = r.Header.Clone()
		rec.body = map[string]any{}
		json.Unmarshal(raw, &rec.body)
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "tok")
}

func TestPostSendsTokenHeaderAndPath(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`)

	got, err := client.GetOwnershipCode(context.Background())
	if err != nil {
		t.Fatalf("GetOwnershipCode: %v", err)
	}

	if rec.path != "/api/v0/getOwnershipCode" {
		t.Errorf("path = %q, want /api/v0/getOwnershipCode", rec.path)
	}
	if rec.headers.Get("Purelymail-Api-Token") != "tok" {
		t.Errorf("token header = %q, want tok", rec.headers.Get("Purelymail-Api-Token"))
	}
	if got != "purelymail_ownership_proof=abc" {
		t.Errorf("code = %q, want the ownership proof", got)
	}
}

func TestErrorBodyWithHTTP200IsAnError(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"error","code":"INVALID_DOMAIN","message":"Domain not found."}`)

	err := client.AddDomain(context.Background(), "a.com")
	if err == nil {
		t.Fatal("a 200 response carrying an error body must be an error")
	}
	if !strings.Contains(err.Error(), "INVALID_DOMAIN") || !strings.Contains(err.Error(), "Domain not found.") {
		t.Errorf("error should carry Purelymail's own code and message; got %q", err)
	}
}

func TestListDomainsDecodesDNSSummary(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"domains":[
		{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,"isShared":false,
		 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":false,"passesDmarc":false}}
	]}}`)

	domains, err := client.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if !domains[0].DNSSummary.PassesMX || domains[0].DNSSummary.PassesDKIM {
		t.Errorf("dnsSummary = %+v, want mx true and dkim false", domains[0].DNSSummary)
	}
	if rec.body["includeShared"] != false {
		t.Errorf("includeShared = %v, want false", rec.body["includeShared"])
	}
}

func TestCreateUserSendsEveryField(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.CreateUser(context.Background(), NewUser{
		UserName:             "contact",
		DomainName:           "a.com",
		Password:             "value-1",
		EnablePasswordReset:  true,
		EnableSearchIndexing: true,
		SendWelcomeEmail:     false,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if rec.path != "/api/v0/createUser" {
		t.Errorf("path = %q, want /api/v0/createUser", rec.path)
	}
	for key, want := range map[string]any{
		"userName":             "contact",
		"domainName":           "a.com",
		"enablePasswordReset":  true,
		"enableSearchIndexing": true,
		"sendWelcomeEmail":     false,
	} {
		if rec.body[key] != want {
			t.Errorf("body[%q] = %v, want %v", key, rec.body[key], want)
		}
	}
	if _, present := rec.body["password"]; !present {
		t.Error("createUser must send the credential field")
	}
}

func TestCreateRoutingRuleMapsPrefixAndCatchAll(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.CreateRoutingRule(context.Background(), RoutingRule{
		DomainName:      "a.com",
		MatchUser:       "info",
		Prefix:          true,
		TargetAddresses: []string{"contact@a.com"},
		Catchall:        false,
	})
	if err != nil {
		t.Fatalf("CreateRoutingRule: %v", err)
	}

	if rec.body["matchUser"] != "info" || rec.body["prefix"] != true || rec.body["catchall"] != false {
		t.Errorf("body = %v, want the mapped rule fields", rec.body)
	}
	targets, _ := rec.body["targetAddresses"].([]any)
	if len(targets) != 1 || targets[0] != "contact@a.com" {
		t.Errorf("targetAddresses = %v, want [contact@a.com]", rec.body["targetAddresses"])
	}
}

func TestListRoutingRulesDecodesIDs(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"rules":[
		{"id":7,"domainName":"a.com","matchUser":"info","prefix":false,"targetAddresses":["contact@a.com"],"catchall":false},
		{"id":8,"domainName":"a.com","matchUser":"","prefix":false,"targetAddresses":["contact@a.com"],"catchall":true}
	]}}`)

	rules, err := client.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("ListRoutingRules: %v", err)
	}
	if len(rules) != 2 || rules[0].ID != 7 || !rules[1].Catchall {
		t.Errorf("rules = %+v, want the two decoded rules", rules)
	}
}

func TestDeleteRoutingRuleSendsID(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	if err := client.DeleteRoutingRule(context.Background(), 7); err != nil {
		t.Fatalf("DeleteRoutingRule: %v", err)
	}
	if rec.body["routingRuleId"].(float64) != 7 {
		t.Errorf("routingRuleId = %v, want 7", rec.body["routingRuleId"])
	}
}

func TestUpsertPasswordResetSendsMethod(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.UpsertPasswordReset(context.Background(), "box@a.com", ResetMethod{
		Type:        "email",
		Target:      "fallback@example.com",
		Description: "personal",
	})
	if err != nil {
		t.Fatalf("UpsertPasswordReset: %v", err)
	}
	if rec.path != "/api/v0/upsertPasswordReset" {
		t.Errorf("path = %q, want /api/v0/upsertPasswordReset", rec.path)
	}
	if rec.body["userName"] != "box@a.com" || rec.body["type"] != "email" ||
		rec.body["target"] != "fallback@example.com" {
		t.Errorf("body = %v, want the method fields", rec.body)
	}
}

func TestListPasswordResetDecodesQuotedID(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"methods":[
		{"id":"42","type":"email","target":"fallback@example.com","description":"personal"}
	]}}`)

	methods, err := client.ListPasswordReset(context.Background(), "box@a.com")
	if err != nil {
		t.Fatalf("ListPasswordReset: %v", err)
	}
	if len(methods) != 1 || methods[0].ID.String() != "42" {
		t.Errorf("methods = %+v, want id 42", methods)
	}
}

func TestListPasswordResetDecodesUnquotedID(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"methods":[
		{"id":42,"type":"email","target":"fallback@example.com","description":"personal"}
	]}}`)

	methods, err := client.ListPasswordReset(context.Background(), "box@a.com")
	if err != nil {
		t.Fatalf("ListPasswordReset: %v, Purelymail may return id as a number, not a string", err)
	}
	if len(methods) != 1 || methods[0].ID.String() != "42" {
		t.Errorf("methods = %+v, want id 42", methods)
	}
}

func TestNetworkFailureNamesTheEndpoint(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "tok")

	err := client.AddDomain(context.Background(), "a.com")
	if err == nil || !strings.Contains(err.Error(), "addDomain") {
		t.Fatalf("err = %v, want an error naming the endpoint", err)
	}
}
