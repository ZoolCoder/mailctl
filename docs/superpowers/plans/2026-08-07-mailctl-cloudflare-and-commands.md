# mailctl Cloudflare Providers and Remaining Commands Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cloudflare Email Routing and Email Sending as first-class mail providers, then finish the command surface — `audit`, `import`, and the imperative `mailbox`/`alias`/`apppass` subcommands — and retire the old `example` tool.

**Architecture:** Both Cloudflare providers implement the same `mail.Provider` interface Purelymail already does, so the engine needs no change to support them; each fetches its own required DNS from Cloudflare's `/dns` endpoints rather than hardcoding records. `audit` deliberately bypasses the provider APIs and resolves through a real DNS resolver, because the API tells you what you asked for and not what the internet sees. `import` reads live state and prints a config block. The imperative subcommands edit the config file and then run the normal reconcile, keeping the config the source of truth.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3`, stdlib `net` resolver.

**Prerequisite:** the core plan and the deliverability plan are complete and their tests pass.

**Spec:** `docs/superpowers/specs/2026-08-07-mailctl-design.md`, sections "Cloudflare Email Routing", "Cloudflare Email Sending", "Declarative and imperative boundary", and "Commands".

## Global Constraints

- Neither Cloudflare provider hosts mailboxes. A config pairing one with a `mailboxes:` block already fails validation (core plan, Task 2); these providers must not silently accept one either.
- Creating a Cloudflare destination address sends a verification email a human must click. `apply` creates the address and reports it as `MANUAL`; it never blocks or polls.
- App credentials are shown exactly once and cannot be listed. They stay out of the reconciled config and live only behind `mailctl apppass`.
- The imperative subcommands write the config file. They must preserve comments — use `yaml.Node` editing, never marshal-and-overwrite.
- Before every commit: `gofmt -l .` prints nothing, `go vet ./...` passes, `go test ./...` passes.
- No live API calls in the test suite.

## File structure

```
internal/mail/cfrouting/client.go     routing REST calls
internal/mail/cfrouting/provider.go   mail.Provider implementation
internal/mail/cfsending/client.go     sending REST calls
internal/mail/cfsending/provider.go   mail.Provider implementation
internal/audit/audit.go               resolver-backed checks and report
internal/importer/importer.go         live state -> YAML config block
internal/configedit/edit.go           comment-preserving config mutations
cmd/mailctl/main.go                   (modified) new subcommands
```

---

### Task 1: Cloudflare Email Routing client

**Files:**
- Create: `internal/mail/cfrouting/client.go`
- Test: `internal/mail/cfrouting/client_test.go`

**Interfaces:**
- Consumes: `cfapi.Client`, `cfapi.List`.
- Produces: `cfrouting.NewClient(api *cfapi.Client, accountID string) *Client` with methods `Settings(ctx, zoneID) (Settings, error)`, `Enable(ctx, zoneID) error`, `RequiredDNS(ctx, zoneID) ([]DNSRecord, error)`, `Rules(ctx, zoneID) ([]Rule, error)`, `CreateRule(ctx, zoneID string, r Rule) error`, `DeleteRule(ctx, zoneID, tag string) error`, `CatchAll(ctx, zoneID) (Rule, error)`, `SetCatchAll(ctx, zoneID string, targets []string, enabled bool) error`, `Destinations(ctx) ([]Destination, error)`, `CreateDestination(ctx, email string) error`. Task 2 consumes all of it.

**Shape of a routing rule.** Cloudflare models a rule as matchers plus actions, not as a
local part plus targets:

```json
{"tag":"abc","name":"info","enabled":true,"priority":0,
 "matchers":[{"type":"literal","field":"to","value":"info@a.com"}],
 "actions":[{"type":"forward","value":["dest@example.com"]}]}
```

The catch-all rule uses `{"type":"all"}` as its single matcher and lives at its own
endpoint. The provider in Task 2 translates between this and `mail.Alias`.

- [ ] **Step 1: Write the failing test**

Create `internal/mail/cfrouting/client_test.go`:

```go
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/mail/cfrouting/ -v`
Expected: FAIL — `undefined: NewClient`.

- [ ] **Step 3: Implement the client**

Create `internal/mail/cfrouting/client.go`:

```go
// Package cfrouting talks to Cloudflare Email Routing and implements
// mail.Provider on top of it.
package cfrouting

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

type Client struct {
	api       *cfapi.Client
	accountID string
}

func NewClient(api *cfapi.Client, accountID string) *Client {
	return &Client{api: api, accountID: accountID}
}

type Settings struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	Status  string `json:"status"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
}

type Matcher struct {
	Type  string `json:"type"`            // literal | all
	Field string `json:"field,omitempty"` // to
	Value string `json:"value,omitempty"`
}

type Action struct {
	Type  string   `json:"type"` // forward | worker | drop
	Value []string `json:"value"`
}

type Rule struct {
	Tag      string    `json:"tag,omitempty"`
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	Priority int       `json:"priority"`
	Matchers []Matcher `json:"matchers"`
	Actions  []Action  `json:"actions"`
}

type Destination struct {
	Tag        string  `json:"tag"`
	Email      string  `json:"email"`
	VerifiedAt *string `json:"verified"`
}

// Verified reports whether the human has clicked the verification link.
// Cloudflare will not deliver to an unverified destination.
func (d Destination) Verified() bool { return d.VerifiedAt != nil && *d.VerifiedAt != "" }

func (c *Client) Settings(ctx context.Context, zoneID string) (Settings, error) {
	var out Settings
	if err := c.api.Do(ctx, http.MethodGet, "/zones/"+zoneID+"/email/routing", nil, &out); err != nil {
		return Settings{}, fmt.Errorf("read Email Routing settings: %w", err)
	}
	return out, nil
}

func (c *Client) Enable(ctx context.Context, zoneID string) error {
	if err := c.api.Do(ctx, http.MethodPost, "/zones/"+zoneID+"/email/routing/enable", map[string]any{}, nil); err != nil {
		return fmt.Errorf("enable Email Routing: %w", err)
	}
	return nil
}

// RequiredDNS asks Cloudflare which records Email Routing needs, rather than
// hardcoding a list that changes when Cloudflare rotates its MX hosts.
func (c *Client) RequiredDNS(ctx context.Context, zoneID string) ([]DNSRecord, error) {
	records, err := cfapi.List[DNSRecord](ctx, c.api, "/zones/"+zoneID+"/email/routing/dns")
	if err != nil {
		return nil, fmt.Errorf("read Email Routing required DNS: %w", err)
	}
	return records, nil
}

func (c *Client) Rules(ctx context.Context, zoneID string) ([]Rule, error) {
	rules, err := cfapi.List[Rule](ctx, c.api, "/zones/"+zoneID+"/email/routing/rules")
	if err != nil {
		return nil, fmt.Errorf("list Email Routing rules: %w", err)
	}
	return rules, nil
}

func (c *Client) CreateRule(ctx context.Context, zoneID string, r Rule) error {
	if err := c.api.Do(ctx, http.MethodPost, "/zones/"+zoneID+"/email/routing/rules", r, nil); err != nil {
		return fmt.Errorf("create Email Routing rule %s: %w", r.Name, err)
	}
	return nil
}

func (c *Client) DeleteRule(ctx context.Context, zoneID, tag string) error {
	if err := c.api.Do(ctx, http.MethodDelete, "/zones/"+zoneID+"/email/routing/rules/"+tag, nil, nil); err != nil {
		return fmt.Errorf("delete Email Routing rule %s: %w", tag, err)
	}
	return nil
}

func (c *Client) CatchAll(ctx context.Context, zoneID string) (Rule, error) {
	var out Rule
	if err := c.api.Do(ctx, http.MethodGet, "/zones/"+zoneID+"/email/routing/rules/catch_all", nil, &out); err != nil {
		return Rule{}, fmt.Errorf("read Email Routing catch-all: %w", err)
	}
	return out, nil
}

func (c *Client) SetCatchAll(ctx context.Context, zoneID string, targets []string, enabled bool) error {
	payload := Rule{
		Name:     "catch-all",
		Enabled:  enabled,
		Matchers: []Matcher{{Type: "all"}},
		Actions:  []Action{{Type: "forward", Value: targets}},
	}
	if err := c.api.Do(ctx, http.MethodPut, "/zones/"+zoneID+"/email/routing/rules/catch_all", payload, nil); err != nil {
		return fmt.Errorf("set Email Routing catch-all: %w", err)
	}
	return nil
}

func (c *Client) Destinations(ctx context.Context) ([]Destination, error) {
	destinations, err := cfapi.List[Destination](ctx, c.api, "/accounts/"+c.accountID+"/email/routing/addresses")
	if err != nil {
		return nil, fmt.Errorf("list Email Routing destination addresses: %w", err)
	}
	return destinations, nil
}

// CreateDestination adds a forwarding target. Cloudflare emails a verification
// link that a human must click before delivery works.
func (c *Client) CreateDestination(ctx context.Context, email string) error {
	payload := map[string]any{"email": email}
	if err := c.api.Do(ctx, http.MethodPost, "/accounts/"+c.accountID+"/email/routing/addresses", payload, nil); err != nil {
		return fmt.Errorf("add Email Routing destination %s: %w", email, err)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/mail/cfrouting/ -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/cfrouting/client.go internal/mail/cfrouting/client_test.go
git commit -m "feat(cfrouting): add email routing api client"
```

---

### Task 2: Cloudflare Email Routing as a mail provider

**Files:**
- Create: `internal/mail/cfrouting/provider.go`
- Test: `internal/mail/cfrouting/provider_test.go`

**Interfaces:**
- Consumes: Task 1's client, `mail.Provider`, `mail.State`, `dns.Record`, `plan.Action`.
- Produces: `cfrouting.Provider` implementing `mail.Provider`, registered as `"cfrouting"`.

**Zone ID.** `mail.Provider` methods receive a `config.Domain`, not a zone ID, and this
provider needs one for every call. Resolve it inside the provider by giving the factory
the `dns.Provider` from `mail.Deps`. Add one field to `mail.Deps` in
`internal/mail/registry.go`:

```go
	// Zones resolves a zone name to a zone ID. Providers whose API is
	// zone-scoped need it; Purelymail ignores it.
	Zones dns.Provider
```

and pass `cfdns.New(api, cfg.Cloudflare.TTL)` into it from `cmd/mailctl/main.go` — the
same value already handed to `engine.New`.

- [ ] **Step 1: Write the failing test**

Create `internal/mail/cfrouting/provider_test.go`:

```go
package cfrouting

import (
	"context"
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/mail/cfrouting/ -run TestDesired -v`
Expected: FAIL — `undefined: Provider`.

- [ ] **Step 3: Implement the provider**

Create `internal/mail/cfrouting/provider.go`:

```go
package cfrouting

import (
	"context"
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

const Name = "cfrouting"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		if deps.Cloudflare == nil {
			return nil, fmt.Errorf("cfrouting needs a Cloudflare API client")
		}
		if deps.AccountID == "" {
			return nil, fmt.Errorf("cfrouting needs cloudflare.accountId in the config")
		}
		if deps.Zones == nil {
			return nil, fmt.Errorf("cfrouting needs a DNS provider to resolve zone ids")
		}
		return &Provider{
			client: NewClient(deps.Cloudflare, deps.AccountID),
			zones:  deps.Zones,
		}, nil
	})
}

type Provider struct {
	client *Client
	zones  dns.Provider

	// zoneID and unverified are filled in by Actual and read by Plan, which
	// performs no I/O of its own.
	zoneID     string
	unverified map[string]bool
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) zone(ctx context.Context, d config.Domain) (string, error) {
	if p.zoneID != "" {
		return p.zoneID, nil
	}
	zone, err := p.zones.Zone(ctx, d.ZoneName)
	if err != nil {
		return "", fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.zoneID = zone.ID
	return zone.ID, nil
}

// DesiredDNS asks Cloudflare what Email Routing needs rather than hardcoding
// hosts that Cloudflare rotates.
func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	zoneID, err := p.zone(ctx, d)
	if err != nil {
		return nil, err
	}
	required, err := p.client.RequiredDNS(ctx, zoneID)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	out := make([]dns.Record, 0, len(required))
	for _, record := range required {
		out = append(out, dns.Record{
			Type:     record.Type,
			Name:     record.Name,
			Content:  record.Content,
			Priority: record.Priority,
			TTL:      record.TTL,
			Kind:     kindOf(record),
		})
	}
	return out, nil
}

func kindOf(record DNSRecord) dns.Kind {
	switch {
	case strings.EqualFold(record.Type, "MX"):
		return dns.KindMX
	case strings.EqualFold(record.Type, "TXT") &&
		strings.HasPrefix(strings.ToLower(record.Content), "v=spf1"):
		return dns.KindSPF
	case strings.Contains(strings.ToLower(record.Name), "._domainkey."):
		return dns.KindDKIM
	default:
		return dns.KindOther
	}
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State

	zoneID, err := p.zone(ctx, d)
	if err != nil {
		return state, err
	}

	settings, err := p.client.Settings(ctx, zoneID)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	state.DomainExists = settings.Enabled
	if !settings.Enabled {
		return state, nil
	}

	rules, err := p.client.Rules(ctx, zoneID)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	suffix := "@" + d.Name
	for _, rule := range rules {
		match, ok := literalLocalPart(rule, suffix)
		if !ok {
			continue
		}
		state.Aliases = append(state.Aliases, mail.Alias{
			ID:    rule.Tag,
			Match: match,
			To:    forwardTargets(rule),
		})
	}

	catchAll, err := p.client.CatchAll(ctx, zoneID)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if catchAll.Enabled {
		state.CatchAll = &mail.CatchAll{ID: catchAll.Tag, To: forwardTargets(catchAll)}
	}

	destinations, err := p.client.Destinations(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.unverified = map[string]bool{}
	known := map[string]bool{}
	for _, destination := range destinations {
		known[strings.ToLower(destination.Email)] = true
		if !destination.Verified() {
			p.unverified[strings.ToLower(destination.Email)] = true
			state.Notes = append(state.Notes,
				"destination "+destination.Email+" is not verified")
		}
	}
	for _, target := range d.AllTargets() {
		if !known[strings.ToLower(target)] {
			p.unverified[strings.ToLower(target)] = true
		}
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, _ mail.Options) ([]plan.Action, error) {
	if len(d.Mailboxes) > 0 {
		return nil, fmt.Errorf(
			"domain %s: cfrouting forwards mail but does not host mailboxes; remove the mailboxes block",
			d.Name)
	}

	var actions []plan.Action
	zoneID := p.zoneID

	if !actual.DomainExists {
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "enable Email Routing",
			Do: func(ctx context.Context) error {
				return p.client.Enable(ctx, zoneID)
			},
		})
	}

	// A destination that is missing or unverified is a human step, reported and
	// never blocked on.
	for _, target := range d.AllTargets() {
		if !p.unverified[strings.ToLower(target)] {
			continue
		}
		target := target
		actions = append(actions, plan.Action{
			Op:       plan.OpManual,
			Resource: "destination",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "verify " + target + " by clicking the link Cloudflare emails to it",
		})
	}

	for _, want := range d.Aliases {
		existing, found := actual.Alias(want.MatchUser(), false)
		if found && sameTargets(existing.To, want.To) {
			continue
		}
		if found {
			tag := existing.ID
			actions = append(actions, plan.Action{
				Op:       plan.OpDelete,
				Resource: "alias",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "replace alias " + want.Match + " (targets changed)",
				Do: func(ctx context.Context) error {
					return p.client.DeleteRule(ctx, zoneID, tag)
				},
			})
		}
		rule := Rule{
			Name:     want.Match,
			Enabled:  true,
			Matchers: []Matcher{{Type: "literal", Field: "to", Value: want.MatchUser() + "@" + d.Name}},
			Actions:  []Action{{Type: "forward", Value: want.To}},
		}
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("alias %s -> %s", want.Match, strings.Join(want.To, ", ")),
			Do: func(ctx context.Context) error {
				return p.client.CreateRule(ctx, zoneID, rule)
			},
		})
	}

	if d.CatchAll != nil && (actual.CatchAll == nil || !sameTargets(actual.CatchAll.To, d.CatchAll.To)) {
		targets := d.CatchAll.To
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "catchall",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "catch-all -> " + strings.Join(targets, ", "),
			Do: func(ctx context.Context) error {
				return p.client.SetCatchAll(ctx, zoneID, targets, true)
			},
		})
	}
	return actions, nil
}

// literalLocalPart extracts the local part from a literal to-matcher whose
// value belongs to this domain.
func literalLocalPart(rule Rule, suffix string) (string, bool) {
	for _, matcher := range rule.Matchers {
		if !strings.EqualFold(matcher.Type, "literal") || !strings.EqualFold(matcher.Field, "to") {
			continue
		}
		value := strings.ToLower(matcher.Value)
		if !strings.HasSuffix(value, strings.ToLower(suffix)) {
			continue
		}
		return strings.TrimSuffix(value, strings.ToLower(suffix)), true
	}
	return "", false
}

func forwardTargets(rule Rule) []string {
	for _, action := range rule.Actions {
		if strings.EqualFold(action.Type, "forward") {
			return action.Value
		}
	}
	return nil
}

func sameTargets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[strings.ToLower(v)]++
	}
	for _, v := range b {
		key := strings.ToLower(v)
		seen[key]--
		if seen[key] < 0 {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Add the `AllTargets` helper to config**

Append to `internal/config/config.go`:

```go
// AllTargets returns every address this domain forwards to, deduplicated.
// Cloudflare Email Routing requires each of them to be a verified destination.
func (d Domain) AllTargets() []string {
	var out []string
	seen := map[string]bool{}
	add := func(list []string) {
		for _, address := range list {
			key := strings.ToLower(address)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, address)
		}
	}
	for _, alias := range d.Aliases {
		add(alias.To)
	}
	if d.CatchAll != nil {
		add(d.CatchAll.To)
	}
	return out
}
```

- [ ] **Step 5: Register the provider in the CLI and pass the zone resolver**

In `cmd/mailctl/main.go`, add the blank import and the new `Deps` field:

```go
	_ "github.com/zoolcoder/mailctl/internal/mail/cfrouting"
```

```go
	zones := cfdns.New(api, cfg.Cloudflare.TTL)

	runner := engine.New(cfg, zones, deployer, mail.Deps{
		Cloudflare:        api,
		AccountID:         cfg.Cloudflare.AccountID,
		PurelymailBaseURL: cfg.Purelymail.BaseURL,
		Zones:             zones,
		Getenv:            os.Getenv,
	}, engine.Options{ /* unchanged */ })
```

- [ ] **Step 6: Run the tests and verify they pass**

Run: `go test ./... -v`
Expected: PASS everywhere, including `TestKnownProvidersMatchRegistry` — `cfrouting` is
already in `config.KnownProviders` from the core plan.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/cfrouting/provider.go internal/mail/cfrouting/provider_test.go \
        internal/mail/registry.go internal/config/config.go cmd/mailctl/main.go
git commit -m "feat(cfrouting): reconcile routing rules and catch-all"
```

---

### Task 3: Cloudflare Email Sending

**Files:**
- Create: `internal/mail/cfsending/client.go`
- Create: `internal/mail/cfsending/provider.go`
- Test: `internal/mail/cfsending/cfsending_test.go`

**Interfaces:**
- Consumes: `cfapi.Client`, `cfapi.List`, `mail.Provider`, `dns.Provider`.
- Produces: `cfsending.NewClient(api *cfapi.Client) *Client` with `Subdomains(ctx, zoneID) ([]Subdomain, error)`, `Enable(ctx, zoneID, name string) (Subdomain, error)`, `Disable(ctx, zoneID, id string) error`, `RequiredDNS(ctx, zoneID, id string) ([]DNSRecord, error)`; and `cfsending.Provider` registered as `"cfsending"`.

Email Sending is outbound only. It has no mailboxes, no aliases, and no catch-all, so its
`Plan` produces at most one action: enable the sending subdomain. Its DNS contribution is
the DKIM and return-path records Cloudflare generates, fetched rather than constructed.

- [ ] **Step 1: Write the failing test**

Create `internal/mail/cfsending/cfsending_test.go`:

```go
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
		io.Copy(io.Discard, r.Body)
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

func TestPlanRejectsMailboxesAndAliases(t *testing.T) {
	provider := &Provider{client: nil, zones: stubZones{}}

	d := sendingDomain()
	d.Aliases = []config.Alias{{Match: "info", To: []string{"x@example.com"}}}

	_, err := provider.Plan(d, mail.State{DomainExists: true}, mail.Options{Secrets: secret.NewResolver(nil)})
	if err == nil || !strings.Contains(err.Error(), "cfsending") {
		t.Fatalf("err = %v, want a refusal naming the provider; cfsending is outbound only", err)
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/mail/cfsending/ -v`
Expected: FAIL — `undefined: NewClient`.

- [ ] **Step 3: Implement the client**

Create `internal/mail/cfsending/client.go`:

```go
// Package cfsending talks to Cloudflare Email Sending. It is outbound only:
// no mailboxes, no aliases, no catch-all.
package cfsending

import (
	"context"
	"fmt"
	"net/http"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

type Client struct {
	api *cfapi.Client
}

func NewClient(api *cfapi.Client) *Client { return &Client{api: api} }

type Subdomain struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Priority int    `json:"priority"`
	TTL      int    `json:"ttl"`
}

func (c *Client) path(zoneID string) string {
	return "/zones/" + zoneID + "/email/sending/subdomains"
}

func (c *Client) Subdomains(ctx context.Context, zoneID string) ([]Subdomain, error) {
	subdomains, err := cfapi.List[Subdomain](ctx, c.api, c.path(zoneID))
	if err != nil {
		return nil, fmt.Errorf("list Email Sending subdomains: %w", err)
	}
	return subdomains, nil
}

func (c *Client) Enable(ctx context.Context, zoneID, name string) (Subdomain, error) {
	var out Subdomain
	if err := c.api.Do(ctx, http.MethodPost, c.path(zoneID), map[string]any{"name": name}, &out); err != nil {
		return Subdomain{}, fmt.Errorf("enable Email Sending for %s: %w", name, err)
	}
	return out, nil
}

func (c *Client) Disable(ctx context.Context, zoneID, id string) error {
	if err := c.api.Do(ctx, http.MethodDelete, c.path(zoneID)+"/"+id, nil, nil); err != nil {
		return fmt.Errorf("disable Email Sending subdomain %s: %w", id, err)
	}
	return nil
}

func (c *Client) RequiredDNS(ctx context.Context, zoneID, id string) ([]DNSRecord, error) {
	records, err := cfapi.List[DNSRecord](ctx, c.api, c.path(zoneID)+"/"+id+"/dns")
	if err != nil {
		return nil, fmt.Errorf("read Email Sending required DNS: %w", err)
	}
	return records, nil
}
```

- [ ] **Step 4: Implement the provider**

Create `internal/mail/cfsending/provider.go`:

```go
package cfsending

import (
	"context"
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

const Name = "cfsending"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		if deps.Cloudflare == nil {
			return nil, fmt.Errorf("cfsending needs a Cloudflare API client")
		}
		if deps.Zones == nil {
			return nil, fmt.Errorf("cfsending needs a DNS provider to resolve zone ids")
		}
		return &Provider{client: NewClient(deps.Cloudflare), zones: deps.Zones}, nil
	})
}

type Provider struct {
	client *Client
	zones  dns.Provider

	zoneID string
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) zone(ctx context.Context, d config.Domain) (string, error) {
	if p.zoneID != "" {
		return p.zoneID, nil
	}
	zone, err := p.zones.Zone(ctx, d.ZoneName)
	if err != nil {
		return "", fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.zoneID = zone.ID
	return zone.ID, nil
}

// DesiredDNS returns nothing until sending is enabled: Cloudflare generates the
// DKIM selector at enable time, so the first apply enables and the second
// publishes the records. The plan output says so rather than looking converged.
func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	zoneID, err := p.zone(ctx, d)
	if err != nil {
		return nil, err
	}
	subdomain, found, err := p.find(ctx, zoneID, d.Name)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}

	required, err := p.client.RequiredDNS(ctx, zoneID, subdomain.ID)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	out := make([]dns.Record, 0, len(required))
	for _, record := range required {
		kind := dns.KindOther
		switch {
		case strings.Contains(strings.ToLower(record.Name), "._domainkey."):
			kind = dns.KindDKIM
		case strings.EqualFold(record.Type, "MX"):
			kind = dns.KindMX
		case strings.EqualFold(record.Type, "TXT") &&
			strings.HasPrefix(strings.ToLower(record.Content), "v=spf1"):
			kind = dns.KindSPF
		}
		out = append(out, dns.Record{
			Type:     record.Type,
			Name:     record.Name,
			Content:  record.Content,
			Priority: record.Priority,
			TTL:      record.TTL,
			Kind:     kind,
		})
	}
	return out, nil
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State

	zoneID, err := p.zone(ctx, d)
	if err != nil {
		return state, err
	}
	subdomain, found, err := p.find(ctx, zoneID, d.Name)
	if err != nil {
		return state, err
	}
	state.DomainExists = found && subdomain.Enabled
	if !state.DomainExists {
		state.Notes = append(state.Notes,
			"Email Sending is not enabled yet; the DKIM records appear on the next run, after it is")
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, _ mail.Options) ([]plan.Action, error) {
	if len(d.Mailboxes) > 0 || len(d.Aliases) > 0 || d.CatchAll != nil {
		return nil, fmt.Errorf(
			"domain %s: cfsending is outbound only and has no mailboxes, aliases, or catch-all; pair it with cfrouting for inbound mail",
			d.Name)
	}
	if actual.DomainExists {
		return nil, nil
	}

	zoneID, name := p.zoneID, d.Name
	return []plan.Action{{
		Op:       plan.OpCreate,
		Resource: "domain",
		Domain:   d.Name,
		Provider: Name,
		Detail:   "enable Email Sending (DKIM records appear on the next run)",
		Do: func(ctx context.Context) error {
			_, err := p.client.Enable(ctx, zoneID, name)
			return err
		},
	}}, nil
}

func (p *Provider) find(ctx context.Context, zoneID, name string) (Subdomain, bool, error) {
	subdomains, err := p.client.Subdomains(ctx, zoneID)
	if err != nil {
		return Subdomain{}, false, fmt.Errorf("domain %s: %w", name, err)
	}
	for _, subdomain := range subdomains {
		if strings.EqualFold(subdomain.Name, name) {
			return subdomain, true, nil
		}
	}
	return Subdomain{}, false, nil
}
```

- [ ] **Step 5: Register it in the CLI**

Add to the blank imports in `cmd/mailctl/main.go`:

```go
	_ "github.com/zoolcoder/mailctl/internal/mail/cfsending"
```

- [ ] **Step 6: Run the tests and verify they pass**

Run: `go test ./... -v`
Expected: PASS everywhere.

- [ ] **Step 7: Confirm the Email Sending endpoints against the live API**

Email Sending is the newest of the three providers and its paths were taken from docs,
not from an observed response. Confirm the shape with a read-only call against any zone
you own:

```bash
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/email/sending/subdomains" \
  | python3 -m json.tool
```

Expected: `success: true` and a `result` array whose objects carry `id`, `name`, and
`enabled`. A 404 on the path means the account does not have Email Sending; that is not a
bug in `mailctl`, and the provider only runs for a domain whose config names it. If the
field names differ, update `Subdomain` and the literals in
`TestSubdomainsListsEnabledState` together.

- [ ] **Step 8: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/cfsending/ cmd/mailctl/main.go
git commit -m "feat(cfsending): add email sending provider"
```

---

### Task 4: The audit command

**Files:**
- Create: `internal/audit/audit.go`
- Test: `internal/audit/audit_test.go`
- Modify: `cmd/mailctl/main.go`

**Interfaces:**
- Consumes: `config.Domain`, `dns.Record`, `deliver.Merge`, `mail.State`.
- Produces: `audit.Resolver` interface (`LookupMX`, `LookupTXT`, `LookupCNAME`), `audit.NetResolver()` returning the stdlib-backed implementation, `audit.Fetcher` (`Get(ctx, url string) (string, error)`), `audit.Run(ctx, d config.Domain, desired []dns.Record, r Resolver, f Fetcher) Report`, `audit.Report{Checks []Check, Notes []string}`, `audit.Check{Name, Want, Got string, OK bool}`, `(Report).Render(io.Writer)`, `(Report).OK() bool`.

**Why a real resolver.** The Cloudflare API reports what you asked it to publish.
Whether the internet can see it is a different question — a proxied record, a
DNSSEC failure, or a zone that is not actually delegated all produce a passing API read
and a failing lookup. `audit` answers the second question.

- [ ] **Step 1: Write the failing test**

Create `internal/audit/audit_test.go`:

```go
package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type fakeResolver struct {
	mx    map[string][]string
	txt   map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupMX(_ context.Context, name string) ([]string, error) {
	hosts, ok := f.mx[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return hosts, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	values, ok := f.txt[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return values, nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	target, ok := f.cname[name]
	if !ok {
		return "", errors.New("no such host")
	}
	return target, nil
}

type fakeFetcher struct {
	bodies map[string]string
}

func (f fakeFetcher) Get(_ context.Context, url string) (string, error) {
	body, ok := f.bodies[url]
	if !ok {
		return "", errors.New("404")
	}
	return body, nil
}

func desiredRecords() []dns.Record {
	return []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject; pct=100", Kind: dns.KindDMARC},
		{Type: "CNAME", Name: "purelymail1._domainkey.a.com", Content: "key1.dkimroot.purelymail.com", Kind: dns.KindDKIM},
		{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=abc123", Kind: dns.KindMTASts},
	}
}

func healthyResolver() fakeResolver {
	return fakeResolver{
		mx:  map[string][]string{"a.com": {"mailserver.purelymail.com"}},
		txt: map[string][]string{
			"a.com":          {"v=spf1 include:_spf.purelymail.com ~all"},
			"_dmarc.a.com":   {"v=DMARC1; p=reject; pct=100"},
			"_mta-sts.a.com": {"v=STSv1; id=abc123"},
		},
		cname: map[string]string{"purelymail1._domainkey.a.com": "key1.dkimroot.purelymail.com."},
	}
}

func TestRunPassesWhenEverythingResolves(t *testing.T) {
	fetcher := fakeFetcher{bodies: map[string]string{
		"https://mta-sts.a.com/.well-known/mta-sts.txt": "version: STSv1\nmode: enforce\nmx: mailserver.purelymail.com\nmax_age: 604800\n",
	}}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), healthyResolver(), fetcher)

	if !report.OK() {
		var failures []string
		for _, check := range report.Checks {
			if !check.OK {
				failures = append(failures, check.Name+": got "+check.Got)
			}
		}
		t.Fatalf("report should pass; failures: %s", strings.Join(failures, "; "))
	}
	if len(report.Checks) != 6 {
		t.Errorf("got %d checks, want 5 records plus the policy fetch", len(report.Checks))
	}
}

func TestRunFlagsAMissingRecord(t *testing.T) {
	resolver := healthyResolver()
	delete(resolver.txt, "_dmarc.a.com")

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	if report.OK() {
		t.Fatal("a missing DMARC record must fail the audit")
	}
	found := false
	for _, check := range report.Checks {
		if strings.Contains(check.Name, "_dmarc") && !check.OK {
			found = true
		}
	}
	if !found {
		t.Errorf("no failing check names _dmarc:\n%+v", report.Checks)
	}
}

func TestRunFlagsDriftedContent(t *testing.T) {
	resolver := healthyResolver()
	resolver.txt["a.com"] = []string{"v=spf1 include:_spf.someone-else.com ~all"}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	for _, check := range report.Checks {
		if check.Name == "TXT a.com" {
			if check.OK {
				t.Error("a different SPF value published must fail")
			}
			if !strings.Contains(check.Got, "someone-else") {
				t.Errorf("the check must show what is actually published; got %q", check.Got)
			}
			return
		}
	}
	t.Fatal("no SPF check present")
}

func TestRunFlagsMultipleSPFRecords(t *testing.T) {
	resolver := healthyResolver()
	resolver.txt["a.com"] = []string{
		"v=spf1 include:_spf.purelymail.com ~all",
		"v=spf1 include:other.com ~all",
	}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	if report.OK() {
		t.Fatal("two SPF records on one name is a hard failure and the audit must say so")
	}
	joined := strings.Join(report.Notes, " ")
	if !strings.Contains(joined, "SPF") {
		t.Errorf("notes should explain the duplicate SPF problem; got %v", report.Notes)
	}
}

func TestRunChecksTheMTAStsPolicyIsServed(t *testing.T) {
	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(),
		healthyResolver(), fakeFetcher{})

	for _, check := range report.Checks {
		if strings.Contains(check.Name, "mta-sts policy") {
			if check.OK {
				t.Error("an unreachable policy endpoint must fail")
			}
			return
		}
	}
	t.Fatal("no policy-fetch check present")
}

func TestRenderShowsFailuresFirst(t *testing.T) {
	resolver := healthyResolver()
	delete(resolver.txt, "_dmarc.a.com")

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	var out strings.Builder
	report.Render(&out)
	rendered := out.String()

	if !strings.Contains(rendered, "FAIL") || !strings.Contains(rendered, "_dmarc") {
		t.Errorf("render should mark the failure:\n%s", rendered)
	}
	if strings.Index(rendered, "FAIL") > strings.Index(rendered, "ok  ") {
		t.Error("failures should be listed before passes so they are not scrolled past")
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/audit/ -v`
Expected: FAIL — `undefined: Run`.

- [ ] **Step 3: Implement the audit**

Create `internal/audit/audit.go`:

```go
// Package audit checks published DNS through a real resolver rather than
// through the provider API, because the API reports what you asked for and not
// what the internet sees.
package audit

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
}

type Fetcher interface {
	Get(ctx context.Context, url string) (string, error)
}

type Check struct {
	Name string
	Want string
	Got  string
	OK   bool
}

type Report struct {
	Domain string
	Checks []Check
	Notes  []string
}

func (r Report) OK() bool {
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return true
}

// Render writes failures first; a long list of passes should not hide the one
// line that matters.
func (r Report) Render(w io.Writer) {
	fmt.Fprintf(w, "\naudit %s\n", r.Domain)

	ordered := make([]Check, len(r.Checks))
	copy(ordered, r.Checks)
	sort.SliceStable(ordered, func(i, j int) bool { return !ordered[i].OK && ordered[j].OK })

	for _, check := range ordered {
		if check.OK {
			fmt.Fprintf(w, "  ok    %s\n", check.Name)
			continue
		}
		fmt.Fprintf(w, "  FAIL  %s\n          want %s\n          got  %s\n", check.Name, check.Want, orNone(check.Got))
	}
	for _, note := range r.Notes {
		fmt.Fprintf(w, "  note  %s\n", note)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(nothing published)"
	}
	return s
}

// Run resolves every desired record and, when MTA-STS is configured, fetches
// the policy endpoint.
func Run(ctx context.Context, d config.Domain, desired []dns.Record, resolver Resolver, fetcher Fetcher) Report {
	report := Report{Domain: d.Name}
	spfCount := 0

	for _, want := range desired {
		check := Check{Name: want.Type + " " + want.Name, Want: want.Content}

		switch strings.ToUpper(want.Type) {
		case "MX":
			hosts, err := resolver.LookupMX(ctx, want.Name)
			check.Got = strings.Join(hosts, ", ")
			check.OK = err == nil && containsHost(hosts, want.Content)
		case "TXT":
			values, err := resolver.LookupTXT(ctx, want.Name)
			check.Got = strings.Join(values, " | ")
			check.OK = err == nil && containsExact(values, want.Content)
			if want.Kind == dns.KindSPF {
				spfCount = countSPF(values)
			}
		case "CNAME":
			target, err := resolver.LookupCNAME(ctx, want.Name)
			check.Got = target
			check.OK = err == nil && equalHost(target, want.Content)
		default:
			check.Got = "unchecked record type"
			check.OK = true
		}
		report.Checks = append(report.Checks, check)
	}

	if spfCount > 1 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d SPF records are published on %s; RFC 7208 requires exactly one, and receivers treat more as a permanent error",
			spfCount, d.Name))
		markFailed(&report, "TXT "+d.Name)
	}

	if d.Deliverability.MTASts != nil && d.Deliverability.MTASts.Mode != "" && d.Deliverability.MTASts.Mode != "none" {
		url := "https://mta-sts." + d.Name + "/.well-known/mta-sts.txt"
		body, err := fetcher.Get(ctx, url)
		check := Check{Name: "mta-sts policy at " + url, Want: "a text/plain STSv1 policy"}
		if err != nil {
			check.Got = err.Error()
		} else {
			check.Got = firstLine(body)
			check.OK = strings.Contains(body, "version: STSv1")
		}
		report.Checks = append(report.Checks, check)
	}

	return report
}

func markFailed(report *Report, name string) {
	for i := range report.Checks {
		if report.Checks[i].Name == name {
			report.Checks[i].OK = false
		}
	}
}

func countSPF(values []string) int {
	n := 0
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "v=spf1") {
			n++
		}
	}
	return n
}

func containsHost(hosts []string, want string) bool {
	for _, host := range hosts {
		if equalHost(host, want) {
			return true
		}
	}
	return false
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func equalHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

func firstLine(s string) string {
	if index := strings.IndexByte(s, '\n'); index >= 0 {
		return s[:index]
	}
	return s
}

// NetResolver returns a Resolver backed by the system resolver.
func NetResolver() Resolver { return netResolver{r: net.DefaultResolver} }

type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	records, err := n.r.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, record.Host)
	}
	return hosts, nil
}

func (n netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}

func (n netResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	return n.r.LookupCNAME(ctx, name)
}

// HTTPFetcher returns a Fetcher backed by net/http.
func HTTPFetcher() Fetcher {
	return httpFetcher{client: &http.Client{Timeout: 15 * time.Second}}
}

type httpFetcher struct{ client *http.Client }

func (h httpFetcher) Get(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return string(body), nil
}
```

- [ ] **Step 4: Expose the desired record set from the engine**

`audit` needs the same desired records `plan` computes. Add to
`internal/engine/engine.go`:

```go
// Desired returns the DNS records mailctl wants published for a domain,
// without reading the zone or planning anything. audit uses it.
func (e *Engine) Desired(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	var desired []dns.Record
	for _, name := range d.Mail.Providers {
		provider, err := mail.Open(name, e.deps)
		if err != nil {
			return nil, fmt.Errorf("domain %s: %w", d.Name, err)
		}
		records, err := provider.DesiredDNS(ctx, d)
		if err != nil {
			return nil, err
		}
		desired = append(desired, records...)
	}
	merged, err := deliver.Merge(d, desired)
	if err != nil {
		return nil, err
	}
	return merged.Records, nil
}

// Domains returns the domains this run covers, honouring -domain.
func (e *Engine) Domains() ([]config.Domain, error) { return e.selectedDomains() }
```

- [ ] **Step 5: Wire the subcommand**

In `cmd/mailctl/main.go`, move `audit` out of the not-built-yet list into the accepted
set alongside `plan` and `apply`, and add this branch after the plan is not needed:

```go
	if command == "audit" {
		domains, err := runner.Domains()
		if err != nil {
			return err
		}
		failed := false
		for _, d := range domains {
			desired, err := runner.Desired(ctx, d)
			if err != nil {
				return err
			}
			report := audit.Run(ctx, d, desired, audit.NetResolver(), audit.HTTPFetcher())
			report.Render(os.Stdout)
			if !report.OK() {
				failed = true
			}
		}
		if failed {
			return errors.New("audit found problems")
		}
		return nil
	}
```

Place it before the `runner.Plan(ctx)` call so `audit` never reads the zone. Add
`"github.com/zoolcoder/mailctl/internal/audit"` to the imports.

- [ ] **Step 6: Run the tests and audit the live domain**

```bash
go test ./... && go build -o mailctl ./cmd/mailctl
./mailctl audit -domain example.com
```

Expected: every check `ok`. A failing DKIM CNAME check usually means the record is
proxied — Cloudflare answers a proxied CNAME with its own addresses, so the lookup
returns something else. Fix by setting the record to DNS-only.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/audit/ internal/engine/engine.go cmd/mailctl/main.go
git commit -m "feat(audit): verify published dns through a real resolver"
```

---

### Task 5: The import command

**Files:**
- Create: `internal/importer/importer.go`
- Test: `internal/importer/importer_test.go`
- Modify: `cmd/mailctl/main.go`

**Interfaces:**
- Consumes: `mail.State`, `config.Domain`.
- Produces: `importer.Render(domain, zoneName, provider string, state mail.State) (string, error)`. `cmd/mailctl` calls it and prints the result.

`import` reads live provider state and prints a YAML block the operator can paste into
their config, so an existing domain can be adopted without hand-writing it. It prints;
it never edits a file. Credentials cannot be read back from any provider, so every
imported mailbox gets a `passwordEnv` placeholder and a comment saying so.

- [ ] **Step 1: Write the failing test**

Create `internal/importer/importer_test.go`:

```go
package importer

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/mail"
	"gopkg.in/yaml.v3"
)

func liveState() mail.State {
	return mail.State{
		DomainExists: true,
		Settings:     mail.Settings{AllowAccountReset: true},
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com", Recovery: []mail.Recovery{
				{Type: "email", Target: "fallback@example.com", Description: "personal"},
			}},
			{Address: "sales@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}
}

func TestRenderProducesParseableConfig(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The rendered block is a domains entry, so wrap it to parse it whole.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Fatalf("rendered config does not parse:\n%s\nerror: %v", full, err)
	}

	if len(cfg.Domains) != 1 {
		t.Fatalf("parsed %d domains, want 1", len(cfg.Domains))
	}
	d := cfg.Domains[0]
	if d.Name != "a.com" || len(d.Mail.Providers) != 1 || d.Mail.Providers[0] != "purelymail" {
		t.Errorf("domain = %+v", d)
	}
	if len(d.Mailboxes) != 2 {
		t.Errorf("mailboxes = %+v, want both", d.Mailboxes)
	}
	if len(d.Aliases) != 1 || d.Aliases[0].Match != "info" {
		t.Errorf("aliases = %+v", d.Aliases)
	}
	if d.CatchAll == nil || len(d.CatchAll.To) != 1 {
		t.Errorf("catchAll = %+v", d.CatchAll)
	}
}

func TestRenderGivesEveryMailboxAPasswordEnvPlaceholder(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !strings.Contains(got, "MAILCTL_CONTACT_A_COM_PASSWORD") {
		t.Errorf("expected a derived placeholder variable name:\n%s", got)
	}
	if !strings.Contains(got, "cannot be read back") {
		t.Errorf("the block should say why the placeholder is there:\n%s", got)
	}
}

func TestRenderCarriesRecoveryMethods(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "fallback@example.com") || !strings.Contains(got, "type: email") {
		t.Errorf("recovery methods missing:\n%s", got)
	}
}

func TestRenderOmitsEmptySections(t *testing.T) {
	got, err := Render("a.com", "a.com", "cfrouting", mail.State{DomainExists: true})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, absent := range []string{"mailboxes:", "aliases:", "catchAll:"} {
		if strings.Contains(got, absent) {
			t.Errorf("empty section %q should be omitted:\n%s", absent, got)
		}
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/importer/ -v`
Expected: FAIL — `undefined: Render`.

- [ ] **Step 3: Implement the importer**

Create `internal/importer/importer.go`:

```go
// Package importer turns live provider state into a YAML config block, so an
// existing domain can be adopted without hand-writing it.
package importer

import (
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/mail"
)

// Render returns a domains-list entry describing the live state. The caller
// prints it; nothing here writes a file.
func Render(domain, zoneName, provider string, state mail.State) (string, error) {
	if !state.DomainExists {
		return "", fmt.Errorf("domain %s does not exist at provider %s; there is nothing to import", domain, provider)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "- name: %s\n", domain)
	if zoneName != "" && zoneName != domain {
		fmt.Fprintf(&b, "  zoneName: %s\n", zoneName)
	}
	fmt.Fprintf(&b, "  mail:\n    provider: %s\n", provider)
	if state.Settings.AllowAccountReset || state.Settings.SymbolicSubaddressing {
		fmt.Fprintf(&b, "    settings:\n")
		fmt.Fprintf(&b, "      allowAccountReset: %t\n", state.Settings.AllowAccountReset)
		fmt.Fprintf(&b, "      symbolicSubaddressing: %t\n", state.Settings.SymbolicSubaddressing)
	}

	if len(state.Mailboxes) > 0 {
		fmt.Fprintf(&b, "\n  # Credentials cannot be read back from any provider. Set each variable\n")
		fmt.Fprintf(&b, "  # below to the credential already in use, or delete the passwordEnv line\n")
		fmt.Fprintf(&b, "  # to have mailctl generate a new one on the next apply.\n")
		fmt.Fprintf(&b, "  mailboxes:\n")
		for _, box := range state.Mailboxes {
			fmt.Fprintf(&b, "    - address: %s\n", box.Address)
			fmt.Fprintf(&b, "      passwordEnv: %s\n", placeholderVar(box.Address))
			if len(box.Recovery) > 0 {
				fmt.Fprintf(&b, "      recovery:\n")
				for _, method := range box.Recovery {
					fmt.Fprintf(&b, "        - type: %s\n          target: %s\n", method.Type, method.Target)
					if method.Description != "" {
						fmt.Fprintf(&b, "          description: %s\n", method.Description)
					}
				}
			}
		}
	}

	if len(state.Aliases) > 0 {
		fmt.Fprintf(&b, "\n  aliases:\n")
		for _, alias := range state.Aliases {
			match := alias.Match
			if alias.Prefix {
				match += "*"
			}
			fmt.Fprintf(&b, "    - match: %s\n      to: [%s]\n", match, strings.Join(alias.To, ", "))
		}
	}

	if state.CatchAll != nil {
		fmt.Fprintf(&b, "\n  catchAll:\n    to: [%s]\n", strings.Join(state.CatchAll.To, ", "))
	}

	return b.String(), nil
}

// placeholderVar derives an environment variable name from an address:
// contact@a.com becomes MAILCTL_CONTACT_A_COM_PASSWORD.
func placeholderVar(address string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, address)
	return "MAILCTL_" + strings.ToUpper(cleaned) + "_PASSWORD"
}
```

- [ ] **Step 4: Wire the subcommand**

`import` needs a domain that is not in the config yet, so it cannot go through
`engine.Domains`. In `cmd/mailctl/main.go`, handle it before the config-driven path:

```go
	if command == "import" {
		if len(domains) != 1 {
			return errors.New("import needs exactly one -domain")
		}
		name := domains[0]

		providerName := *importProvider
		if providerName == "" {
			return errors.New("import needs -provider (purelymail, cfrouting, or cfsending)")
		}
		zoneName := *importZone
		if zoneName == "" {
			zoneName = name
		}

		provider, err := mail.Open(providerName, deps)
		if err != nil {
			return err
		}
		stub := config.Domain{Name: name, ZoneName: zoneName,
			Mail: config.Mail{Providers: []string{providerName}}}

		state, err := provider.Actual(ctx, stub)
		if err != nil {
			return err
		}
		block, err := importer.Render(name, zoneName, providerName, state)
		if err != nil {
			return err
		}
		fmt.Print(block)
		return nil
	}
```

Add the two flags next to the others:

```go
	importProvider := flags.String("provider", "", "provider to import from (import only)")
	importZone := flags.String("zone", "", "Cloudflare zone name (import only, defaults to the domain)")
```

Hoist the `mail.Deps` literal into a `deps` variable so both this branch and
`engine.New` use it. Move `import` out of the not-built-yet list, and add
`"github.com/zoolcoder/mailctl/internal/importer"` to the imports.

`import` still loads the config file, because it needs `cloudflare.accountId` and the
base URLs. A domain absent from that config is fine — nothing here looks it up.

- [ ] **Step 5: Run the tests and import the live domain**

```bash
go test ./... && go build -o mailctl ./cmd/mailctl
./mailctl import -domain example.com -provider purelymail
```

Expected: a YAML block listing the four mailboxes and any routing rules. Diff it against
the hand-written `mailctl.yaml` — a difference is either something the hand-written
config missed or an importer bug, and both are worth knowing.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/importer/ cmd/mailctl/main.go
git commit -m "feat(import): print a config block from live provider state"
```

---

### Task 6: Imperative subcommands

**Files:**
- Create: `internal/configedit/edit.go`
- Test: `internal/configedit/edit_test.go`
- Modify: `cmd/mailctl/main.go`

**Interfaces:**
- Consumes: `gopkg.in/yaml.v3` node API.
- Produces: `configedit.AddMailbox(path, domain, address, passwordEnv string) error`, `configedit.RemoveMailbox(path, domain, address string) error`, `configedit.AddAlias(path, domain, match string, to []string) error`, `configedit.RemoveAlias(path, domain, match string) error`.

**Why node editing.** Unmarshalling into `config.Config` and re-marshalling would silently
delete every comment in the file, including the ones `import` writes explaining the
credential placeholders. Editing the `yaml.Node` tree preserves them.

**`mailctl mailbox passwd`** is deliberately not implemented as a config edit: a
credential never belongs in the config file. It calls `modifyUser` directly with a value
from `-password-env`, or generates one and reports it once.

- [ ] **Step 1: Write the failing test**

Create `internal/configedit/edit_test.go`:

```go
package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const startingConfig = `version: 1

domains:
  # our main domain
  - name: a.com
    mail:
      provider: purelymail
    mailboxes:
      - address: contact@a.com
        passwordEnv: CONTACT_PW
`

func write(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(startingConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(body)
}

func TestAddMailboxPreservesComments(t *testing.T) {
	path := write(t)

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}

	got := read(t, path)
	if !strings.Contains(got, "# our main domain") {
		t.Errorf("comments must survive an edit:\n%s", got)
	}
	if !strings.Contains(got, "sales@a.com") || !strings.Contains(got, "SALES_PW") {
		t.Errorf("new mailbox missing:\n%s", got)
	}
	if !strings.Contains(got, "contact@a.com") {
		t.Errorf("existing mailbox must survive:\n%s", got)
	}
}

func TestAddMailboxRejectsADuplicate(t *testing.T) {
	path := write(t)

	err := AddMailbox(path, "a.com", "contact@a.com", "OTHER_PW")
	if err == nil || !strings.Contains(err.Error(), "contact@a.com") {
		t.Fatalf("err = %v, want a duplicate error naming the address", err)
	}
}

func TestAddMailboxRejectsAnUnknownDomain(t *testing.T) {
	path := write(t)

	err := AddMailbox(path, "b.com", "x@b.com", "PW")
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming the missing domain", err)
	}
}

func TestRemoveMailbox(t *testing.T) {
	path := write(t)

	if err := RemoveMailbox(path, "a.com", "contact@a.com"); err != nil {
		t.Fatalf("RemoveMailbox: %v", err)
	}
	if strings.Contains(read(t, path), "contact@a.com") {
		t.Errorf("mailbox should be gone:\n%s", read(t, path))
	}
}

func TestRemoveMailboxRejectsAMissingAddress(t *testing.T) {
	path := write(t)

	err := RemoveMailbox(path, "a.com", "nope@a.com")
	if err == nil || !strings.Contains(err.Error(), "nope@a.com") {
		t.Fatalf("err = %v, want an error naming the address", err)
	}
}

func TestAddAliasCreatesTheSectionWhenAbsent(t *testing.T) {
	path := write(t)

	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	got := read(t, path)
	if !strings.Contains(got, "aliases:") || !strings.Contains(got, "match: info") {
		t.Errorf("alias section missing:\n%s", got)
	}
}

func TestRemoveAlias(t *testing.T) {
	path := write(t)
	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	if err := RemoveAlias(path, "a.com", "info"); err != nil {
		t.Fatalf("RemoveAlias: %v", err)
	}
	if strings.Contains(read(t, path), "match: info") {
		t.Errorf("alias should be gone:\n%s", read(t, path))
	}
}

func TestEditsRoundTripThroughYAML(t *testing.T) {
	path := write(t)

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}
	if err := AddAlias(path, "a.com", "info", []string{"sales@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	// The result must still be a config the loader accepts.
	if _, err := loadForTest(path); err != nil {
		t.Fatalf("edited config no longer loads: %v\n%s", err, read(t, path))
	}
}
```

Add this helper at the bottom of the test file, importing `"github.com/zoolcoder/mailctl/internal/config"`:

```go
func loadForTest(path string) (config.Config, error) {
	return config.Load(path, func(string) string { return "x" })
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/configedit/ -v`
Expected: FAIL — `undefined: AddMailbox`.

- [ ] **Step 3: Implement the editor**

Create `internal/configedit/edit.go`:

```go
// Package configedit makes small, comment-preserving changes to a mailctl
// config file. It edits the YAML node tree rather than round-tripping through
// the config structs, which would delete every comment in the file.
package configedit

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// AddMailbox appends a mailbox to a domain.
func AddMailbox(path, domain, address, passwordEnv string) error {
	return edit(path, func(d *yaml.Node) error {
		list := ensureSequence(d, "mailboxes")
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "address"), address) {
				return fmt.Errorf("mailbox %s is already in the config for %s", address, domain)
			}
		}

		entry := mapping(
			"address", address,
		)
		if passwordEnv != "" {
			appendPair(entry, "passwordEnv", passwordEnv)
		}
		list.Content = append(list.Content, entry)
		return nil
	}, domain)
}

// RemoveMailbox drops a mailbox from a domain. It does not delete the mailbox
// at the provider; that happens on the next apply with -prune.
func RemoveMailbox(path, domain, address string) error {
	return edit(path, func(d *yaml.Node) error {
		list := findSequence(d, "mailboxes")
		if list == nil {
			return fmt.Errorf("domain %s has no mailboxes block", domain)
		}
		kept := list.Content[:0]
		found := false
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "address"), address) {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			return fmt.Errorf("mailbox %s is not in the config for %s", address, domain)
		}
		list.Content = kept
		return nil
	}, domain)
}

// AddAlias appends an alias to a domain.
func AddAlias(path, domain, match string, to []string) error {
	return edit(path, func(d *yaml.Node) error {
		list := ensureSequence(d, "aliases")
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "match"), match) {
				return fmt.Errorf("alias %s is already in the config for %s", match, domain)
			}
		}

		entry := mapping("match", match)
		targets := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, address := range to {
			targets.Content = append(targets.Content, scalar(address))
		}
		entry.Content = append(entry.Content, scalar("to"), targets)
		list.Content = append(list.Content, entry)
		return nil
	}, domain)
}

// RemoveAlias drops an alias from a domain.
func RemoveAlias(path, domain, match string) error {
	return edit(path, func(d *yaml.Node) error {
		list := findSequence(d, "aliases")
		if list == nil {
			return fmt.Errorf("domain %s has no aliases block", domain)
		}
		kept := list.Content[:0]
		found := false
		for _, item := range list.Content {
			if strings.EqualFold(scalarField(item, "match"), match) {
				found = true
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			return fmt.Errorf("alias %s is not in the config for %s", match, domain)
		}
		list.Content = kept
		return nil
	}, domain)
}

// edit loads the file, hands the requested domain's mapping node to mutate, and
// writes the result back with the original permissions.
func edit(path string, mutate func(domain *yaml.Node) error, domainName string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	if len(doc.Content) == 0 {
		return fmt.Errorf("config %s is empty", path)
	}
	root := doc.Content[0]

	domains := findSequence(root, "domains")
	if domains == nil {
		return fmt.Errorf("config %s has no domains list", path)
	}
	var target *yaml.Node
	for _, item := range domains.Content {
		if strings.EqualFold(scalarField(item, "name"), domainName) {
			target = item
			break
		}
	}
	if target == nil {
		return fmt.Errorf("domain %s is not in %s", domainName, path)
	}

	if err := mutate(target); err != nil {
		return err
	}

	var out strings.Builder
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		return fmt.Errorf("render config %s: %w", path, err)
	}
	if err := encoder.Close(); err != nil {
		return fmt.Errorf("render config %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(out.String()), info.Mode().Perm()); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

func findSequence(mappingNode *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mappingNode.Content); i += 2 {
		if mappingNode.Content[i].Value == key {
			return mappingNode.Content[i+1]
		}
	}
	return nil
}

func ensureSequence(mappingNode *yaml.Node, key string) *yaml.Node {
	if existing := findSequence(mappingNode, key); existing != nil {
		return existing
	}
	list := &yaml.Node{Kind: yaml.SequenceNode}
	mappingNode.Content = append(mappingNode.Content, scalar(key), list)
	return list
}

func scalarField(mappingNode *yaml.Node, key string) string {
	for i := 0; i+1 < len(mappingNode.Content); i += 2 {
		if mappingNode.Content[i].Value == key {
			return mappingNode.Content[i+1].Value
		}
	}
	return ""
}

func scalar(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func mapping(pairs ...string) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode}
	for i := 0; i+1 < len(pairs); i += 2 {
		appendPair(node, pairs[i], pairs[i+1])
	}
	return node
}

func appendPair(mappingNode *yaml.Node, key, value string) {
	mappingNode.Content = append(mappingNode.Content, scalar(key), scalar(value))
}
```

- [ ] **Step 4: Run the editor tests and verify they pass**

Run: `go test ./internal/configedit/ -v`
Expected: PASS (8 tests).

- [ ] **Step 5: Wire the subcommands**

In `cmd/mailctl/main.go`, replace the not-built-yet branch for `mailbox`, `alias`, and
`apppass` with real handling. The pattern for all of them: edit or call, then run the
normal reconcile so the config stays the source of truth.

```go
	switch command {
	case "mailbox":
		verb, rest := shift(flags.Args())
		address := firstOrEmpty(rest)
		if address == "" {
			return errors.New("usage: mailctl mailbox add|rm|passwd <address>")
		}
		domainName := domainOf(address)

		switch verb {
		case "add":
			if err := configedit.AddMailbox(*configPath, domainName, address, *passwordEnv); err != nil {
				return err
			}
		case "rm":
			if err := configedit.RemoveMailbox(*configPath, domainName, address); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr,
				"Removed from the config. The mailbox still exists at the provider; run apply -prune to delete it and its mail.")
			return nil
		case "passwd":
			return changePassword(ctx, cfg, deps, address, *passwordEnv, secrets, *secretsOut)
		default:
			return fmt.Errorf("unknown mailbox verb %q; want add, rm, or passwd", verb)
		}

	case "alias":
		verb, rest := shift(flags.Args())
		match := firstOrEmpty(rest)
		if match == "" || *aliasDomain == "" {
			return errors.New("usage: mailctl alias add|rm <local-part> -domain <domain> [-to a@b.com]")
		}
		switch verb {
		case "add":
			if len(aliasTargets) == 0 {
				return errors.New("alias add needs at least one -to address")
			}
			if err := configedit.AddAlias(*configPath, *aliasDomain, match, aliasTargets); err != nil {
				return err
			}
		case "rm":
			if err := configedit.RemoveAlias(*configPath, *aliasDomain, match); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr,
				"Removed from the config. The rule still exists at the provider; run apply -prune to delete it.")
			return nil
		default:
			return fmt.Errorf("unknown alias verb %q; want add or rm", verb)
		}

	case "apppass":
		return appPassword(ctx, cfg, flags.Args(), *secretsOut)
	}

	// mailbox add and alias add fall through here: reload the edited config and
	// apply it, so the change reaches the provider in the same command.
	cfg, err = config.Load(*configPath, os.Getenv)
	if err != nil {
		return err
	}
	command = "apply"
```

Add these helpers at the bottom of `main.go`:

```go
func shift(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

func firstOrEmpty(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return strings.ToLower(args[0])
}

func domainOf(address string) string {
	_, domain, _ := strings.Cut(address, "@")
	return strings.ToLower(domain)
}

// changePassword sets a new credential on an existing mailbox. A credential
// never goes in the config file, so this bypasses configedit entirely.
func changePassword(ctx context.Context, cfg config.Config, deps mail.Deps,
	address, passwordEnv string, secrets *secret.Resolver, secretsOut string) error {

	domainName := domainOf(address)
	d, ok := cfg.Domain(domainName)
	if !ok {
		return fmt.Errorf("domain %s is not in the config", domainName)
	}
	if len(d.Mail.Providers) != 1 || d.Mail.Providers[0] != purelymail.Name {
		return fmt.Errorf("changing a credential is only supported for the purelymail provider")
	}

	token := os.Getenv("PURELYMAIL_API_TOKEN")
	if token == "" {
		return errors.New("PURELYMAIL_API_TOKEN is required")
	}
	credential, err := secrets.Password(domainName, config.Mailbox{Address: address, PasswordEnv: passwordEnv})
	if err != nil {
		return err
	}

	client := purelymail.NewClient(cfg.Purelymail.BaseURL, token)
	if err := client.ModifyUser(ctx, purelymail.UserChanges{UserName: address, NewPassword: &credential}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Credential changed for %s\n", address)

	if generated := secrets.Generated(); len(generated) > 0 {
		if secretsOut != "" {
			return secret.WriteFile(secretsOut, generated)
		}
		return secret.ReportTo(os.Stderr, generated)
	}
	return nil
}

// appPassword creates or deletes an application credential. These are shown
// once and cannot be listed, which is why they are not part of the config.
func appPassword(ctx context.Context, cfg config.Config, args []string, secretsOut string) error {
	verb, rest := shift(args)
	address := firstOrEmpty(rest)
	if address == "" {
		return errors.New("usage: mailctl apppass create|rm <address> [-name label]")
	}

	token := os.Getenv("PURELYMAIL_API_TOKEN")
	if token == "" {
		return errors.New("PURELYMAIL_API_TOKEN is required")
	}
	client := purelymail.NewClient(cfg.Purelymail.BaseURL, token)

	switch verb {
	case "create":
		credential, err := client.CreateAppPassword(ctx, address, appPassName)
		if err != nil {
			return err
		}
		generated := map[string]string{address + " (app)": credential}
		if secretsOut != "" {
			fmt.Fprintf(os.Stderr, "Wrote the app credential to %s\n", secretsOut)
			return secret.WriteFile(secretsOut, generated)
		}
		return secret.ReportTo(os.Stderr, generated)
	case "rm":
		if appPassName == "" {
			return errors.New("apppass rm needs -name")
		}
		return client.DeleteAppPassword(ctx, address, appPassName)
	default:
		return fmt.Errorf("unknown apppass verb %q; want create or rm", verb)
	}
}
```

Add the remaining flags alongside the existing ones:

```go
	passwordEnv := flags.String("password-env", "", "environment variable holding the credential (mailbox add|passwd)")
	aliasDomain := flags.String("alias-domain", "", "domain the alias belongs to (alias add|rm)")
	appPassNameFlag := flags.String("name", "", "app credential label (apppass)")
	flags.Var(&aliasTargets, "to", "alias target address; repeat for several")
```

with `aliasTargets` declared as another `domainList`, and `appPassName` assigned from
`*appPassNameFlag` after `flags.Parse`. Extend the `usage` constant to document all of
it, and remove `mailbox`, `alias`, and `apppass` from the not-built-yet list.

- [ ] **Step 6: Exercise each subcommand end to end**

```bash
go build -o mailctl ./cmd/mailctl

./mailctl alias add support -alias-domain example.com -to contact@example.com
./mailctl plan -domain example.com      # expect: no changes, the add already applied
./mailctl alias rm support -alias-domain example.com
./mailctl apply -domain example.com -prune
```

Expected: the alias appears at the provider after the first command, and the `-prune`
apply asks you to type `example.com` before removing it.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/configedit/ cmd/mailctl/main.go
git commit -m "feat(cli): add mailbox, alias, and apppass subcommands"
```

---

### Task 7: Retire the old tool

**Files:**
- Delete: `../legacy-mailsetup/cmd/mailsetup/`
- Delete: `../legacy-mailsetup/internal/mailsetup/`
- Delete: `../legacy-mailsetup/mailsetup.example.json`
- Delete: `../legacy-mailsetup/mailsetup.example.env`
- Delete: `../legacy-mailsetup/go.mod`

**This is the last task for a reason.** The old tool is the only working reference for
what the live Purelymail state should look like. Deleting it before `mailctl` is proven
against the live domain would remove the fallback.

- [ ] **Step 1: Confirm mailctl is genuinely converged first**

```bash
cd the repository root
./mailctl plan  -domain example.com   # expect: no changes
./mailctl audit -domain example.com   # expect: every check ok
```

Do not proceed unless both are clean. If either is not, that is the work; deleting the
old tool does not make it go away.

- [ ] **Step 2: Check nothing else in the example repo references the old tool**

```bash
cd ../legacy-mailsetup
grep -rn "mailsetup" . --exclude-dir=.git
```

Expected hits: only the files being deleted, plus the three `.gitignore` lines. If a
script, CI job, or Makefile target calls `mailsetup`, update it to invoke `mailctl`
before deleting anything.

- [ ] **Step 3: Delete the old tool**

```bash
cd ../legacy-mailsetup
rm -rf cmd/mailsetup internal/mailsetup
rm -f mailsetup.example.json mailsetup.example.env go.mod
rmdir cmd internal 2>/dev/null || true
```

`go.mod` goes too: `module legacy-mailsetup` existed only for this tool, and the
example repo is a website, not a Go module.

- [ ] **Step 4: Clean up the gitignore**

Remove the three now-meaningless lines from `../legacy-mailsetup/.gitignore`:

```
mailsetup
mailsetup.json
```

Keep `.env`.

- [ ] **Step 5: Confirm the repo is clean**

```bash
cd ../legacy-mailsetup
grep -rn "mailsetup" . --exclude-dir=.git    # expect no output
ls                                            # expect no cmd/, internal/, or go.mod
```

- [ ] **Step 6: Record the move in the mailctl repo**

```bash
cd the repository root
git commit --allow-empty -m "chore: supersede example mailsetup"
```

The example directory is not a git repository, so the deletion cannot be committed
there. The empty commit here is the record that the migration completed.

---

## Self-review

**Spec coverage.** Cloudflare Email Routing with settings, required DNS fetched from
Cloudflare, rules, catch-all, and account-scoped destinations (Tasks 1–2); Cloudflare
Email Sending with subdomain enable, list, disable, and required DNS (Task 3); both
providers refusing a `mailboxes:` block with a message naming the provider (Tasks 2 and
3); destination verification surfaced as `MANUAL` and never blocked on (Task 2);
`audit` resolving through a real resolver, checking every desired record plus the
MTA-STS policy endpoint, and flagging duplicate SPF records (Task 4); `import` printing
an adoptable config block (Task 5); `mailbox`, `alias`, and `apppass` as comment-preserving
config edits followed by the normal reconcile, with credentials kept out of the config
(Task 6); the old tool removed only after the new one is proven (Task 7).

Two spec items land differently than written, deliberately: `audit` reports Purelymail's
`dnsSummary` through the provider's existing `State.Notes`, which `plan` already renders,
rather than duplicating a Purelymail-specific call inside `audit` — keeping `audit`
provider-agnostic is worth more than the one extra line. And `checkAccountCredit` is
called by nothing; it is implemented and tested in the core plan, and wiring it into
`audit` would make `audit` Purelymail-aware for a single informational number. Add it to
`plan`'s notes in the Purelymail provider if it turns out to be wanted.

**Placeholder scan.** No TBDs. The two uncertain API surfaces — the Workers custom-domain
list shape and the Email Sending subdomain shape — each have a verification step naming
the exact structs and test literals to change together (deliverability plan Task 5 Step
10; this plan Task 3 Step 7).

**Type consistency.** `mail.Deps` gains `Zones dns.Provider` in Task 2 and is used by
Task 3's factory with the same name. `cfrouting.Rule`/`Matcher`/`Action` are identical
between Tasks 1 and 2. `audit.Resolver` and `audit.Fetcher` match between the fakes in
Task 4's test and the stdlib implementations in the same task. `configedit`'s four
exported functions match their call sites in Task 6.

**Known soft spot.** Task 2's `Provider` carries `zoneID` and `unverified` as fields set
by `Actual` and read by `Plan`. That is state on a value the registry hands out, and it
only works because the engine calls `Actual` before `Plan` for each domain and opens a
fresh provider per domain. Both hold today (core plan, Task 10). If a future change opens
one provider and reuses it across domains, this breaks silently — the second domain would
plan against the first domain's zone. If that change is ever made, move these two fields
into `mail.State` instead.
