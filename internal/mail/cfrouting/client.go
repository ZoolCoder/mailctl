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
// It checks for the presence of a non-empty timestamp, not its validity.
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
