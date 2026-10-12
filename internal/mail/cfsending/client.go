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
