// Package cloudflare implements dns.Provider against the Cloudflare v4 API.
package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type Provider struct {
	api *cfapi.Client
	ttl int
}

// New returns a provider. ttl is the fallback for records that do not set their
// own; 1 means "automatic" to Cloudflare.
func New(api *cfapi.Client, ttl int) *Provider {
	if ttl == 0 {
		ttl = 1
	}
	return &Provider{api: api, ttl: ttl}
}

var _ dns.Provider = (*Provider)(nil)

type apiZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Proxied  bool   `json:"proxied"`
}

func (p *Provider) Zone(ctx context.Context, name string) (dns.Zone, error) {
	query := url.Values{}
	query.Set("name", name)

	zones, err := cfapi.List[apiZone](ctx, p.api, "/zones?"+query.Encode())
	if err != nil {
		return dns.Zone{}, fmt.Errorf("look up Cloudflare zone %s: %w", name, err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return dns.Zone{ID: z.ID, Name: z.Name}, nil
		}
	}
	return dns.Zone{}, fmt.Errorf(
		"Cloudflare zone %s was not found; check the zone name and that the API token can read it", name)
}

func (p *Provider) Records(ctx context.Context, zoneID string) ([]dns.Existing, error) {
	records, err := cfapi.List[apiRecord](ctx, p.api, "/zones/"+zoneID+"/dns_records")
	if err != nil {
		return nil, fmt.Errorf("list Cloudflare DNS records for zone %s: %w", zoneID, err)
	}

	out := make([]dns.Existing, 0, len(records))
	for _, r := range records {
		proxied := r.Proxied
		out = append(out, dns.Existing{
			ID: r.ID,
			Record: dns.Record{
				Type:     r.Type,
				Name:     r.Name,
				Content:  r.Content,
				TTL:      r.TTL,
				Priority: r.Priority,
				Proxied:  &proxied,
				Kind:     dns.KindOther,
			},
		})
	}
	return out, nil
}

func (p *Provider) Create(ctx context.Context, zoneID string, r dns.Record) error {
	ttl := r.TTL
	if ttl == 0 {
		ttl = p.ttl
	}
	payload := map[string]any{
		"type":    r.Type,
		"name":    r.Name,
		"content": r.Content,
		"ttl":     ttl,
	}
	if r.Priority > 0 {
		payload["priority"] = r.Priority
	}
	if r.Proxied != nil {
		payload["proxied"] = *r.Proxied
	}

	if err := p.api.Do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, nil); err != nil {
		return fmt.Errorf("create DNS record %s: %w", r.String(), err)
	}
	return nil
}

func (p *Provider) Delete(ctx context.Context, zoneID, recordID string) error {
	if err := p.api.Do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil); err != nil {
		return fmt.Errorf("delete DNS record %s: %w", recordID, err)
	}
	return nil
}
