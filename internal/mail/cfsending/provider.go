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

	// zoneID is cached between calls. This is safe only because the engine opens
	// a fresh provider per domain and calls DesiredDNS/Actual before Plan.
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
		case strings.EqualFold(record.Type, "TXT") &&
			strings.HasPrefix(strings.ToLower(record.Content), "v=spf1"):
			kind = dns.KindSPF
			// cfsending is outbound-only: config.publishesMX() hardcodes it as never
			// publishing MX. If an MX record reached MXHosts(), it would corrupt the
			// MTA-STS policy. Any MX from Email Sending falls through to KindOther.
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
			"Email Sending is not enabled yet; the DKIM records appear on the next run, once it is enabled")
	}
	return state, nil
}

// Plan has no prunable objects of its own: cfsending never creates mailboxes,
// aliases, or a catch-all, so -prune has nothing to discard here. mail.Options
// is unused deliberately, not by oversight (I2).
func (p *Provider) Plan(d config.Domain, actual mail.State, _ mail.Options) ([]plan.Action, error) {
	// Refuse only when cfsending is the domain's sole provider: mailboxes,
	// aliases, and a catch-all evaluated over the whole domain would wrongly
	// reject [cfrouting, cfsending] and [purelymail, cfsending], where those
	// objects belong to the other provider, not to cfsending (C2).
	if soleProvider(d, Name) && (len(d.Mailboxes) > 0 || len(d.Aliases) > 0 || d.CatchAll != nil) {
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

// soleProvider reports whether name is the only mail provider configured for
// d, mirroring config.onlyMailboxless's idea of scoping a check to what a
// provider itself owns rather than to the whole domain.
func soleProvider(d config.Domain, name string) bool {
	return len(d.Mail.Providers) == 1 && strings.EqualFold(d.Mail.Providers[0], name)
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
