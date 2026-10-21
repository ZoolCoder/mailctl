// Package resend configures Resend as an outbound-only sender for a domain.
// Resend generates the records at domain creation, so the first apply adds
// the domain and the next one publishes its DKIM and bounce records, the same
// two-step cfsending takes.
package resend

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

const Name = "resend"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		if deps.Getenv == nil {
			return nil, errors.New("resend: no environment accessor supplied")
		}
		key := deps.Getenv("RESEND_API_KEY")
		if key == "" {
			return nil, errors.New("RESEND_API_KEY is required for the resend provider (a full-access key; a sending-only key cannot manage domains)")
		}
		return &Provider{client: NewClient(deps.ResendBaseURL, key)}, nil
	})
}

type Provider struct {
	client *Client

	// domain is cached between calls. Safe because the engine opens a fresh
	// provider per domain and calls DesiredDNS/Actual before Plan.
	domain *Domain
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

// DesiredDNS returns nothing until the domain exists at Resend.
func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	domain, err := p.find(ctx, d.Name)
	if err != nil || domain == nil {
		return nil, err
	}

	out := make([]dns.Record, 0, len(domain.Records))
	for _, record := range domain.Records {
		name := qualify(record.Name, d.Name)
		kind := dns.KindOther
		switch {
		case strings.Contains(strings.ToLower(name), "._domainkey."):
			kind = dns.KindDKIM
		case strings.EqualFold(record.Type, "TXT") && strings.HasPrefix(strings.ToLower(record.Value), "v=spf1"):
			// The SPF record sits on the bounce subdomain (send.), so
			// deliver.Merge passes it through rather than folding it into
			// the apex SPF.
			kind = dns.KindSPF
			// Resend's MX also sits on send. and is for bounces only:
			// config.publishesMX() treats resend as never publishing MX, so
			// it stays KindOther and out of the MTA-STS policy.
		}
		out = append(out, dns.Record{
			Type:     strings.ToUpper(record.Type),
			Name:     name,
			Content:  record.Value,
			Priority: record.Priority,
			Kind:     kind,
		})
	}
	return out, nil
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State
	domain, err := p.find(ctx, d.Name)
	if err != nil {
		return state, err
	}
	if domain == nil {
		state.Notes = append(state.Notes,
			"the domain is not on Resend yet; its DKIM and bounce records appear on the next run, once it is added")
		return state, nil
	}
	state.DomainExists = true
	state.Verified = domain.Status == "verified"
	if !state.Verified {
		state.Notes = append(state.Notes, "Resend status: "+domain.Status)
	}
	return state, nil
}

// Plan adds the domain, then asks Resend to verify it once the records are
// published. Resend owns no mailboxes, aliases or catch-all, so -prune has
// nothing to remove here.
func (p *Provider) Plan(d config.Domain, actual mail.State, _ mail.Options) ([]plan.Action, error) {
	if soleProvider(d) && (len(d.Mailboxes) > 0 || len(d.Aliases) > 0 || d.CatchAll != nil) {
		return nil, fmt.Errorf(
			"domain %s: resend is outbound only and has no mailboxes, aliases, or catch-all; pair it with an inbound provider",
			d.Name)
	}

	name := d.Name
	if !actual.DomainExists {
		region := ""
		if d.Mail.Resend != nil {
			region = d.Mail.Resend.Region
		}
		detail := "add the domain to Resend (DKIM and bounce records appear on the next run)"
		if region != "" {
			detail += ", region " + region
		}
		return []plan.Action{{
			Op: plan.OpCreate, Resource: "domain", Domain: name, Provider: Name, Detail: detail,
			Do: func(ctx context.Context) error {
				_, err := p.client.Create(ctx, name, region)
				return err
			},
		}}, nil
	}

	if actual.Verified || p.domain == nil {
		return nil, nil
	}
	id := p.domain.ID
	return []plan.Action{{
		Op: plan.OpUpdate, Resource: "domain", Domain: name, Provider: Name,
		Detail: "ask Resend to verify the published records",
		Do:     func(ctx context.Context) error { return p.client.Verify(ctx, id) },
	}}, nil
}

// find returns the domain with its records, or nil when Resend has none by
// that name. The list omits records, so a match is fetched once more.
func (p *Provider) find(ctx context.Context, name string) (*Domain, error) {
	if p.domain != nil && strings.EqualFold(p.domain.Name, name) {
		return p.domain, nil
	}
	domains, err := p.client.Domains(ctx)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", name, err)
	}
	for _, listed := range domains {
		if !strings.EqualFold(listed.Name, name) {
			continue
		}
		full, err := p.client.Domain(ctx, listed.ID)
		if err != nil {
			return nil, fmt.Errorf("domain %s: %w", name, err)
		}
		p.domain = &full
		return p.domain, nil
	}
	return nil, nil
}

// qualify turns Resend's record name into a full name. The docs show both
// relative ("send") and full ("links.example.com") names.
func qualify(name, domain string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	switch {
	case name == "" || name == "@" || name == domain:
		return domain
	case strings.HasSuffix(name, "."+domain):
		return name
	}
	return name + "." + domain
}

func soleProvider(d config.Domain) bool {
	return len(d.Mail.Providers) == 1 && strings.EqualFold(d.Mail.Providers[0], Name)
}
