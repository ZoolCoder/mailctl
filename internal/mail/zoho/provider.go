// Package zoho configures Zoho Mail for a domain through the Zoho Mail
// organisation API, signed in with an OAuth self-client refresh token.
//
// Zoho issues the ownership code when the domain is added and only accepts
// mail once the domain is verified, so a new domain takes three runs: add
// it, publish the ownership TXT and verify (enabling hosting and creating a
// DKIM key in the same step), then publish MX, SPF and DKIM.
package zoho

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

const Name = "zoho"

// dkimSelector is the selector mailctl creates a key under.
const dkimSelector = "zmail"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		if deps.Getenv == nil {
			return nil, errors.New("zoho: no environment accessor supplied")
		}
		creds := Credentials{
			ClientID:     deps.Getenv("ZOHO_CLIENT_ID"),
			ClientSecret: deps.Getenv("ZOHO_CLIENT_SECRET"),
			RefreshToken: deps.Getenv("ZOHO_REFRESH_TOKEN"),
			OrgID:        deps.Getenv("ZOHO_ORG_ID"),
		}
		if creds.ClientID == "" || creds.ClientSecret == "" || creds.RefreshToken == "" {
			return nil, errors.New("ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET and ZOHO_REFRESH_TOKEN are required for the zoho provider")
		}
		return &Provider{deps: deps, creds: creds}, nil
	})
}

type Provider struct {
	deps  mail.Deps
	creds Credentials

	// client and region are set on first use, from the domain's
	// mail.zoho.region; the engine opens a fresh provider per domain.
	client *Client
	region Region

	// domain and accounts are cached by Actual for Plan, which does no I/O.
	domain   *Domain
	accounts []Account
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) open(d config.Domain) *Client {
	if p.client != nil {
		return p.client
	}
	key := "com"
	if d.Mail.Zoho != nil && d.Mail.Zoho.Region != "" {
		key = d.Mail.Zoho.Region
	}
	p.region = Regions[key]
	apiURL, accountsURL := p.region.API, p.region.Accounts
	if p.deps.ZohoBaseURL != "" {
		apiURL = p.deps.ZohoBaseURL
	}
	if p.deps.ZohoAccountsURL != "" {
		accountsURL = p.deps.ZohoAccountsURL
	}
	p.client = NewClient(apiURL, accountsURL, p.creds)
	return p.client
}

func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	domain, err := p.find(ctx, d)
	if err != nil || domain == nil {
		return nil, err
	}

	records := []dns.Record{{
		Type: "TXT", Name: d.Name, Kind: dns.KindOwnership,
		Content: "zoho-verification=" + domain.CNAMEVerification + ".zmverify." + p.region.Mail,
	}}
	// MX waits for verification: Zoho bounces mail for a domain it has not
	// verified, so switching MX earlier would lose mail.
	if !domain.Verified {
		return records, nil
	}
	records = append(records,
		dns.Record{Type: "MX", Name: d.Name, Content: "mx." + p.region.Mail, Priority: 10, Kind: dns.KindMX},
		dns.Record{Type: "MX", Name: d.Name, Content: "mx2." + p.region.Mail, Priority: 20, Kind: dns.KindMX},
		dns.Record{Type: "MX", Name: d.Name, Content: "mx3." + p.region.Mail, Priority: 50, Kind: dns.KindMX},
		dns.Record{Type: "TXT", Name: d.Name, Content: "v=spf1 include:" + p.region.Mail + " ~all", Kind: dns.KindSPF},
	)
	for _, key := range domain.DKIM {
		if key.Selector == "" || key.PublicKey == "" {
			continue
		}
		records = append(records, dns.Record{
			Type: "TXT", Name: key.Selector + "._domainkey." + d.Name, Content: key.PublicKey, Kind: dns.KindDKIM,
		})
	}
	return records, nil
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State
	domain, err := p.find(ctx, d)
	if err != nil {
		return state, err
	}
	if domain == nil {
		state.Notes = append(state.Notes, "the domain is not in the Zoho organisation yet; its ownership TXT appears on the next run")
		return state, nil
	}
	state.DomainExists = true
	state.Verified = bool(domain.Verified)
	if !state.Verified {
		state.Notes = append(state.Notes, "domain not verified at Zoho; mailboxes, aliases and the catch-all wait until it is")
		return state, nil
	}
	state.Notes = append(state.Notes, fmt.Sprintf("Zoho DNS check: mx=%t spf=%t hosting=%t",
		domain.MXStatus, domain.SPFStatus, domain.MailHostingEnabled))

	accounts, err := p.open(d).Accounts(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.accounts = accounts
	suffix := "@" + strings.ToLower(d.Name)
	for _, account := range accounts {
		if strings.HasSuffix(strings.ToLower(account.Primary), suffix) {
			state.Mailboxes = append(state.Mailboxes, mail.Mailbox{Address: account.Primary, ID: string(account.ZUID)})
		}
		for _, address := range account.EmailAddress {
			local, ok := strings.CutSuffix(strings.ToLower(address.MailID), suffix)
			if !bool(address.IsAlias) || !ok {
				continue
			}
			state.Aliases = append(state.Aliases, mail.Alias{
				ID: string(account.ZUID), Match: local, To: []string{account.Primary},
			})
		}
	}
	if domain.CatchAllAddress != "" {
		state.CatchAll = &mail.CatchAll{To: []string{domain.CatchAllAddress}}
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	client := p.open(d)
	name := d.Name
	action := func(op plan.Op, resource, detail string, do func(context.Context) error) plan.Action {
		return plan.Action{Op: op, Resource: resource, Domain: name, Provider: Name, Detail: detail, Do: do}
	}

	if !actual.DomainExists {
		return []plan.Action{action(plan.OpCreate, "domain", "add domain "+name+" to the Zoho organisation",
			func(ctx context.Context) error { return client.AddDomain(ctx, name) })}, nil
	}
	if !actual.Verified {
		return []plan.Action{action(plan.OpUpdate, "domain", "verify ownership, enable mail hosting and create a DKIM key",
			func(ctx context.Context) error {
				if err := client.VerifyDomain(ctx, name); err != nil {
					return fmt.Errorf("%w; the ownership TXT may not have propagated yet, wait a few minutes and rerun", err)
				}
				if err := client.EnableHosting(ctx, name); err != nil {
					return err
				}
				return client.AddDKIM(ctx, name, dkimSelector)
			})}, nil
	}

	var actions []plan.Action
	if p.domain != nil {
		if !p.domain.MailHostingEnabled {
			actions = append(actions, action(plan.OpUpdate, "domain", "enable mail hosting",
				func(ctx context.Context) error { return client.EnableHosting(ctx, name) }))
		}
		if len(p.domain.DKIM) == 0 {
			actions = append(actions, action(plan.OpCreate, "domain", "create a DKIM key (published on the next run)",
				func(ctx context.Context) error { return client.AddDKIM(ctx, name, dkimSelector) }))
		}
		for _, key := range p.domain.DKIM {
			if !bool(key.IsVerified) && key.PublicKey != "" {
				id := key.ID
				actions = append(actions, action(plan.OpUpdate, "domain", "verify DKIM selector "+key.Selector,
					func(ctx context.Context) error { return client.VerifyDKIM(ctx, name, id) }))
			}
		}
	}

	mailboxes, err := p.planMailboxes(d, actual, opts, action)
	if err != nil {
		return nil, err
	}
	actions = append(actions, mailboxes...)
	actions = append(actions, p.planAliases(d, actual, opts, action)...)

	if d.CatchAll != nil && (actual.CatchAll == nil || !strings.EqualFold(actual.CatchAll.To[0], d.CatchAll.To[0])) {
		target := d.CatchAll.To[0]
		actions = append(actions, action(plan.OpUpdate, "catchall", "catch-all -> "+target,
			func(ctx context.Context) error { return client.SetCatchAll(ctx, name, target) }))
	}
	return actions, nil
}

type actionFunc func(op plan.Op, resource, detail string, do func(context.Context) error) plan.Action

func (p *Provider) planMailboxes(d config.Domain, actual mail.State, opts mail.Options, action actionFunc) ([]plan.Action, error) {
	var actions []plan.Action
	managed := map[string]bool{}
	for _, want := range d.Mailboxes {
		managed[strings.ToLower(want.Address)] = true
		if _, exists := actual.Mailbox(want.Address); exists {
			continue
		}
		credential, err := opts.Secrets.Password(d.Name, want)
		if err != nil {
			return nil, err
		}
		account := NewAccount{Address: want.Address, Password: credential, Role: "member",
			DisplayName: want.DisplayName, FirstName: want.LocalPart()}
		address := want.Address
		actions = append(actions, action(plan.OpCreate, "mailbox", "create "+address,
			func(ctx context.Context) error {
				if err := p.client.AddAccount(ctx, account); err != nil {
					return err
				}
				opts.Secrets.MarkApplied(address)
				return nil
			}))
	}

	// Deleting a mailbox destroys mail: it needs -prune and -prune-mailboxes.
	if !opts.Prune || !opts.PruneMailboxes {
		return actions, nil
	}
	for _, have := range actual.Mailboxes {
		if managed[strings.ToLower(have.Address)] {
			continue
		}
		address := have.Address
		actions = append(actions, action(plan.OpDelete, "mailbox", "delete "+address+" and all mail it holds",
			func(ctx context.Context) error { return p.client.DeleteAccount(ctx, address) }))
	}
	return actions, nil
}

// planAliases adds each alias address to its one target mailbox. Moving an
// alias deletes it from the old mailbox first.
func (p *Provider) planAliases(d config.Domain, actual mail.State, opts mail.Options, action actionFunc) []plan.Action {
	var actions []plan.Action
	managed := map[string]bool{}
	for _, want := range d.Aliases {
		match := strings.ToLower(want.MatchUser())
		managed[match] = true
		address := match + "@" + d.Name
		target := want.To[0]

		existing, found := actual.Alias(match, false)
		if found && strings.EqualFold(existing.To[0], target) {
			continue
		}
		if found {
			zuid := ID(existing.ID)
			actions = append(actions, action(plan.OpDelete, "alias", fmt.Sprintf("move alias %s off %s", address, existing.To[0]),
				func(ctx context.Context) error { return p.client.DeleteAlias(ctx, zuid, address) }))
		}
		actions = append(actions, action(plan.OpCreate, "alias", fmt.Sprintf("alias %s -> %s", address, target),
			func(ctx context.Context) error {
				zuid, err := p.accountID(ctx, target)
				if err != nil {
					return err
				}
				return p.client.AddAlias(ctx, zuid, address)
			}))
	}

	if !opts.Prune {
		return actions
	}
	for _, have := range actual.Aliases {
		if managed[strings.ToLower(have.Match)] {
			continue
		}
		zuid, address := ID(have.ID), have.Match+"@"+d.Name
		actions = append(actions, action(plan.OpDelete, "alias", "delete unmanaged alias "+address,
			func(ctx context.Context) error { return p.client.DeleteAlias(ctx, zuid, address) }))
	}
	return actions
}

// accountID finds a mailbox's zuid at apply time, so an alias can target a
// mailbox created earlier in the same apply.
func (p *Provider) accountID(ctx context.Context, address string) (ID, error) {
	find := func(accounts []Account) (ID, bool) {
		i := slices.IndexFunc(accounts, func(a Account) bool { return strings.EqualFold(a.Primary, address) })
		if i < 0 {
			return "", false
		}
		return accounts[i].ZUID, true
	}
	if id, ok := find(p.accounts); ok {
		return id, nil
	}
	accounts, err := p.client.Accounts(ctx)
	if err != nil {
		return "", err
	}
	p.accounts = accounts
	if id, ok := find(accounts); ok {
		return id, nil
	}
	return "", fmt.Errorf("alias target %s is not a mailbox in the Zoho organisation", address)
}

// find returns the domain, or nil when the organisation does not have it.
func (p *Provider) find(ctx context.Context, d config.Domain) (*Domain, error) {
	if p.domain != nil {
		return p.domain, nil
	}
	client := p.open(d)
	domains, err := client.Domains(ctx)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if !slices.ContainsFunc(domains, func(x Domain) bool { return strings.EqualFold(x.Name, d.Name) }) {
		return nil, nil
	}
	domain, err := client.Domain(ctx, d.Name)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.domain = &domain
	return p.domain, nil
}
