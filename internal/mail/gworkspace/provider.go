// Package gworkspace configures Google Workspace mail for a domain through
// the Admin SDK Directory API and the Site Verification API, signed in as a
// service account with domain-wide delegation acting for a super admin.
//
// A new domain takes two runs: add it and publish the ownership TXT, then
// verify, after which MX, SPF and DKIM are published. Google has no API for
// the DKIM key or for catch-all routing, so the DKIM TXT comes from
// mail.gworkspace.dkim and catch-all stays an Admin console setting.
package gworkspace

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

const Name = "gworkspace"

// SPFInclude is Google's sending SPF mechanism.
const SPFInclude = "include:_spf.google.com"

const defaultDKIMSelector = "google"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		if deps.Getenv == nil {
			return nil, errors.New("gworkspace: no environment accessor supplied")
		}
		key, admin := deps.Getenv("GOOGLE_SERVICE_ACCOUNT_KEY"), deps.Getenv("GOOGLE_ADMIN_EMAIL")
		if key == "" || admin == "" {
			return nil, errors.New("GOOGLE_SERVICE_ACCOUNT_KEY (JSON or a file path) and GOOGLE_ADMIN_EMAIL are required for the gworkspace provider")
		}
		account, err := LoadServiceAccount(key)
		if err != nil {
			return nil, err
		}
		baseURL, siteURL, tokenURL := DefaultBaseURL, SiteVerificationURL, DefaultTokenURL
		if deps.GoogleBaseURL != "" {
			baseURL, siteURL = deps.GoogleBaseURL, deps.GoogleBaseURL+"/siteVerification"
		}
		if deps.GoogleTokenURL != "" {
			tokenURL = deps.GoogleTokenURL
		}
		client, err := NewClient(baseURL, siteURL, tokenURL, account, admin)
		if err != nil {
			return nil, err
		}
		return &Provider{client: client}, nil
	})
}

type Provider struct {
	client *Client

	// domain is cached by DesiredDNS and Actual; found reports the lookup ran.
	domain *Domain
	found  bool
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	token, err := p.client.VerificationToken(ctx, d.Name)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	// The ownership TXT stays after verification: Google checks it again.
	records := []dns.Record{{Type: "TXT", Name: d.Name, Content: token, Kind: dns.KindOwnership}}

	domain, err := p.find(ctx, d)
	if err != nil {
		return nil, err
	}
	// MX waits for verification so mail is never sent to Google before it
	// accepts the domain.
	if domain == nil || !domain.Verified {
		return records, nil
	}
	records = append(records,
		dns.Record{Type: "MX", Name: d.Name, Content: "smtp.google.com", Priority: 1, Kind: dns.KindMX},
		dns.Record{Type: "TXT", Name: d.Name, Content: "v=spf1 " + SPFInclude + " ~all", Kind: dns.KindSPF},
	)
	if settings := d.Mail.GWorkspace; settings != nil && settings.DKIM != "" {
		selector := settings.DKIMSelector
		if selector == "" {
			selector = defaultDKIMSelector
		}
		records = append(records, dns.Record{
			Type: "TXT", Name: selector + "._domainkey." + d.Name, Content: settings.DKIM, Kind: dns.KindDKIM,
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
		return state, nil
	}
	state.DomainExists = true
	state.Verified = domain.Verified
	if !state.Verified {
		state.Notes = append(state.Notes, "domain not verified at Google; users and aliases wait until it is")
		return state, nil
	}
	if d.Mail.GWorkspace == nil || d.Mail.GWorkspace.DKIM == "" {
		state.Notes = append(state.Notes,
			"no DKIM published: generate a key under Apps > Gmail > Authenticate email and copy its TXT value to mail.gworkspace.dkim")
	}

	users, err := p.client.Users(ctx, d.Name)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	suffix := "@" + strings.ToLower(d.Name)
	for _, user := range users {
		state.Mailboxes = append(state.Mailboxes, mail.Mailbox{Address: user.PrimaryEmail, ID: user.ID})
		for _, alias := range user.Aliases {
			if local, ok := strings.CutSuffix(strings.ToLower(alias), suffix); ok {
				state.Aliases = append(state.Aliases, mail.Alias{ID: user.ID, Match: local, To: []string{user.PrimaryEmail}})
			}
		}
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	name := d.Name
	action := func(op plan.Op, resource, detail string, do func(context.Context) error) plan.Action {
		return plan.Action{Op: op, Resource: resource, Domain: name, Provider: Name, Detail: detail, Do: do}
	}
	if !actual.DomainExists {
		return []plan.Action{action(plan.OpCreate, "domain", "add domain "+name+" to Google Workspace",
			func(ctx context.Context) error { return p.client.AddDomain(ctx, name) })}, nil
	}
	if !actual.Verified {
		return []plan.Action{action(plan.OpUpdate, "domain", "verify ownership through the TXT record",
			func(ctx context.Context) error {
				if err := p.client.Verify(ctx, name); err != nil {
					return fmt.Errorf("%w; the ownership TXT may not have propagated yet, wait a few minutes and rerun", err)
				}
				return nil
			})}, nil
	}

	actions, err := p.planUsers(d, actual, opts, action)
	if err != nil {
		return nil, err
	}
	return append(actions, p.planAliases(d, actual, opts, action)...), nil
}

type actionFunc func(op plan.Op, resource, detail string, do func(context.Context) error) plan.Action

func (p *Provider) planUsers(d config.Domain, actual mail.State, opts mail.Options, action actionFunc) ([]plan.Action, error) {
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
		user := User{PrimaryEmail: want.Address, Name: userName(want), Password: credential,
			ChangePasswordAtNextLogin: true}
		address := want.Address
		actions = append(actions, action(plan.OpCreate, "mailbox", "create user "+address,
			func(ctx context.Context) error {
				if err := p.client.AddUser(ctx, user); err != nil {
					return err
				}
				opts.Secrets.MarkApplied(address)
				return nil
			}))
	}

	// Deleting a user destroys its mail and Drive: it needs -prune and
	// -prune-mailboxes.
	if !opts.Prune || !opts.PruneMailboxes {
		return actions, nil
	}
	for _, have := range actual.Mailboxes {
		if managed[strings.ToLower(have.Address)] {
			continue
		}
		address := have.Address
		actions = append(actions, action(plan.OpDelete, "mailbox", "delete user "+address+" with its mail and files",
			func(ctx context.Context) error { return p.client.DeleteUser(ctx, address) }))
	}
	return actions, nil
}

func (p *Provider) planAliases(d config.Domain, actual mail.State, opts mail.Options, action actionFunc) []plan.Action {
	var actions []plan.Action
	managed := map[string]bool{}
	for _, want := range d.Aliases {
		match := strings.ToLower(want.MatchUser())
		managed[match] = true
		address, target := match+"@"+d.Name, want.To[0]

		existing, found := actual.Alias(match, false)
		if found && strings.EqualFold(existing.To[0], target) {
			continue
		}
		if found {
			owner := existing.To[0]
			actions = append(actions, action(plan.OpDelete, "alias", fmt.Sprintf("move alias %s off %s", address, owner),
				func(ctx context.Context) error { return p.client.DeleteAlias(ctx, owner, address) }))
		}
		actions = append(actions, action(plan.OpCreate, "alias", fmt.Sprintf("alias %s -> %s", address, target),
			func(ctx context.Context) error { return p.client.AddAlias(ctx, target, address) }))
	}

	if !opts.Prune {
		return actions
	}
	for _, have := range actual.Aliases {
		if managed[strings.ToLower(have.Match)] {
			continue
		}
		owner, address := have.To[0], have.Match+"@"+d.Name
		actions = append(actions, action(plan.OpDelete, "alias", "delete unmanaged alias "+address,
			func(ctx context.Context) error { return p.client.DeleteAlias(ctx, owner, address) }))
	}
	return actions
}

// userName splits the display name into the given and family names Google
// requires, falling back to the local part for both.
func userName(box config.Mailbox) UserName {
	given, family, _ := strings.Cut(strings.TrimSpace(box.DisplayName), " ")
	if given == "" {
		given = box.LocalPart()
	}
	if family = strings.TrimSpace(family); family == "" {
		family = given
	}
	return UserName{GivenName: given, FamilyName: family}
}

func (p *Provider) find(ctx context.Context, d config.Domain) (*Domain, error) {
	if p.found {
		return p.domain, nil
	}
	domain, err := p.client.Domain(ctx, d.Name)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.domain, p.found = domain, true
	return domain, nil
}
