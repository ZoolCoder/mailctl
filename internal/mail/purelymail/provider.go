package purelymail

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// Name is the value used in the config's mail.provider field.
const Name = "purelymail"

// SPFInclude is the mechanism Purelymail requires in the domain's SPF record.
// The deliverability package merges it with any additional includes.
const SPFInclude = "include:_spf.purelymail.com"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		getenv := deps.Getenv
		if getenv == nil {
			return nil, fmt.Errorf("purelymail: no environment accessor supplied")
		}
		token := getenv("PURELYMAIL_API_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("PURELYMAIL_API_TOKEN is required for the purelymail provider")
		}
		return &Provider{client: NewClient(deps.PurelymailBaseURL, token)}, nil
	})
}

type Provider struct {
	client *Client
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	code, err := p.client.GetOwnershipCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if code == "" {
		return nil, fmt.Errorf("domain %s: Purelymail returned an empty ownership code", d.Name)
	}

	dnsOnly := false
	records := []dns.Record{
		{Type: "MX", Name: d.Name, Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
		{Type: "TXT", Name: d.Name, Content: "v=spf1 " + SPFInclude + " ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: d.Name, Content: code, Kind: dns.KindOwnership},
	}
	for i := 1; i <= 3; i++ {
		records = append(records, dns.Record{
			Type:    "CNAME",
			Name:    fmt.Sprintf("purelymail%d._domainkey.%s", i, d.Name),
			Content: fmt.Sprintf("key%d.dkimroot.purelymail.com", i),
			Proxied: &dnsOnly,
			Kind:    dns.KindDKIM,
		})
	}

	// When the config declares a DMARC policy, the deliverability package owns
	// _dmarc as a TXT record; two managers of one name would fight.
	if d.Deliverability.DMARC == nil {
		records = append(records, dns.Record{
			Type:    "CNAME",
			Name:    "_dmarc." + d.Name,
			Content: "dmarcroot.purelymail.com",
			Proxied: &dnsOnly,
			Kind:    dns.KindDMARC,
		})
	}
	return records, nil
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State

	domains, err := p.client.ListDomains(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	for _, remote := range domains {
		if !strings.EqualFold(remote.Name, d.Name) {
			continue
		}
		state.DomainExists = true
		state.Settings = mail.Settings{
			AllowAccountReset:     remote.AllowAccountReset,
			SymbolicSubaddressing: remote.SymbolicSubaddressing,
		}
		summary := remote.DNSSummary
		if !(summary.PassesMX && summary.PassesSPF && summary.PassesDKIM && summary.PassesDMARC) {
			state.Notes = append(state.Notes, fmt.Sprintf(
				"purelymail DNS check: mx=%t spf=%t dkim=%t dmarc=%t",
				summary.PassesMX, summary.PassesSPF, summary.PassesDKIM, summary.PassesDMARC))
		}
		break
	}

	if !state.DomainExists {
		// Nothing else can exist for a domain Purelymail does not know about.
		return state, nil
	}

	users, err := p.client.ListUsers(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	suffix := "@" + d.Name
	for _, address := range users {
		address = strings.ToLower(address)
		if !strings.HasSuffix(address, suffix) {
			continue
		}
		methods, err := p.client.ListPasswordReset(ctx, address)
		if err != nil {
			return state, fmt.Errorf("domain %s: mailbox %s: %w", d.Name, address, err)
		}
		box := mail.Mailbox{Address: address}
		for _, m := range methods {
			box.Recovery = append(box.Recovery, mail.Recovery{
				ID: m.ID.String(), Type: m.Type, Target: m.Target, Description: m.Description,
			})
		}
		state.Mailboxes = append(state.Mailboxes, box)
	}

	rules, err := p.client.ListRoutingRules(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	for _, rule := range rules {
		if !strings.EqualFold(rule.DomainName, d.Name) {
			continue
		}
		if rule.Catchall {
			state.CatchAll = &mail.CatchAll{ID: strconv.Itoa(rule.ID), To: rule.TargetAddresses}
			continue
		}
		state.Aliases = append(state.Aliases, mail.Alias{
			ID:     strconv.Itoa(rule.ID),
			Match:  rule.MatchUser,
			Prefix: rule.Prefix,
			To:     rule.TargetAddresses,
		})
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	var actions []plan.Action

	actions = append(actions, p.planDomain(d, actual)...)

	mailboxActions, err := p.planMailboxes(d, actual, opts)
	if err != nil {
		return nil, err
	}
	actions = append(actions, mailboxActions...)

	actions = append(actions, p.planAliases(d, actual, opts)...)
	actions = append(actions, p.planCatchAll(d, actual)...)
	return actions, nil
}

func (p *Provider) planDomain(d config.Domain, actual mail.State) []plan.Action {
	if !actual.DomainExists {
		name := d.Name
		return []plan.Action{{
			Op:       plan.OpCreate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "add domain " + name,
			Do: func(ctx context.Context) error {
				if err := p.client.AddDomain(ctx, name); err != nil {
					return fmt.Errorf(
						"add Purelymail domain %s failed; the ownership TXT record may not have propagated yet, wait a minute and rerun: %w",
						name, err)
				}
				return nil
			},
		}}
	}

	want := d.Mail.Settings
	allowReset := want.AllowAccountReset
	symbolic := want.SymbolicSubaddressing
	resetDrift := allowReset != nil && *allowReset != actual.Settings.AllowAccountReset
	symbolicDrift := symbolic != nil && *symbolic != actual.Settings.SymbolicSubaddressing
	if !resetDrift && !symbolicDrift {
		return nil
	}

	name := d.Name
	return []plan.Action{{
		Op:       plan.OpUpdate,
		Resource: "domain",
		Domain:   d.Name,
		Provider: Name,
		Detail: fmt.Sprintf("update settings (allowAccountReset=%s symbolicSubaddressing=%s)",
			boolText(allowReset), boolText(symbolic)),
		Do: func(ctx context.Context) error {
			return p.client.UpdateDomainSettings(ctx, name, allowReset, symbolic, false)
		},
	}}
}

func (p *Provider) planMailboxes(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	var actions []plan.Action
	managed := map[string]bool{}

	for _, want := range d.Mailboxes {
		managed[want.Address] = true
		_, exists := actual.Mailbox(want.Address)
		if !exists {
			credential, err := opts.Secrets.Password(d.Name, want)
			if err != nil {
				return nil, err
			}
			newUser := NewUser{
				UserName:             want.LocalPart(),
				DomainName:           d.Name,
				Password:             credential,
				EnablePasswordReset:  config.BoolOr(want.EnablePasswordReset, true),
				EnableSearchIndexing: config.BoolOr(want.EnableSearchIndexing, true),
				SendWelcomeEmail:     config.BoolOr(want.SendWelcomeEmail, false),
			}
			address := want.Address
			actions = append(actions, plan.Action{
				Op:       plan.OpCreate,
				Resource: "mailbox",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "create " + address,
				Do: func(ctx context.Context) error {
					if err := p.client.CreateUser(ctx, newUser); err != nil {
						return err
					}
					// Only report a credential once it is actually on the
					// provider; MarkApplied is a no-op if it was never
					// generated (e.g. taken from the environment instead).
					opts.Secrets.MarkApplied(address)
					return nil
				},
			})
		}
		actions = append(actions, p.planRecovery(d, want, actual)...)
	}

	// PruneMailboxes is a second opt-in on top of Prune: deleting a mailbox
	// destroys mail, unlike an alias, catch-all rule or recovery method, none
	// of which carry any. Aliases and the catch-all below stay gated on Prune
	// alone; only this block requires both.
	if !opts.Prune || !opts.PruneMailboxes {
		return actions, nil
	}
	for _, have := range actual.Mailboxes {
		if managed[strings.ToLower(have.Address)] {
			continue
		}
		address := have.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "mailbox",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "delete " + address + " and all mail it holds",
			Do: func(ctx context.Context) error {
				return p.client.DeleteUser(ctx, address)
			},
		})
	}
	return actions, nil
}

// planRecovery reconciles password-reset methods for one mailbox. A mailbox
// that does not exist yet has no methods, so everything in config is created.
func (p *Provider) planRecovery(d config.Domain, want config.Mailbox, actual mail.State) []plan.Action {
	var actions []plan.Action
	have, _ := actual.Mailbox(want.Address)

	keep := map[string]bool{}
	for _, method := range want.Recovery {
		existing, found := findRecovery(have.Recovery, method.Type, method.Target)
		if found {
			keep[existing.ID] = true
			continue
		}
		method := method
		address := want.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "recovery",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("add %s recovery %s to %s", method.Type, method.Target, address),
			Do: func(ctx context.Context) error {
				return p.client.UpsertPasswordReset(ctx, address, ResetMethod{
					Type:        method.Type,
					Target:      method.Target,
					Description: method.Description,
				})
			},
		})
	}

	// Recovery methods are fully managed once a mailbox declares any, because a
	// stale reset path is a standing account-takeover route. A mailbox with no
	// recovery block in config is left alone.
	if len(want.Recovery) == 0 {
		return actions
	}
	for _, method := range have.Recovery {
		if keep[method.ID] {
			continue
		}
		method := method
		address := want.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "recovery",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("remove %s recovery %s from %s", method.Type, method.Target, address),
			Do: func(ctx context.Context) error {
				return p.client.DeletePasswordReset(ctx, address, method.ID)
			},
		})
	}
	return actions
}

func (p *Provider) planAliases(d config.Domain, actual mail.State, opts mail.Options) []plan.Action {
	var actions []plan.Action
	managed := map[string]bool{}

	for _, want := range d.Aliases {
		key := aliasKey(want.MatchUser(), want.Prefix())
		managed[key] = true

		existing, found := actual.Alias(want.MatchUser(), want.Prefix())
		if found && sameTargets(existing.To, want.To) {
			continue
		}
		if found {
			// Purelymail has no update endpoint for a routing rule.
			id := existing.ID
			actions = append(actions, plan.Action{
				Op:       plan.OpDelete,
				Resource: "alias",
				Domain:   d.Name,
				Provider: Name,
				Detail:   fmt.Sprintf("replace alias %s (targets changed)", want.Match),
				Do:       p.deleteRule(d.Name, id),
			})
		}
		rule := RoutingRule{
			DomainName:      d.Name,
			MatchUser:       want.MatchUser(),
			Prefix:          want.Prefix(),
			TargetAddresses: want.To,
		}
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("alias %s -> %s", want.Match, strings.Join(want.To, ", ")),
			Do: func(ctx context.Context) error {
				return p.client.CreateRoutingRule(ctx, rule)
			},
		})
	}

	if !opts.Prune {
		return actions
	}
	for _, have := range actual.Aliases {
		if managed[aliasKey(have.Match, have.Prefix)] {
			continue
		}
		id, match := have.ID, have.Match
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "delete unmanaged alias " + match,
			Do:       p.deleteRule(d.Name, id),
		})
	}
	return actions
}

func (p *Provider) planCatchAll(d config.Domain, actual mail.State) []plan.Action {
	// Omitting the key leaves whatever exists untouched.
	if d.CatchAll == nil {
		return nil
	}
	if actual.CatchAll != nil && sameTargets(actual.CatchAll.To, d.CatchAll.To) {
		return nil
	}

	var actions []plan.Action
	if actual.CatchAll != nil {
		id := actual.CatchAll.ID
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "catchall",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "replace catch-all (targets changed)",
			Do:       p.deleteRule(d.Name, id),
		})
	}
	rule := RoutingRule{
		DomainName:      d.Name,
		TargetAddresses: d.CatchAll.To,
		Catchall:        true,
	}
	return append(actions, plan.Action{
		Op:       plan.OpCreate,
		Resource: "catchall",
		Domain:   d.Name,
		Provider: Name,
		Detail:   "catch-all -> " + strings.Join(d.CatchAll.To, ", "),
		Do: func(ctx context.Context) error {
			return p.client.CreateRoutingRule(ctx, rule)
		},
	})
}

func (p *Provider) deleteRule(domain, id string) func(context.Context) error {
	return func(ctx context.Context) error {
		numeric, err := strconv.Atoi(id)
		if err != nil {
			return fmt.Errorf("domain %s: Purelymail routing rule id %q is not a number: %w", domain, id, err)
		}
		return p.client.DeleteRoutingRule(ctx, numeric)
	}
}

func findRecovery(methods []mail.Recovery, kind, target string) (mail.Recovery, bool) {
	for _, m := range methods {
		if strings.EqualFold(m.Type, kind) && strings.EqualFold(m.Target, target) {
			return m, true
		}
	}
	return mail.Recovery{}, false
}

func aliasKey(match string, prefix bool) string {
	return fmt.Sprintf("%s|%t", strings.ToLower(match), prefix)
}

// sameTargets compares target lists ignoring order and case.
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

func boolText(v *bool) string {
	if v == nil {
		return "unchanged"
	}
	return strconv.FormatBool(*v)
}
