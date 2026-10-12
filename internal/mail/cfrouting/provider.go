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

	// zoneID is filled in by whichever of DesiredDNS or Actual runs first;
	// unverified and missing are filled in by Actual. All three are read by
	// Plan, which performs no I/O of its own. Caching them on the provider is
	// safe only because the engine opens a fresh provider per domain and
	// always calls Actual before Plan; a future change that reuses one
	// provider across domains would silently corrupt the second domain's plan.
	zoneID string
	// unverified holds destinations Cloudflare already knows about but has
	// not yet verified.
	unverified map[string]bool
	// missing holds destinations that do not exist in Cloudflare's account at
	// all; Plan must create these before it can tell a human to verify them.
	missing map[string]bool
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

	// Destinations is account-scoped, not zone-scoped, so it does not depend
	// on Email Routing being enabled on this zone yet. Reading it before the
	// not-enabled return keeps missing/unverified populated on a first run;
	// otherwise Plan's destination loop is a no-op and it creates an alias
	// rule pointing at a destination Cloudflare has never heard of, which
	// Cloudflare then rejects mid-apply (I1).
	destinations, err := p.client.Destinations(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	p.unverified = map[string]bool{}
	p.missing = map[string]bool{}
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
			p.missing[strings.ToLower(target)] = true
		}
	}

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
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
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

	// A destination that is missing or unverified is a human step, reported
	// and never blocked on. Cloudflare only emails a verification link once
	// the address exists, so a missing target is registered first; the
	// manual entry that follows is then a step a human can actually complete.
	for _, target := range d.AllTargets() {
		key := strings.ToLower(target)
		switch {
		case p.missing[key]:
			target := target
			actions = append(actions, plan.Action{
				Op:       plan.OpCreate,
				Resource: "destination",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "register destination " + target,
				Do: func(ctx context.Context) error {
					return p.client.CreateDestination(ctx, target)
				},
			})
			actions = append(actions, plan.Action{
				Op:       plan.OpManual,
				Resource: "destination",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "verify " + target + " by clicking the link Cloudflare will email to it once it is registered",
			})
		case p.unverified[key]:
			actions = append(actions, plan.Action{
				Op:       plan.OpManual,
				Resource: "destination",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "verify " + target + " by clicking the link Cloudflare already emailed to it",
			})
		}
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

	// Pruning only ever deletes what -prune explicitly asked for (I2):
	// nothing here runs unless opts.Prune is set.
	if opts.Prune {
		actions = append(actions, p.pruneAliases(d, actual, zoneID)...)
		// The catch-all is deliberately outside -prune's scope. Omitting
		// catchAll: means "leave whatever exists untouched" (mailctl.example.yaml,
		// validate.go's own error text), not "delete it" — but *CatchAll is a
		// plain pointer, so "never declared" and "explicitly wants none" both
		// collapse to nil. Pruning on that ambiguity would delete a live
		// catch-all an operator simply never mentioned.
	}
	return actions, nil
}

// pruneAliases returns delete actions for routing rules that exist in
// Cloudflare but no longer appear in the config, so a removed alias actually
// stops forwarding instead of silently continuing to (I2).
func (p *Provider) pruneAliases(d config.Domain, actual mail.State, zoneID string) []plan.Action {
	wanted := map[string]bool{}
	for _, want := range d.Aliases {
		wanted[strings.ToLower(want.MatchUser())] = true
	}

	var actions []plan.Action
	for _, existing := range actual.Aliases {
		if wanted[strings.ToLower(existing.Match)] {
			continue
		}
		tag, match := existing.ID, existing.Match
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "prune alias " + match + " (not in config)",
			Do: func(ctx context.Context) error {
				return p.client.DeleteRule(ctx, zoneID, tag)
			},
		})
	}
	return actions
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
