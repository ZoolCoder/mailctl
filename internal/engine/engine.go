// Package engine turns a config plus live provider state into an ordered plan,
// and executes it.
package engine

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/deliver"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
	"github.com/zoolcoder/mailctl/internal/worker"
)

type Options struct {
	// Domains limits the run to these domain names. Empty means every domain.
	Domains []string
	// Prune plans deletion of provider-side objects absent from the config.
	Prune bool
	// PruneMailboxes allows Prune to plan mailbox deletion. It is a second
	// opt-in because deleting a mailbox destroys mail.
	PruneMailboxes bool
	// ReplaceDNS deletes conflicting DNS records instead of failing.
	ReplaceDNS bool
	// Secrets resolves mailbox credentials.
	Secrets *secret.Resolver
}

type Engine struct {
	cfg      config.Config
	zone     dns.Provider
	deployer *worker.Deployer
	deps     mail.Deps
	opts     Options
}

// New builds an engine. deployer may be nil when no domain deploys an MTA-STS
// policy Worker; a domain that asks for one then fails with a clear message.
func New(cfg config.Config, zone dns.Provider, deployer *worker.Deployer, deps mail.Deps, opts Options) *Engine {
	if opts.Secrets == nil {
		opts.Secrets = secret.NewResolver(nil)
	}
	return &Engine{cfg: cfg, zone: zone, deployer: deployer, deps: deps, opts: opts}
}

// Plan reads live state and returns everything that would change. It performs
// no writes.
func (e *Engine) Plan(ctx context.Context) (plan.Plan, error) {
	domains, err := e.selectedDomains()
	if err != nil {
		return plan.Plan{}, err
	}

	var out plan.Plan
	for _, d := range domains {
		domainPlan, err := e.planDomain(ctx, d)
		if err != nil {
			return plan.Plan{}, err
		}
		out.Extend(domainPlan)
	}
	return out, nil
}

func (e *Engine) planDomain(ctx context.Context, d config.Domain) (plan.Plan, error) {
	var out plan.Plan

	providers, err := e.openProviders(d)
	if err != nil {
		return out, err
	}

	// Desired DNS is the union across providers. The deliverability layer
	// (SPF merge, DMARC, MTA-STS, TLS-RPT, BIMI) is folded in below by
	// deliver.Merge.
	desired, err := e.unionDesiredDNS(ctx, d, providers)
	if err != nil {
		return out, err
	}

	merged, err := deliver.Merge(d, desired)
	if err != nil {
		return out, err
	}

	zone, err := e.zone.Zone(ctx, d.ZoneName)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	actualRecords, err := e.zone.Records(ctx, zone.ID)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	dnsActions, err := dns.Diff(e.zone, zone.ID, d.Name, actualRecords, merged.Records,
		dns.DiffOptions{ReplaceConflicts: e.opts.ReplaceDNS})
	if err != nil {
		return out, err
	}

	workerActions, err := e.planWorker(ctx, d, zone.ID, merged)
	if err != nil {
		return out, err
	}

	// Worker actions are added before DNS actions: on a policy update, the
	// _mta-sts TXT's new id must not go live before the Worker serves the
	// policy it names, or a receiver refetches, gets the stale policy under
	// the new id, and stays pinned to it until the id changes again.
	out.Add(workerActions...)
	out.Add(dnsActions...)

	// Mail actions run after DNS because Purelymail's addDomain fails until the
	// ownership TXT record resolves.
	for _, provider := range providers {
		state, err := provider.Actual(ctx, d)
		if err != nil {
			return out, err
		}
		for _, note := range state.Notes {
			out.Add(plan.Action{
				Op:       plan.OpManual,
				Resource: "note",
				Domain:   d.Name,
				Provider: provider.Name(),
				Detail:   note,
			})
		}
		actions, err := provider.Plan(d, state, mail.Options{
			Prune:          e.opts.Prune,
			PruneMailboxes: e.opts.PruneMailboxes,
			Secrets:        e.opts.Secrets,
		})
		if err != nil {
			return out, err
		}
		out.Add(actions...)
	}
	return out, nil
}

// Apply runs every executable action in order, writing one line per action.
func (e *Engine) Apply(ctx context.Context, p plan.Plan, out io.Writer) error {
	actions := p.Executable()
	for i, action := range actions {
		fmt.Fprintf(out, "[%d/%d] %s %s %s: %s\n",
			i+1, len(actions), action.Op, action.Domain, action.Resource, action.Detail)

		if err := action.Do(ctx); err != nil {
			return fmt.Errorf(
				"%s %s %s failed after %d of %d actions succeeded (provider %s: %s); every action is idempotent, so fix the cause and rerun: %w",
				action.Op, action.Domain, action.Resource, i, len(actions), action.Provider, action.Detail, err)
		}
	}
	fmt.Fprintf(out, "Applied %d actions.\n", len(actions))
	return nil
}

// Desired returns the DNS records mailctl wants published for a domain,
// without reading the zone or planning anything. audit uses it, and it
// applies the same collision guard planDomain does via unionDesiredDNS, so
// audit and plan cannot disagree about whether a config is legal.
func (e *Engine) Desired(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	providers, err := e.openProviders(d)
	if err != nil {
		return nil, err
	}
	desired, err := e.unionDesiredDNS(ctx, d, providers)
	if err != nil {
		return nil, err
	}
	merged, err := deliver.Merge(d, desired)
	if err != nil {
		return nil, err
	}
	return merged.Records, nil
}

// openProviders opens every mail provider configured for a domain, in order.
func (e *Engine) openProviders(d config.Domain) ([]mail.Provider, error) {
	providers := make([]mail.Provider, 0, len(d.Mail.Providers))
	for _, name := range d.Mail.Providers {
		provider, err := mail.Open(name, e.deps)
		if err != nil {
			return nil, fmt.Errorf("domain %s: %w", d.Name, err)
		}
		providers = append(providers, provider)
	}
	return providers, nil
}

// unionDesiredDNS collects each provider's desired DNS and unions them,
// applying the cross-provider collision guard. planDomain and Desired both
// call this, so plan and audit can never diverge on whether a config is
// legal (I3).
//
// The guard only applies to singleton record kinds (see singleton): MX is a
// multi-valued RRset, DKIM lives on distinct selector names, ownership TXTs
// are provider-specific, and SPF is reconciled into one record by
// deliver.Merge. None of those can collide the way a singleton record can,
// so they pass through uncontested.
func (e *Engine) unionDesiredDNS(ctx context.Context, d config.Domain, providers []mail.Provider) ([]dns.Record, error) {
	var desired []dns.Record
	owner := map[string]string{}
	for _, provider := range providers {
		records, err := provider.DesiredDNS(ctx, d)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if !singleton(record.Kind) {
				desired = append(desired, record)
				continue
			}
			key := recordKey(record)
			if previous, claimed := owner[key]; claimed {
				if !sameContent(desired, key, record) {
					if previous == provider.Name() {
						return nil, fmt.Errorf(
							"domain %s: provider %s returned conflicting records for %s %s with different content; it contradicts itself",
							d.Name, provider.Name(), record.Type, record.Name)
					}
					return nil, fmt.Errorf(
						"domain %s: providers %s and %s both want %s %s with different content; they cannot share this record",
						d.Name, previous, provider.Name(), record.Type, record.Name)
				}
				continue
			}
			owner[key] = provider.Name()
			desired = append(desired, record)
		}
	}
	return desired, nil
}

// singleton reports whether a record kind is one-per-name by specification,
// so two providers proposing different content for it is a genuine conflict
// rather than a legitimate multi-value case something else already handles.
// DMARC, MTA-STS, TLS-RPT, and BIMI each live on exactly one name per
// domain. Everything else is not: MX is an RRset with several values (three
// apex records from Cloudflare Email Routing, for instance), DKIM keys live
// on distinct per-selector names, two providers can each want their own
// ownership TXT, and SPF is deliberately excluded because deliver.Merge
// reconciles every provider's contribution into one record downstream.
func singleton(kind dns.Kind) bool {
	switch kind {
	case dns.KindDMARC, dns.KindMTASts, dns.KindTLSRpt, dns.KindBIMI:
		return true
	default:
		return false
	}
}

// Domains returns the domains this run covers, honouring -domain.
func (e *Engine) Domains() ([]config.Domain, error) { return e.selectedDomains() }

func (e *Engine) selectedDomains() ([]config.Domain, error) {
	if len(e.opts.Domains) == 0 {
		return e.cfg.Domains, nil
	}
	// Deduplicate requested domain names while preserving order (case-insensitive).
	seen := make(map[string]bool)
	var deduped []string
	for _, name := range e.opts.Domains {
		lower := strings.ToLower(name)
		if seen[lower] {
			continue
		}
		seen[lower] = true
		deduped = append(deduped, name)
	}
	var out []config.Domain
	for _, name := range deduped {
		d, ok := e.cfg.Domain(name)
		if !ok {
			return nil, fmt.Errorf("domain %s is not in the config", name)
		}
		out = append(out, d)
	}
	return out, nil
}

// recordKey returns the collision-detection key for a DNS record: lowercase
// kind, type, and normalized name (no trailing dot). Kind is included because
// two records can legitimately share a type and name with different content —
// Purelymail's apex TXT carries both an SPF record and an ownership proof —
// and dns.conflicts() already treats those as non-conflicting by Kind.
func recordKey(r dns.Record) string {
	return strings.ToLower(string(r.Kind) + " " + r.Type + " " + strings.TrimSuffix(r.Name, "."))
}

// sameContent reports whether the already-collected record for a key has the
// same content as a newly proposed one.
func sameContent(collected []dns.Record, key string, candidate dns.Record) bool {
	for _, record := range collected {
		if recordKey(record) == key {
			return strings.EqualFold(record.Content, candidate.Content)
		}
	}
	return false
}

// planWorker plans the upload and binding of the MTA-STS policy Worker. It is a
// no-op unless the domain sets mtaSts.deploy.
func (e *Engine) planWorker(ctx context.Context, d config.Domain, zoneID string, merged deliver.Result) ([]plan.Action, error) {
	if merged.MTAStsPolicy == "" || d.Deliverability.MTASts == nil || !d.Deliverability.MTASts.Deploy {
		return nil, nil
	}
	if e.deployer == nil {
		return nil, fmt.Errorf(
			"domain %s: mtaSts.deploy is true but cloudflare.accountId is not set in the config",
			d.Name)
	}

	name, err := worker.ScriptName(d.Name)
	if err != nil {
		return nil, err
	}
	source := worker.PolicyScript(merged.MTAStsPolicy)
	var actions []plan.Action

	matches, err := e.deployer.ScriptMatches(ctx, name, source)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if !matches {
		actions = append(actions, plan.Action{
			Op:       plan.OpUpdate,
			Resource: "worker",
			Domain:   d.Name,
			Provider: "cloudflare",
			Detail:   "upload MTA-STS policy Worker " + name,
			Do: func(ctx context.Context) error {
				return e.deployer.Upload(ctx, name, source)
			},
		})
	}

	attached, err := e.deployer.DomainAttached(ctx, merged.MTAStsHost, zoneID, name)
	if err != nil {
		return nil, fmt.Errorf("domain %s: check Worker custom domain %s: %w", d.Name, merged.MTAStsHost, err)
	}
	if !attached {
		host := merged.MTAStsHost
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "worker",
			Domain:   d.Name,
			Provider: "cloudflare",
			Detail:   fmt.Sprintf("bind %s to Worker %s", host, name),
			Do: func(ctx context.Context) error {
				return e.deployer.AttachDomain(ctx, host, zoneID, name)
			},
		})
	}
	return actions, nil
}
