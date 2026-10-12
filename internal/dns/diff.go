package dns

import (
	"context"
	"fmt"

	"github.com/zoolcoder/mailctl/internal/plan"
)

type DiffOptions struct {
	// ReplaceConflicts deletes conflicting records instead of failing.
	ReplaceConflicts bool
}

// Diff returns the actions that bring a zone from actual to desired. It is
// additive: a record already in the zone that no desired record conflicts with
// is left untouched.
func Diff(p Provider, zoneID, domain string, actual []Existing, desired []Record, opts DiffOptions) ([]plan.Action, error) {
	var actions []plan.Action
	// A deletion planned for one desired record must not be planned again by a
	// later one, so track what is already scheduled to go.
	deleted := map[string]bool{}

	// An existing record that already satisfies some desired record must
	// never be treated as blocking a different desired record on the same
	// name. Without this, two desired records that share a Kind (Purelymail's
	// single MX, or Cloudflare Email Routing's several) make each other look
	// like conflicts: a converged zone becomes a hard error, and with
	// -replace-dns both correct records get deleted and only one recreated.
	protected := map[string]bool{}
	for _, have := range actual {
		for _, want := range desired {
			if same(have.Record, want) {
				protected[have.ID] = true
				break
			}
		}
	}

	for _, want := range desired {
		if want.Content == "" {
			return nil, fmt.Errorf("cloudflare: domain %s: refusing to publish an empty %s record for %s",
				domain, want.Type, want.Name)
		}

		satisfied := false
		var blocking []Existing
		for _, have := range actual {
			if deleted[have.ID] {
				continue
			}
			if same(have.Record, want) {
				satisfied = true
				continue
			}
			if protected[have.ID] {
				continue
			}
			if conflicts(have.Record, want) {
				blocking = append(blocking, have)
			}
		}

		// Handle blocking records separately for satisfied vs unsatisfied cases.
		// A name mailctl owns outright (F3) never needs -replace-dns: nothing
		// else legitimately lives there, so replacement is the routine
		// lifecycle of the feature, not a destructive surprise.
		if len(blocking) > 0 {
			if !opts.ReplaceConflicts && !ownedOutright(want.Kind) {
				// Different error messages depending on whether the desired record is satisfied
				if satisfied {
					return nil, fmt.Errorf(
						"cloudflare: domain %s: %s conflicts with the desired %s record and must be removed; rerun with -replace-dns",
						domain, blocking[0].Record.String(), want.Type)
				}
				return nil, fmt.Errorf(
					"cloudflare: domain %s: %s already exists and does not match the desired %s record; rerun with -replace-dns to replace it",
					domain, blocking[0].Record.String(), want.Type)
			}

			// Delete all blocking records
			for _, block := range blocking {
				block := block
				deleted[block.ID] = true
				actions = append(actions, plan.Action{
					Op:       plan.OpDelete,
					Resource: "dns",
					Domain:   domain,
					Provider: "cloudflare",
					Detail:   "conflicting " + block.Record.String(),
					Do: func(ctx context.Context) error {
						if err := p.Delete(ctx, zoneID, block.ID); err != nil {
							return fmt.Errorf("cloudflare: domain %s: delete %s: %w", domain, block.Record.String(), err)
						}
						return nil
					},
				})
			}
		}

		// If the desired record is already satisfied, don't create it
		if satisfied {
			continue
		}

		want := want
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "dns",
			Domain:   domain,
			Provider: "cloudflare",
			Detail:   want.String(),
			Do: func(ctx context.Context) error {
				if err := p.Create(ctx, zoneID, want); err != nil {
					return fmt.Errorf("cloudflare: domain %s: create %s: %w", domain, want.String(), err)
				}
				return nil
			},
		})
	}

	return actions, nil
}
