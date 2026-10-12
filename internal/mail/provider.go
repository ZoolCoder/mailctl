// Package mail defines the interface every mail provider implements and the
// vocabulary the engine uses to talk about provider-side state.
package mail

import (
	"context"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

// Provider is one mail service managing one or more domains.
type Provider interface {
	Name() string

	// DesiredDNS returns the records this provider needs published for the
	// domain. Providers that expose a DNS endpoint fetch them; providers that
	// do not construct them.
	DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error)

	// Actual reads current provider-side state for the domain.
	Actual(ctx context.Context, d config.Domain) (State, error)

	// Plan diffs the config against actual and returns ordered actions. Plan
	// performs no I/O; the returned actions carry closures that do.
	Plan(d config.Domain, actual State, opts Options) ([]plan.Action, error)
}

// State is provider-side reality for one domain.
type State struct {
	DomainExists bool
	Settings     Settings
	Mailboxes    []Mailbox
	Aliases      []Alias
	CatchAll     *CatchAll
	// Verified and SupportedServices are set by providers that have a
	// verification step; Purelymail leaves them zero.
	Verified          bool
	SupportedServices []string
	// Notes are provider observations worth showing in plan output, such as
	// "DNS check: mx=true spf=false".
	Notes []string
}

type Settings struct {
	AllowAccountReset     bool
	SymbolicSubaddressing bool
}

type Mailbox struct {
	Address string
	// AlternateAddress is a second identity address config may name for this
	// same mailbox, set by providers with two distinct identity attributes
	// that can diverge (Microsoft Graph's mail and userPrincipalName, after an
	// admin changes either one independently). Address holds whichever the
	// provider prefers to display; AlternateAddress holds the other one, when
	// it differs and is non-empty. Providers with a single address identity
	// leave it empty.
	AlternateAddress string
	// ID is the provider's own object identifier for this mailbox, set by
	// providers that need one to act on a mailbox unambiguously (e.g.
	// Microsoft Graph, which resolves /users/{id} by id or userPrincipalName,
	// never by an arbitrary address). Providers that address mailboxes by name
	// leave it empty; Purelymail deletes by address via its own API, so it does.
	ID string
	// AssignedSkuIDs are the licence SKU ids already assigned to this
	// mailbox, set by providers with a licence concept so Plan can detect an
	// existing-but-unlicensed account without I/O. Purelymail leaves it empty.
	AssignedSkuIDs []string
	Recovery       []Recovery
}

type Recovery struct {
	ID          string
	Type        string // email | phone
	Target      string
	Description string
}

type Alias struct {
	ID     string
	Match  string // local part, without any trailing *
	Prefix bool
	To     []string
}

type CatchAll struct {
	ID string
	To []string
}

// Options are the flags that change what Plan produces.
type Options struct {
	// Prune plans deletion of provider-side objects absent from the config.
	Prune bool
	// PruneMailboxes allows Prune to plan mailbox deletion. It is a second
	// opt-in because deleting a mailbox destroys mail, and a prune scope wider
	// than the operator intended has already caused data loss in this project.
	PruneMailboxes bool
	// Secrets resolves mailbox credentials.
	Secrets *secret.Resolver
}

// Mailbox returns the state entry for an address, and whether it exists.
// A match on AlternateAddress counts too, so a provider whose two identity
// attributes have diverged is still found by whichever one config names.
func (s State) Mailbox(address string) (Mailbox, bool) {
	for _, m := range s.Mailboxes {
		if equalFold(m.Address, address) {
			return m, true
		}
		if m.AlternateAddress != "" && equalFold(m.AlternateAddress, address) {
			return m, true
		}
	}
	return Mailbox{}, false
}

// Alias returns the state entry matching a local part and prefix flag.
func (s State) Alias(match string, prefix bool) (Alias, bool) {
	for _, a := range s.Aliases {
		if equalFold(a.Match, match) && a.Prefix == prefix {
			return a, true
		}
	}
	return Alias{}, false
}

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
