// Package dns models the DNS records mailctl publishes and diffs them against
// what a zone already contains.
package dns

import (
	"context"
	"fmt"
	"strings"
)

// Kind identifies what role a record plays, which decides what already-present
// record counts as a conflict.
type Kind string

const (
	KindMX        Kind = "mx"
	KindSPF       Kind = "spf"
	KindDKIM      Kind = "dkim"
	KindDMARC     Kind = "dmarc"
	KindOwnership Kind = "ownership"
	KindMTASts    Kind = "mtasts"
	KindTLSRpt    Kind = "tlsrpt"
	KindBIMI      Kind = "bimi"
	KindOther     Kind = "other"
)

type Record struct {
	Type     string
	Name     string
	Content  string
	TTL      int
	Priority int
	Proxied  *bool
	Kind     Kind
}

// Existing is a record already published in a zone.
type Existing struct {
	Record
	ID string
}

type Zone struct {
	ID   string
	Name string
}

// Provider is a DNS zone mailctl can read and change.
type Provider interface {
	Zone(ctx context.Context, name string) (Zone, error)
	Records(ctx context.Context, zoneID string) ([]Existing, error)
	Create(ctx context.Context, zoneID string, r Record) error
	Delete(ctx context.Context, zoneID, recordID string) error
}

func (r Record) String() string {
	out := fmt.Sprintf("%s %s -> %s", r.Type, r.Name, r.Content)
	if r.Priority > 0 {
		out += fmt.Sprintf(" priority=%d", r.Priority)
	}
	return out
}

// same reports whether an existing record already satisfies a desired one.
// Comparison is case-insensitive and ignores the trailing dot Cloudflare adds
// to CNAME and MX targets.
func same(existing, desired Record) bool {
	if !strings.EqualFold(existing.Type, desired.Type) {
		return false
	}
	if !equalHost(existing.Name, desired.Name) {
		return false
	}
	if !equalHost(existing.Content, desired.Content) {
		return false
	}
	if desired.Priority > 0 && existing.Priority != desired.Priority {
		return false
	}
	return true
}

func equalHost(a, b string) bool {
	return strings.EqualFold(unquote(strings.TrimSuffix(a, ".")), unquote(strings.TrimSuffix(b, ".")))
}

// ownedOutright reports whether a kind lives on a name that nothing else
// legitimately occupies, so an existing record blocking it can be replaced
// without -replace-dns. SPF is deliberately excluded: it sits on the apex
// alongside unrelated TXT records, and a pre-existing one there may belong to
// another provider entirely, so replacing it needs the flag's explicit
// confirmation.
func ownedOutright(kind Kind) bool {
	switch kind {
	case KindMTASts, KindDMARC, KindTLSRpt, KindBIMI, KindDKIM:
		return true
	default:
		return false
	}
}

// unquote strips one layer of surrounding double quotes. Some DNS providers
// return TXT content quoted; mailctl never writes quotes itself, so this only
// ever affects records read back from a zone.
func unquote(s string) string {
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		return s[1 : len(s)-1]
	}
	return s
}

// conflicts reports whether an existing record blocks a desired one. Only
// records on the same name can conflict.
func conflicts(existing, desired Record) bool {
	if !equalHost(existing.Name, desired.Name) {
		return false
	}
	content := strings.ToLower(unquote(strings.TrimSpace(existing.Content)))
	isTXT := strings.EqualFold(existing.Type, "TXT")

	switch desired.Kind {
	case KindMX:
		return strings.EqualFold(existing.Type, "MX")
	case KindSPF:
		return isTXT && strings.HasPrefix(content, "v=spf1")
	case KindMTASts:
		return isTXT && strings.HasPrefix(content, "v=stsv1")
	case KindTLSRpt:
		return isTXT && strings.HasPrefix(content, "v=tlsrptv1")
	case KindBIMI:
		return isTXT && strings.HasPrefix(content, "v=bimi1")
	case KindOwnership:
		// Ownership TXT records sit alongside anything else on the apex.
		return false
	case KindDKIM, KindDMARC:
		// These live on names mailctl owns outright, so anything there is stale.
		return true
	default:
		return strings.EqualFold(existing.Type, desired.Type)
	}
}
