// Package deliver builds the deliverability DNS records for a domain. Every
// function here is pure: same inputs, same records, no I/O.
package deliver

import (
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/dns"
)

// allQualifiers are ordered from most permissive to strictest. Merging keeps
// the strictest one any input asked for, because loosening a policy silently
// is the worse mistake.
var allQualifiers = []string{"+all", "?all", "~all", "-all"}

// SPFMechanisms returns the mechanisms of an SPF record, excluding the v=spf1
// prefix and any trailing all qualifier. A mechanism that names no value — a
// bare "include:" left by whitespace after the colon — is an error rather than
// a mechanism, because publishing it produces a record that looks configured
// and fails at receiving servers.
func SPFMechanisms(content string) ([]string, error) {
	var out []string
	for _, token := range strings.Fields(content) {
		lower := strings.ToLower(token)
		if lower == "v=spf1" || strings.HasSuffix(lower, "all") && qualifierRank(lower) >= 0 {
			continue
		}
		if valueless(lower) {
			return nil, fmt.Errorf(
				"SPF record %q contains %q with no value; a mechanism and its value must not be separated by whitespace",
				content, token)
		}
		out = append(out, token)
	}
	return out, nil
}

// needsValue lists the SPF mechanisms and modifiers that require a value.
var needsValue = []string{"include:", "redirect=", "exists:", "exp=", "a:", "mx:", "ptr:", "ip4:", "ip6:"}

// alwaysNeedsValue lists the mechanisms and modifiers that require a value
// under every spelling, including a bare name with no ":" or "=" at all
// (RFC 7208). "a", "mx" and "ptr" are deliberately excluded: bare, they are
// legal SPF mechanisms meaning the domain's own A/MX records ("ptr" bare is
// legal though deprecated), so rejecting them would break working domains.
var alwaysNeedsValue = []string{"include", "exists", "ip4", "ip6", "redirect", "exp"}

// valueless reports whether a token is one of those prefixes — or, for the
// mechanisms that never make sense without a value, one of those bare
// names — with nothing after it.
func valueless(token string) bool {
	trimmed := strings.TrimLeft(token, "+-~?")
	for _, prefix := range needsValue {
		if trimmed == prefix {
			return true
		}
	}
	for _, name := range alwaysNeedsValue {
		if trimmed == name {
			return true
		}
	}
	return false
}

// MergeSPF folds every SPF record the providers asked for, plus any extra
// mechanisms from config, into one record. It reports false when there is
// nothing to publish, and an error when a record contains a mechanism with
// no value rather than republishing an SPF record that will fail at
// receiving servers.
func MergeSPF(domain string, records []dns.Record, extra []string) (dns.Record, bool, error) {
	var mechanisms []string
	seen := map[string]bool{}
	qualifier := ""

	add := func(list []string) {
		for _, mechanism := range list {
			key := strings.ToLower(mechanism)
			if seen[key] {
				continue
			}
			seen[key] = true
			mechanisms = append(mechanisms, mechanism)
		}
	}

	for _, record := range records {
		if record.Kind != dns.KindSPF {
			continue
		}
		// A provider's SPF record for a subdomain must not be relocated onto
		// the apex; only the domain's own apex record is eligible to merge.
		if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), domain) {
			continue
		}
		found, err := SPFMechanisms(record.Content)
		if err != nil {
			return dns.Record{}, false, fmt.Errorf("SPF record %q on %q: %w", record.Content, record.Name, err)
		}
		add(found)
		qualifier = strictest(qualifier, findQualifier(record.Content))
	}
	// Route config includes through the same mechanism filter as provider
	// records, so a stray qualifier or bare "all" in config cannot slip
	// through a second, unfiltered path.
	fromExtra, err := SPFMechanisms("v=spf1 " + strings.Join(extra, " "))
	if err != nil {
		return dns.Record{}, false, fmt.Errorf("SPF config includes for %q: %w", domain, err)
	}
	add(fromExtra)

	if len(mechanisms) == 0 {
		if qualifier == "" {
			return dns.Record{}, false, nil
		}
		// A qualifier was found but no mechanism survived filtering (e.g. an
		// input record was just "v=spf1 all"): publish the qualifier alone
		// rather than dropping the record entirely.
		return dns.Record{Type: "TXT", Name: domain, Content: "v=spf1 " + qualifier, Kind: dns.KindSPF}, true, nil
	}
	if qualifier == "" {
		qualifier = "~all"
	}

	content := "v=spf1 " + strings.Join(mechanisms, " ") + " " + qualifier
	return dns.Record{Type: "TXT", Name: domain, Content: content, Kind: dns.KindSPF}, true, nil
}

func findQualifier(content string) string {
	for _, token := range strings.Fields(content) {
		lower := strings.ToLower(token)
		if qualifierRank(lower) >= 0 {
			return lower
		}
	}
	return ""
}

func strictest(a, b string) string {
	if qualifierRank(b) > qualifierRank(a) {
		return b
	}
	return a
}

// qualifierRank returns the strictness of an all qualifier, or -1 if the token
// is not one.
func qualifierRank(token string) int {
	for i, candidate := range allQualifiers {
		if token == candidate {
			return i
		}
	}
	if token == "all" {
		return 0
	}
	return -1
}
