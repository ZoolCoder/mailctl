package deliver

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

// DefaultMaxAge is one week, the value most published policies use.
const DefaultMaxAge = 604800

// MTAStsPolicy renders the policy file served at
// https://mta-sts.<domain>/.well-known/mta-sts.txt. The line order is fixed so
// that the same configuration always hashes to the same id.
func MTAStsPolicy(mode string, maxAge int, mx []string) string {
	var b strings.Builder
	b.WriteString("version: STSv1\n")
	fmt.Fprintf(&b, "mode: %s\n", mode)
	for _, host := range mx {
		fmt.Fprintf(&b, "mx: %s\n", host)
	}
	fmt.Fprintf(&b, "max_age: %d\n", maxAge)
	return b.String()
}

// MTAStsID is the policy id published in DNS: the first 16 hex characters of
// the policy's SHA-256. Deriving it from the text is what makes an edited
// policy actually reach receivers.
func MTAStsID(policy string) string {
	sum := sha256.Sum256([]byte(policy))
	return hex.EncodeToString(sum[:])[:16]
}

// MTASts returns the DNS records for MTA-STS and the policy text they refer to.
// The A/AAAA record for the mta-sts host is not returned here: binding the
// Worker to the custom domain creates it.
func MTASts(domain string, m config.MTASts, mx []string) ([]dns.Record, string, error) {
	if m.Mode == "" {
		return nil, "", nil
	}
	// mode: none withdraws enforcement and authorises nothing, so it needs no
	// mx line; every other mode without one would authorise no hosts.
	if m.Mode != "none" && len(mx) == 0 {
		return nil, "", fmt.Errorf(
			"domain %s: MTA-STS mode %s needs at least one MX host; a policy with no mx line authorises no hosts",
			domain, m.Mode)
	}

	maxAge := m.MaxAge
	if maxAge == 0 {
		maxAge = DefaultMaxAge
	}
	policy := MTAStsPolicy(m.Mode, maxAge, mx)

	records := []dns.Record{{
		Type:    "TXT",
		Name:    "_mta-sts." + domain,
		Content: "v=STSv1; id=" + MTAStsID(policy),
		Kind:    dns.KindMTASts,
	}}
	return records, policy, nil
}

// MXHosts extracts the MX targets from a record set, sorted and without
// trailing dots. Sorting matters: an unsorted list would hash differently on
// each run and republish the policy forever.
func MXHosts(records []dns.Record) []string {
	var hosts []string
	seen := map[string]bool{}
	for _, record := range records {
		if record.Kind != dns.KindMX {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(record.Content, "."))
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}
