package deliver

import (
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

// Result is the final desired DNS set for a domain plus everything the engine
// needs to deploy the MTA-STS policy.
type Result struct {
	Records []dns.Record
	// MTAStsPolicy is the policy file body, empty when MTA-STS is off.
	MTAStsPolicy string
	// MTAStsHost is the hostname the policy is served from, empty when off.
	MTAStsHost string
}

// Merge folds the deliverability layer into the records the mail providers
// asked for. Provider SPF records are collapsed into one; a provider DMARC
// record is dropped when the config declares its own policy.
func Merge(d config.Domain, providerRecords []dns.Record) (Result, error) {
	var out Result
	v := d.Deliverability
	configOwnsDMARC := v.DMARC != nil

	for _, record := range providerRecords {
		switch record.Kind {
		case dns.KindSPF:
			// Only an apex SPF record is MergeSPF's business, collected and
			// re-emitted once, below. A record on any other name (a sending
			// subdomain, say) is not something MergeSPF looks at, so it must
			// pass straight through here or it vanishes with no error (C3).
			if !strings.EqualFold(strings.TrimSuffix(record.Name, "."), d.Name) {
				out.Records = append(out.Records, record)
			}
			continue
		case dns.KindDMARC:
			if configOwnsDMARC {
				continue
			}
		}
		out.Records = append(out.Records, record)
	}

	spf, ok, err := MergeSPF(d.Name, providerRecords, v.SPFIncludes)
	if err != nil {
		return Result{}, err
	}
	if ok {
		out.Records = append(out.Records, spf)
	}
	if configOwnsDMARC {
		out.Records = append(out.Records, DMARC(d.Name, *v.DMARC))
	}
	if v.TLSRpt != "" {
		out.Records = append(out.Records, TLSRpt(d.Name, v.TLSRpt))
	}
	if v.BIMI != nil {
		out.Records = append(out.Records, BIMI(d.Name, *v.BIMI))
	}

	if v.MTASts != nil {
		records, policy, err := MTASts(d.Name, *v.MTASts, MXHosts(providerRecords))
		if err != nil {
			return Result{}, err
		}
		out.Records = append(out.Records, records...)
		if policy != "" {
			out.MTAStsPolicy = policy
			out.MTAStsHost = "mta-sts." + d.Name
		}
	}
	return out, nil
}
