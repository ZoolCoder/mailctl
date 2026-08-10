package ms365

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zoolcoder/mailctl/internal/deliver"
	"github.com/zoolcoder/mailctl/internal/dns"
)

// emailService is the only supportedService mailctl publishes records for. SRV
// records, which the other writable services need, cannot be represented by
// dns.Record.
const emailService = "Email"

// dnsOnly is the Proxied value every CNAME uses. A proxied CNAME would route
// mail discovery through Cloudflare's proxy and break it.
var dnsOnly = false

// spacedMechanism matches an SPF mechanism separated from its value by
// whitespace, but only when what follows looks like the start of a real
// value (a letter, digit, "%" macro, or "_"). Microsoft's published example
// renders the record as "include: spf.protection.outlook.com"; left alone
// that produces a record which looks configured and fails at receiving
// servers. Requiring a value start also means a genuinely missing value —
// "include: -all", where the qualifier immediately follows — is left
// unwelded, so validation below still rejects it instead of reading the
// qualifier as the mechanism's value.
var spacedMechanism = regexp.MustCompile(`(?i)\b(include:|redirect=|exists:|exp=|a:|mx:|ptr:|ip4:|ip6:)\s+([A-Za-z0-9%_])`)

func normaliseSPF(text string) string {
	return spacedMechanism.ReplaceAllString(text, "${1}${2}")
}

// odataName strips the leading "#" and the namespace Graph prefixes to
// @odata.type, leaving e.g. "domainDnsMxRecord".
func odataName(odataType string) string {
	trimmed := strings.TrimPrefix(odataType, "#")
	if index := strings.LastIndex(trimmed, "."); index >= 0 {
		trimmed = trimmed[index+1:]
	}
	return trimmed
}

// toRecord converts one Graph DNS record. It never sets TTL: the DNS layer
// applies the configured value.
func toRecord(in domainDNSRecord) (dns.Record, error) {
	switch odataName(in.ODataType) {
	case "domainDnsMxRecord":
		return dns.Record{
			Type: "MX", Name: in.Label, Content: in.MailExchange,
			Priority: in.Preference, Kind: dns.KindMX,
		}, nil

	case "domainDnsTxtRecord":
		text, kind := in.Text, dns.KindOwnership
		if isSPF(text) {
			text = normaliseSPF(text)
			kind = dns.KindSPF
			// Fail here rather than publishing an SPF record that cannot work.
			if _, err := deliver.SPFMechanisms(text); err != nil {
				return dns.Record{}, fmt.Errorf(
					"Microsoft 365 returned an SPF record for %s that mailctl cannot use: %w", in.Label, err)
			}
		}
		return dns.Record{Type: "TXT", Name: in.Label, Content: text, Kind: kind}, nil

	case "domainDnsCnameRecord":
		return dns.Record{
			Type: "CNAME", Name: in.Label, Content: in.CanonicalName,
			Proxied: &dnsOnly, Kind: dns.KindOther,
		}, nil

	case "domainDnsSrvRecord":
		return dns.Record{}, fmt.Errorf(
			"Microsoft 365 requires an SRV record for %s, which mailctl cannot publish: dns.Record has no SRV fields; "+
				"mailctl only supports the Email service, so add this Teams or Skype record to DNS by hand",
			in.Label)

	case "domainDnsUnavailableRecord":
		return dns.Record{}, fmt.Errorf(
			"Microsoft 365 reports its DNS records for %s are not ready yet; rerun in a few minutes",
			in.Label)

	default:
		return dns.Record{}, fmt.Errorf(
			"Microsoft 365 returned an unrecognised DNS record type %q for %s; this is a mailctl gap worth reporting, naming the %s record",
			odataName(in.ODataType), in.Label, in.Label)
	}
}

func isSPF(text string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "v=spf1")
}

// desiredFromGraph builds the desired record set: the ownership TXT, the Email
// service records, and the two DKIM CNAMEs when configured.
func desiredFromGraph(ownership, service []domainDNSRecord, dkim []string, domain string) ([]dns.Record, error) {
	var out []dns.Record

	for _, in := range ownership {
		record, err := toRecord(in)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}

	for _, in := range service {
		if in.SupportedService != emailService {
			continue
		}
		// Optional records are service extras, not requirements. mailctl
		// defends and prunes what it publishes, so opting in on the
		// operator's behalf is the wrong default.
		if in.IsOptional {
			continue
		}
		record, err := toRecord(in)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}

	// Both selectors or neither: one alone signs nothing and looks configured.
	// Any other count is silently reachable from any caller in the package, so
	// it must fail loudly rather than quietly publish an incomplete DKIM setup.
	switch len(dkim) {
	case 0:
		// Nothing to publish.
	case 2:
		for i, target := range dkim {
			out = append(out, dns.Record{
				Type:    "CNAME",
				Name:    fmt.Sprintf("selector%d._domainkey.%s", i+1, domain),
				Content: target,
				Proxied: &dnsOnly,
				Kind:    dns.KindDKIM,
			})
		}
	default:
		return nil, fmt.Errorf(
			"domain %s: Microsoft 365 reported %d DKIM selector(s), want exactly two (selector1 and selector2) or none; rerun once both selectors are configured",
			domain, len(dkim))
	}

	return out, nil
}
