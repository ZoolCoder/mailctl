package deliver

import (
	"fmt"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

// DMARC builds the _dmarc TXT record. Tag order follows the convention
// receivers' parsers are most commonly tested against; only v and p are
// actually required by RFC 7489.
func DMARC(domain string, d config.DMARC) dns.Record {
	tags := []string{"v=DMARC1", "p=" + d.Policy}
	if d.SubdomainPolicy != "" {
		tags = append(tags, "sp="+d.SubdomainPolicy)
	}
	tags = append(tags, fmt.Sprintf("pct=%d", d.Pct))
	if d.RUA != "" {
		tags = append(tags, "rua="+d.RUA)
	}
	if d.RUF != "" {
		tags = append(tags, "ruf="+d.RUF)
	}
	return dns.Record{
		Type:    "TXT",
		Name:    "_dmarc." + domain,
		Content: strings.Join(tags, "; "),
		Kind:    dns.KindDMARC,
	}
}

// TLSRpt builds the _smtp._tls TXT record that tells reporters where to send
// TLS failure reports.
func TLSRpt(domain, rua string) dns.Record {
	return dns.Record{
		Type:    "TXT",
		Name:    "_smtp._tls." + domain,
		Content: "v=TLSRPTv1; rua=" + rua,
		Kind:    dns.KindTLSRpt,
	}
}

// BIMI builds the default._bimi TXT record. The a= tag is only meaningful with
// a Verified Mark Certificate, which most senders do not have.
func BIMI(domain string, b config.BIMI) dns.Record {
	content := "v=BIMI1; l=" + b.Logo
	if b.VMC != "" {
		content += "; a=" + b.VMC
	}
	return dns.Record{
		Type:    "TXT",
		Name:    "default._bimi." + domain,
		Content: content,
		Kind:    dns.KindBIMI,
	}
}
