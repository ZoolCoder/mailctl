package deliver

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func providerRecords() []dns.Record {
	off := false
	return []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: "a.com", Content: "purelymail_ownership_proof=abc", Kind: dns.KindOwnership},
		{Type: "CNAME", Name: "purelymail1._domainkey.a.com", Content: "key1.dkimroot.purelymail.com",
			Proxied: &off, Kind: dns.KindDKIM},
	}
}

func countKind(records []dns.Record, kind dns.Kind) int {
	n := 0
	for _, r := range records {
		if r.Kind == kind {
			n++
		}
	}
	return n
}

func TestMergePassesProviderRecordsThrough(t *testing.T) {
	got, err := Merge(config.Domain{Name: "a.com"}, providerRecords())
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if countKind(got.Records, dns.KindMX) != 1 || countKind(got.Records, dns.KindOwnership) != 1 ||
		countKind(got.Records, dns.KindDKIM) != 1 {
		t.Errorf("records = %+v, want the provider MX, ownership, and DKIM records preserved", got.Records)
	}
	if countKind(got.Records, dns.KindSPF) != 1 {
		t.Errorf("SPF count = %d, want exactly one merged record", countKind(got.Records, dns.KindSPF))
	}
}

func TestMergePassesThroughNonApexSPF(t *testing.T) {
	// A provider SPF record on a subdomain (cfsending's send.a.com, say) is
	// not MergeSPF's business, and dropping it silently would break outbound
	// mail from that subdomain (C3). It must survive untouched while the
	// apex records still fold into exactly one record.
	records := append(providerRecords(), dns.Record{
		Type: "TXT", Name: "send.a.com", Content: "v=spf1 include:_spf.cfsending.example ~all", Kind: dns.KindSPF,
	})

	got, err := Merge(config.Domain{Name: "a.com"}, records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	var apex, subdomain int
	for _, r := range got.Records {
		if r.Kind != dns.KindSPF {
			continue
		}
		switch r.Name {
		case "a.com":
			apex++
		case "send.a.com":
			subdomain++
			if r.Content != "v=spf1 include:_spf.cfsending.example ~all" {
				t.Errorf("subdomain SPF content = %q, want it unchanged", r.Content)
			}
		default:
			t.Errorf("unexpected SPF record name %q", r.Name)
		}
	}
	if apex != 1 {
		t.Errorf("apex SPF count = %d, want exactly one merged record", apex)
	}
	if subdomain != 1 {
		t.Errorf("subdomain SPF count = %d, want the send.a.com record to survive untouched", subdomain)
	}
}

func TestMergeAppliesConfigSPFIncludes(t *testing.T) {
	d := config.Domain{Name: "a.com"}
	d.Deliverability.SPFIncludes = []string{"include:servers.mailgun.org"}

	got, err := Merge(d, providerRecords())
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	for _, r := range got.Records {
		if r.Kind == dns.KindSPF {
			if !strings.Contains(r.Content, "servers.mailgun.org") ||
				!strings.Contains(r.Content, "_spf.purelymail.com") {
				t.Errorf("SPF = %q, want both includes in one record", r.Content)
			}
			return
		}
	}
	t.Fatal("no SPF record produced")
}

func TestMergeReplacesProviderDMARCWithTheConfiguredPolicy(t *testing.T) {
	off := false
	records := append(providerRecords(), dns.Record{
		Type: "CNAME", Name: "_dmarc.a.com", Content: "dmarcroot.purelymail.com",
		Proxied: &off, Kind: dns.KindDMARC,
	})

	d := config.Domain{Name: "a.com"}
	d.Deliverability.DMARC = &config.DMARC{Policy: "reject", Pct: 100}

	got, err := Merge(d, records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if countKind(got.Records, dns.KindDMARC) != 1 {
		t.Fatalf("DMARC count = %d, want exactly one", countKind(got.Records, dns.KindDMARC))
	}
	for _, r := range got.Records {
		if r.Kind == dns.KindDMARC && r.Type != "TXT" {
			t.Errorf("DMARC record = %+v, want the configured TXT policy to win over a provider CNAME", r)
		}
	}
}

func TestMergePassesThroughProviderDMARCWhenConfigHasNone(t *testing.T) {
	off := false
	records := append(providerRecords(), dns.Record{
		Type: "CNAME", Name: "_dmarc.a.com", Content: "dmarcroot.purelymail.com",
		Proxied: &off, Kind: dns.KindDMARC,
	})

	d := config.Domain{Name: "a.com"}
	// d.Deliverability.DMARC is nil, so provider record should pass through

	got, err := Merge(d, records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if countKind(got.Records, dns.KindDMARC) != 1 {
		t.Fatalf("DMARC count = %d, want exactly one", countKind(got.Records, dns.KindDMARC))
	}
	for _, r := range got.Records {
		if r.Kind == dns.KindDMARC {
			if r.Type != "CNAME" {
				t.Errorf("DMARC record Type = %q, want CNAME (provider record)", r.Type)
			}
			if r.Content != "dmarcroot.purelymail.com" {
				t.Errorf("DMARC record Content = %q, want dmarcroot.purelymail.com (unchanged from provider)", r.Content)
			}
			return
		}
	}
	t.Fatal("DMARC record not found")
}

func TestMergeAddsTLSRptBIMIAndMTASts(t *testing.T) {
	d := config.Domain{Name: "a.com"}
	d.Deliverability.TLSRpt = "mailto:tls@a.com"
	d.Deliverability.BIMI = &config.BIMI{Logo: "https://a.com/logo.svg"}
	d.Deliverability.MTASts = &config.MTASts{Mode: "enforce", MaxAge: 604800, Deploy: true}

	got, err := Merge(d, providerRecords())
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	for _, kind := range []dns.Kind{dns.KindTLSRpt, dns.KindBIMI, dns.KindMTASts} {
		if countKind(got.Records, kind) != 1 {
			t.Errorf("%s count = %d, want 1", kind, countKind(got.Records, kind))
		}
	}
	if !strings.Contains(got.MTAStsPolicy, "mx: mailserver.purelymail.com") {
		t.Errorf("policy = %q, want it built from the provider MX record", got.MTAStsPolicy)
	}
	if got.MTAStsHost != "mta-sts.a.com" {
		t.Errorf("host = %q, want mta-sts.a.com", got.MTAStsHost)
	}
}

func TestMergeIsDeterministic(t *testing.T) {
	d := config.Domain{Name: "a.com"}
	d.Deliverability.MTASts = &config.MTASts{Mode: "enforce", Deploy: true}

	// Hoist providerRecords() to a single call. The struct comparison below uses ==,
	// which includes pointer identity of the Proxied field. A single input slice ensures
	// that records passed through by value have identical pointers in both runs, while
	// a rebuild would change pointer addresses and be caught by the test.
	records := providerRecords()

	first, err := Merge(d, records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	second, err := Merge(d, records)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}

	if len(first.Records) != len(second.Records) {
		t.Fatalf("record counts differ between runs: %d and %d", len(first.Records), len(second.Records))
	}
	for i := range first.Records {
		if first.Records[i] != second.Records[i] {
			t.Fatalf("record %d differs between runs:\n%+v\n%+v", i, first.Records[i], second.Records[i])
		}
	}
}

func TestMergeReturnsZeroResultOnMTAStsError(t *testing.T) {
	d := config.Domain{Name: "a.com"}
	d.Deliverability.MTASts = &config.MTASts{Mode: "enforce", Deploy: true}
	d.Deliverability.TLSRpt = "mailto:tls@a.com"
	d.Deliverability.BIMI = &config.BIMI{Logo: "https://a.com/logo.svg"}

	// providerRecords has MX, so this alone would not error.
	// Create records with no MX to trigger MTASts error.
	records := []dns.Record{
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: "a.com", Content: "purelymail_ownership_proof=abc", Kind: dns.KindOwnership},
	}

	got, err := Merge(d, records)
	if err == nil {
		t.Fatal("Merge: expected error with enforce mode and no MX, got nil")
	}

	// Must return zero Result, not a partial one with accumulated records.
	if len(got.Records) != 0 || got.MTAStsPolicy != "" || got.MTAStsHost != "" {
		t.Errorf("Merge: got non-zero Result on error: %+v, want all zero fields", got)
	}
}
