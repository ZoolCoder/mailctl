package ms365

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestToRecordMapsEachODataType(t *testing.T) {
	cases := []struct {
		name string
		in   domainDNSRecord
		want dns.Record
	}{
		{
			name: "mx",
			in: domainDNSRecord{
				ODataType: "#microsoft.graph.domainDnsMxRecord",
				Label:     "example.com", RecordType: "Mx", SupportedService: "Email",
				MailExchange: "example-com.mail.protection.outlook.com", Preference: 0,
			},
			want: dns.Record{Type: "MX", Name: "example.com",
				Content: "example-com.mail.protection.outlook.com", Kind: dns.KindMX},
		},
		{
			name: "spf txt",
			in: domainDNSRecord{
				ODataType: "#microsoft.graph.domainDnsTxtRecord",
				Label:     "example.com", RecordType: "Txt", SupportedService: "Email",
				Text: "v=spf1 include:spf.protection.outlook.com -all",
			},
			want: dns.Record{Type: "TXT", Name: "example.com",
				Content: "v=spf1 include:spf.protection.outlook.com -all", Kind: dns.KindSPF},
		},
		{
			name: "non-spf txt is ownership",
			in: domainDNSRecord{
				ODataType: "#microsoft.graph.domainDnsTxtRecord",
				Label:     "example.com", RecordType: "Txt", SupportedService: "Email",
				Text: "MS=ms12345678",
			},
			want: dns.Record{Type: "TXT", Name: "example.com",
				Content: "MS=ms12345678", Kind: dns.KindOwnership},
		},
		{
			name: "cname",
			in: domainDNSRecord{
				ODataType: "#microsoft.graph.domainDnsCnameRecord",
				Label:     "autodiscover.example.com", RecordType: "CName", SupportedService: "Email",
				CanonicalName: "autodiscover.outlook.com",
			},
			want: dns.Record{Type: "CNAME", Name: "autodiscover.example.com",
				Content: "autodiscover.outlook.com", Kind: dns.KindOther},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toRecord(tc.in)
			if err != nil {
				t.Fatalf("toRecord: %v", err)
			}
			if got.Type != tc.want.Type || got.Name != tc.want.Name ||
				got.Content != tc.want.Content || got.Kind != tc.want.Kind {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			if tc.want.Type == "CNAME" {
				if got.Proxied == nil || *got.Proxied {
					t.Error("a CNAME must set Proxied to false; a proxied CNAME breaks mail discovery")
				}
			}
			if got.TTL != 0 {
				t.Errorf("TTL = %d, want 0; the DNS layer applies the configured TTL", got.TTL)
			}
		})
	}
}

func TestToRecordNormalisesTheSpacedIncludeForm(t *testing.T) {
	// Microsoft's own documentation prints the record this way.
	got, err := toRecord(domainDNSRecord{
		ODataType: "#microsoft.graph.domainDnsTxtRecord",
		Label:     "example.com", SupportedService: "Email",
		Text: "v=spf1 include: spf.protection.outlook.com ~all",
	})
	if err != nil {
		t.Fatalf("toRecord: %v", err)
	}
	want := "v=spf1 include:spf.protection.outlook.com ~all"
	if got.Content != want {
		t.Fatalf("Content = %q, want %q", got.Content, want)
	}
}

func TestToRecordRejectsAMissingIncludeValueEvenAcrossWhitespace(t *testing.T) {
	// The qualifier immediately follows the mechanism prefix with only
	// whitespace between them; normalising must not weld the two together
	// into an include with the qualifier as its bogus "value".
	_, err := toRecord(domainDNSRecord{
		ODataType: "#microsoft.graph.domainDnsTxtRecord",
		Label:     "example.com", SupportedService: "Email",
		Text: "v=spf1 include: -all",
	})
	if err == nil {
		t.Fatal("want an error; \"include: -all\" has no include value")
	}
}

func TestNormaliseSPFPreservesLegalValueStarts(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "underscore-led value",
			text: "v=spf1 include: _spf.example.com ~all",
			want: "v=spf1 include:_spf.example.com ~all",
		},
		{
			name: "percent-led macro value",
			text: "v=spf1 exists: %{i}._spf.example.com ~all",
			want: "v=spf1 exists:%{i}._spf.example.com ~all",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := toRecord(domainDNSRecord{
				ODataType: "#microsoft.graph.domainDnsTxtRecord",
				Label:     "example.com", SupportedService: "Email",
				Text: tc.text,
			})
			if err != nil {
				t.Fatalf("toRecord: %v", err)
			}
			if got.Content != tc.want {
				t.Fatalf("Content = %q, want %q", got.Content, tc.want)
			}
		})
	}
}

func TestToRecordRefusesSRVAndUnavailable(t *testing.T) {
	cases := []struct {
		name string
		in   domainDNSRecord
		want []string
	}{
		{"srv", domainDNSRecord{ODataType: "#microsoft.graph.domainDnsSrvRecord", Label: "_sip.example.com"},
			[]string{"SRV", "Teams or Skype", "by hand"}},
		{"unavailable", domainDNSRecord{ODataType: "#microsoft.graph.domainDnsUnavailableRecord", Label: "example.com"},
			[]string{"not ready"}},
		{"unknown", domainDNSRecord{ODataType: "#microsoft.graph.domainDnsFutureRecord", Label: "example.com"},
			[]string{"domainDnsFutureRecord", "worth reporting", "example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := toRecord(tc.in)
			if err == nil {
				t.Fatal("want an error")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

func TestDesiredFromGraphFiltersAndAddsDKIM(t *testing.T) {
	ownership := []domainDNSRecord{{
		ODataType: "#microsoft.graph.domainDnsTxtRecord",
		Label:     "example.com", Text: "MS=ms12345678", SupportedService: "Email",
	}}
	service := []domainDNSRecord{
		{ODataType: "#microsoft.graph.domainDnsMxRecord", Label: "example.com",
			MailExchange: "example-com.mail.protection.outlook.com", SupportedService: "Email"},
		{ODataType: "#microsoft.graph.domainDnsTxtRecord", Label: "example.com",
			Text: "v=spf1 include:spf.protection.outlook.com -all", SupportedService: "Email"},
		// Filtered out: another service.
		{ODataType: "#microsoft.graph.domainDnsSrvRecord", Label: "_sip.example.com",
			SupportedService: "OfficeCommunicationsOnline"},
		// Filtered out: optional.
		{ODataType: "#microsoft.graph.domainDnsCnameRecord", Label: "extra.example.com",
			CanonicalName: "x.outlook.com", SupportedService: "Email", IsOptional: true},
	}
	dkim := []string{
		"selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft",
		"selector2-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft",
	}

	got, err := desiredFromGraph(ownership, service, dkim, "example.com")
	if err != nil {
		t.Fatalf("desiredFromGraph: %v", err)
	}

	byName := map[string]dns.Record{}
	for _, r := range got {
		byName[r.Type+" "+r.Name] = r
	}
	for _, want := range []string{
		"TXT example.com", "MX example.com",
		"CNAME selector1._domainkey.example.com",
		"CNAME selector2._domainkey.example.com",
	} {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing %s", want)
		}
	}
	if _, ok := byName["CNAME extra.example.com"]; ok {
		t.Error("an isOptional record must not be published")
	}
	if len(got) != 5 {
		t.Errorf("len = %d, want 5 (ownership, MX, SPF, two DKIM)", len(got))
	}
	if r := byName["CNAME selector1._domainkey.example.com"]; r.Content != dkim[0] {
		t.Errorf("selector1 target = %q, want %q", r.Content, dkim[0])
	}
	if r := byName["CNAME selector1._domainkey.example.com"]; r.Kind != dns.KindDKIM {
		t.Errorf("selector1 Kind = %q, want dkim", r.Kind)
	}
}

func TestDesiredFromGraphWithoutDKIMOmitsBoth(t *testing.T) {
	got, err := desiredFromGraph(nil, nil, nil, "example.com")
	if err != nil {
		t.Fatalf("desiredFromGraph: %v", err)
	}
	for _, r := range got {
		if strings.Contains(r.Name, "_domainkey") {
			t.Fatalf("unexpected DKIM record %v when dkimCnames is empty", r)
		}
	}
}

func TestDesiredFromGraphRejectsALopsidedDKIMSlice(t *testing.T) {
	// One or three selectors is not a state the config layer ever asks for
	// deliberately; desiredFromGraph must not depend on a caller having
	// already validated for it.
	cases := []struct {
		name string
		dkim []string
	}{
		{"one selector", []string{"selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft"}},
		{"three selectors", []string{"a.dkim.mail.microsoft", "b.dkim.mail.microsoft", "c.dkim.mail.microsoft"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := desiredFromGraph(nil, nil, tc.dkim, "example.com"); err == nil {
				t.Fatal("want an error rather than silently publishing an incomplete DKIM setup")
			}
		})
	}
}

func TestDesiredFromGraphPropagatesAnSRVInTheEmailSet(t *testing.T) {
	// An SRV record claiming to be an Email record cannot be represented; it
	// must be an error, not a dropped record.
	service := []domainDNSRecord{{
		ODataType: "#microsoft.graph.domainDnsSrvRecord",
		Label:     "_sip.example.com", SupportedService: "Email",
	}}
	if _, err := desiredFromGraph(nil, service, nil, "example.com"); err == nil {
		t.Fatal("want an error rather than a silently dropped record")
	}
}
