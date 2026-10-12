package deliver

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/dns"
)

func spf(content string) dns.Record {
	return dns.Record{Type: "TXT", Name: "a.com", Content: content, Kind: dns.KindSPF}
}

func TestSPFMechanismsSplitsOnWhitespace(t *testing.T) {
	got, err := SPFMechanisms("v=spf1  include:_spf.one.com   include:two.com  ~all")
	if err != nil {
		t.Fatalf("SPFMechanisms: %v", err)
	}

	want := []string{"include:_spf.one.com", "include:two.com"}
	if len(got) != len(want) {
		t.Fatalf("mechanisms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanism %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMergeSPFCombinesProvidersAndConfig(t *testing.T) {
	records := []dns.Record{
		spf("v=spf1 include:_spf.purelymail.com ~all"),
		spf("v=spf1 include:_spf.mx.cloudflare.net ~all"),
	}

	got, ok, err := MergeSPF("a.com", records, []string{"include:servers.mailgun.org"})
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false with SPF records present")
	}
	want := "v=spf1 include:_spf.purelymail.com include:_spf.mx.cloudflare.net include:servers.mailgun.org ~all"
	if got.Content != want {
		t.Errorf("content = %q,\nwant                %q", got.Content, want)
	}
	if got.Kind != dns.KindSPF || got.Type != "TXT" || got.Name != "a.com" {
		t.Errorf("record = %+v, want a TXT SPF record on the apex", got)
	}
}

func TestMergeSPFDropsDuplicateMechanisms(t *testing.T) {
	records := []dns.Record{
		spf("v=spf1 include:_spf.purelymail.com ~all"),
		spf("v=spf1 Include:_spf.Purelymail.com ~all"),
	}

	got, _, err := MergeSPF("a.com", records, []string{"include:_spf.purelymail.com"})
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if got.Content != "v=spf1 include:_spf.purelymail.com ~all" {
		t.Errorf("content = %q, want the mechanism exactly once in the casing of the first occurrence", got.Content)
	}
}

func TestMergeSPFKeepsTheStrictestAllQualifier(t *testing.T) {
	tests := []struct {
		name     string
		contents []string
		want     string
	}{
		{"softfail and softfail", []string{"v=spf1 include:a ~all", "v=spf1 include:b ~all"}, "~all"},
		{"softfail and fail keeps fail", []string{"v=spf1 include:a ~all", "v=spf1 include:b -all"}, "-all"},
		{"neutral and softfail keeps softfail", []string{"v=spf1 include:a ?all", "v=spf1 include:b ~all"}, "~all"},
		{"missing all defaults to softfail", []string{"v=spf1 include:a"}, "~all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := make([]dns.Record, 0, len(tt.contents))
			for _, c := range tt.contents {
				records = append(records, spf(c))
			}
			got, _, err := MergeSPF("a.com", records, nil)
			if err != nil {
				t.Fatalf("MergeSPF: %v", err)
			}
			if !hasSuffix(got.Content, " "+tt.want) {
				t.Errorf("content = %q, want it to end with %q", got.Content, tt.want)
			}
		})
	}
}

func TestMergeSPFReportsNothingWhenNoSPFRecordsExist(t *testing.T) {
	_, ok, err := MergeSPF("a.com", nil, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if ok {
		t.Error("ok = true with no SPF inputs; a domain with no sending provider needs no SPF record")
	}
}

func TestMergeSPFBuildsFromConfigAloneWhenAsked(t *testing.T) {
	got, ok, err := MergeSPF("a.com", nil, []string{"include:servers.mailgun.org"})
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("config includes alone should still produce a record")
	}
	if got.Content != "v=spf1 include:servers.mailgun.org ~all" {
		t.Errorf("content = %q", got.Content)
	}
}

func TestSPFMechanismsSkipsBareAll(t *testing.T) {
	got, err := SPFMechanisms("v=spf1 include:x.com all")
	if err != nil {
		t.Fatalf("SPFMechanisms: %v", err)
	}

	want := []string{"include:x.com"}
	if len(got) != len(want) {
		t.Fatalf("mechanisms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanism %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMergeSPFDetectsBareAllAsQualifier(t *testing.T) {
	records := []dns.Record{
		spf("v=spf1 include:x.com all"),
	}

	got, ok, err := MergeSPF("a.com", records, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false with SPF records present")
	}
	if !hasSuffix(got.Content, " all") {
		t.Errorf("content = %q, want it to end with ' all', not default to ~all", got.Content)
	}
}

func TestSPFMechanismsKeepsTokensEndingInAll(t *testing.T) {
	got, err := SPFMechanisms("v=spf1 include:mail-all exists:small.example ip4:1.2.3.4 ~all")
	if err != nil {
		t.Fatalf("SPFMechanisms: %v", err)
	}

	want := []string{"include:mail-all", "exists:small.example", "ip4:1.2.3.4"}
	if len(got) != len(want) {
		t.Fatalf("mechanisms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanism %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSPFMechanismsCaseHandling(t *testing.T) {
	got, err := SPFMechanisms("V=SPF1 include:x.com ~ALL")
	if err != nil {
		t.Fatalf("SPFMechanisms: %v", err)
	}

	want := []string{"include:x.com"}
	if len(got) != len(want) {
		t.Fatalf("mechanisms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mechanism %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestMergeSPFRecognizesCaseInsensitiveQualifier(t *testing.T) {
	records := []dns.Record{
		spf("V=SPF1 include:x.com ~ALL"),
	}

	got, ok, err := MergeSPF("a.com", records, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false with SPF records present")
	}
	if !hasSuffix(got.Content, " ~all") {
		t.Errorf("content = %q, want it to end with ' ~all', with lowercase normalization", got.Content)
	}
}

func TestMergeSPFEmitsQualifierOnlyRecordWhenNoMechanismsSurvive(t *testing.T) {
	// An input record that is just "v=spf1 all" leaves no mechanism after
	// filtering, but the qualifier it carried must still be published rather
	// than the record being dropped entirely (F9).
	records := []dns.Record{spf("v=spf1 -all")}

	got, ok, err := MergeSPF("a.com", records, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false; a bare qualifier should still produce a record")
	}
	if got.Content != "v=spf1 -all" {
		t.Errorf("content = %q, want v=spf1 -all", got.Content)
	}
}

func TestMergeSPFSkipsRecordsNotOnTheApex(t *testing.T) {
	// A provider SPF record for a subdomain must not be relocated onto the
	// apex (F9).
	sub := dns.Record{Type: "TXT", Name: "sub.a.com", Content: "v=spf1 include:sub-provider.com ~all", Kind: dns.KindSPF}

	_, ok, err := MergeSPF("a.com", []dns.Record{sub}, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if ok {
		t.Error("MergeSPF should ignore an SPF record whose name is not the domain apex")
	}

	apex := spf("v=spf1 include:apex-provider.com ~all")
	got, ok, err := MergeSPF("a.com", []dns.Record{apex, sub}, nil)
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false with an apex SPF record present")
	}
	if strings.Contains(got.Content, "sub-provider.com") {
		t.Errorf("content = %q, must not carry the subdomain record's mechanism", got.Content)
	}
	if !strings.Contains(got.Content, "apex-provider.com") {
		t.Errorf("content = %q, must carry the apex record's mechanism", got.Content)
	}
}

func TestMergeSPFRoutesConfigIncludesThroughTheMechanismFilter(t *testing.T) {
	// add(extra) used to bypass SPFMechanisms; routing it through the same
	// filter means a bare "all" mechanism in config cannot slip into the
	// mechanism list unfiltered, the way a provider record's never could
	// (F4). Config validation rejects an "all" entry outright, so this only
	// exercises the filtering itself.
	got, ok, err := MergeSPF("a.com", nil, []string{"include:servers.mailgun.org", "all"})
	if err != nil {
		t.Fatalf("MergeSPF: %v", err)
	}
	if !ok {
		t.Fatal("MergeSPF returned ok=false with a config include present")
	}
	want := "v=spf1 include:servers.mailgun.org ~all"
	if got.Content != want {
		t.Errorf("content = %q, want %q; the bare all must be filtered out of the mechanism list", got.Content, want)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func TestSPFMechanismsRejectsAValuelessMechanism(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"bare include", "v=spf1 include: spf.protection.outlook.com ~all", "include:"},
		{"bare redirect", "v=spf1 redirect= example.com", "redirect="},
		{"bare exists", "v=spf1 exists: example.com ~all", "exists:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SPFMechanisms(tc.content)
			if err == nil {
				t.Fatal("want an error for a mechanism with no value")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

func TestSPFMechanismsStillParsesTheExistingProviders(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"purelymail", "v=spf1 include:_spf.purelymail.com ~all", []string{"include:_spf.purelymail.com"}},
		{"microsoft", "v=spf1 include:spf.protection.outlook.com -all", []string{"include:spf.protection.outlook.com"}},
		{"multiple", "v=spf1 include:a.example ip4:198.51.100.0/24 -all",
			[]string{"include:a.example", "ip4:198.51.100.0/24"}},
		{"qualifier only", "v=spf1 ~all", nil},
		{"bare all is dropped", "v=spf1 all", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SPFMechanisms(tc.content)
			if err != nil {
				t.Fatalf("SPFMechanisms: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestMergeSPFFailsOnAMalformedProviderRecord(t *testing.T) {
	records := []dns.Record{{
		Type:    "TXT",
		Name:    "example.com",
		Content: "v=spf1 include: spf.protection.outlook.com ~all",
		Kind:    dns.KindSPF,
	}}
	if _, _, err := MergeSPF("example.com", records, nil); err == nil {
		t.Fatal("want MergeSPF to refuse a malformed provider record rather than republish it")
	}
}

func TestSPFMechanismsRejectsABareMechanismName(t *testing.T) {
	cases := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"bare include", "include", true},
		{"bare exists", "exists", true},
		{"bare ip4", "ip4", true},
		{"bare ip6", "ip6", true},
		{"bare redirect", "redirect", true},
		{"bare exp", "exp", true},
		{"bare a is legal", "a", false},
		{"bare mx is legal", "mx", false},
		{"bare ptr is legal", "ptr", false},
		{"qualified bare a is legal", "-a", false},
		{"qualified bare mx is legal", "?mx", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := "v=spf1 " + tc.token + " ~all"
			got, err := SPFMechanisms(content)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error for bare %q, got mechanisms %v", tc.token, got)
				}
				if !strings.Contains(err.Error(), tc.token) {
					t.Errorf("error = %q, want it to name %q", err, tc.token)
				}
				return
			}
			if err != nil {
				t.Fatalf("SPFMechanisms(%q): %v, want %q accepted as legal", content, err, tc.token)
			}
			want := []string{tc.token}
			if len(got) != len(want) || got[0] != want[0] {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestSPFMechanismsRejectsBareIncludeWithNoColon(t *testing.T) {
	// The realistic vector: an operator's config entry with a typo, not a
	// provider record. "include" with no colon at all is not legal SPF
	// grammar and must not be silently republished.
	_, err := SPFMechanisms("v=spf1 include x.com ~all")
	if err == nil {
		t.Fatal("want an error for a bare mechanism name with no value")
	}
	if !strings.Contains(err.Error(), "include") {
		t.Errorf("error = %q, want it to name %q", err, "include")
	}
}

func TestMergeSPFFailsOnAMalformedConfigIncludeAndNamesConfig(t *testing.T) {
	_, _, err := MergeSPF("example.com", nil, []string{"include", "x.com"})
	if err == nil {
		t.Fatal("want MergeSPF to refuse a malformed config include rather than republish it")
	}
	if !strings.Contains(err.Error(), "config") {
		t.Errorf("error = %q, want it to say this came from config includes, not a provider record", err)
	}
	if !strings.Contains(err.Error(), "include") {
		t.Errorf("error = %q, want it to name the offending token %q", err, "include")
	}
}
