package audit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type fakeResolver struct {
	mx    map[string][]string
	txt   map[string][]string
	cname map[string]string
}

func (f fakeResolver) LookupMX(_ context.Context, name string) ([]string, error) {
	hosts, ok := f.mx[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return hosts, nil
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	values, ok := f.txt[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	return values, nil
}

func (f fakeResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	target, ok := f.cname[name]
	if !ok {
		return "", errors.New("no such host")
	}
	return target, nil
}

type fakeFetcher struct {
	bodies map[string]string
}

func (f fakeFetcher) Get(_ context.Context, url string) (string, error) {
	body, ok := f.bodies[url]
	if !ok {
		return "", errors.New("404")
	}
	return body, nil
}

func desiredRecords() []dns.Record {
	return []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject; pct=100", Kind: dns.KindDMARC},
		{Type: "CNAME", Name: "purelymail1._domainkey.a.com", Content: "key1.dkimroot.purelymail.com", Kind: dns.KindDKIM},
		{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=abc123", Kind: dns.KindMTASts},
	}
}

func healthyResolver() fakeResolver {
	return fakeResolver{
		mx: map[string][]string{"a.com": {"mailserver.purelymail.com"}},
		txt: map[string][]string{
			"a.com":          {"v=spf1 include:_spf.purelymail.com ~all"},
			"_dmarc.a.com":   {"v=DMARC1; p=reject; pct=100"},
			"_mta-sts.a.com": {"v=STSv1; id=abc123"},
		},
		cname: map[string]string{"purelymail1._domainkey.a.com": "key1.dkimroot.purelymail.com."},
	}
}

func TestRunPassesWhenEverythingResolves(t *testing.T) {
	fetcher := fakeFetcher{bodies: map[string]string{
		"https://mta-sts.a.com/.well-known/mta-sts.txt": "version: STSv1\nmode: enforce\nmx: mailserver.purelymail.com\nmax_age: 604800\n",
	}}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), healthyResolver(), fetcher)

	if !report.OK() {
		var failures []string
		for _, check := range report.Checks {
			if !check.OK {
				failures = append(failures, check.Name+": got "+check.Got)
			}
		}
		t.Fatalf("report should pass; failures: %s", strings.Join(failures, "; "))
	}
	if len(report.Checks) != 6 {
		t.Errorf("got %d checks, want 5 records plus the policy fetch", len(report.Checks))
	}
}

func TestRunFlagsAMissingRecord(t *testing.T) {
	resolver := healthyResolver()
	delete(resolver.txt, "_dmarc.a.com")

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	if report.OK() {
		t.Fatal("a missing DMARC record must fail the audit")
	}
	found := false
	for _, check := range report.Checks {
		if strings.Contains(check.Name, "_dmarc") && !check.OK {
			found = true
		}
	}
	if !found {
		t.Errorf("no failing check names _dmarc:\n%+v", report.Checks)
	}
}

func TestRunFlagsDriftedContent(t *testing.T) {
	resolver := healthyResolver()
	resolver.txt["a.com"] = []string{"v=spf1 include:_spf.someone-else.com ~all"}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	for _, check := range report.Checks {
		if check.Name == "TXT a.com" {
			if check.OK {
				t.Error("a different SPF value published must fail")
			}
			if !strings.Contains(check.Got, "someone-else") {
				t.Errorf("the check must show what is actually published; got %q", check.Got)
			}
			return
		}
	}
	t.Fatal("no SPF check present")
}

func TestRunFlagsMultipleSPFRecords(t *testing.T) {
	resolver := healthyResolver()
	resolver.txt["a.com"] = []string{
		"v=spf1 include:_spf.purelymail.com ~all",
		"v=spf1 include:other.com ~all",
	}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	if report.OK() {
		t.Fatal("two SPF records on one name is a hard failure and the audit must say so")
	}
	joined := strings.Join(report.Notes, " ")
	if !strings.Contains(joined, "SPF") {
		t.Errorf("notes should explain the duplicate SPF problem; got %v", report.Notes)
	}
}

// purelymail's DesiredDNS emits two TXT records at the apex: SPF and an
// ownership-proof record, both named "TXT a.com". Duplicate SPF must fail
// only the SPF check, not the unrelated ownership check that happens to
// share its name.
func TestRunFlagsDuplicateSPFWithoutFailingTheOwnershipRecord(t *testing.T) {
	desired := []dns.Record{
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: "a.com", Content: "purelymail-verification=abc123", Kind: dns.KindOwnership},
	}
	resolver := fakeResolver{txt: map[string][]string{
		"a.com": {
			"v=spf1 include:_spf.purelymail.com ~all",
			"v=spf1 include:other.com ~all",
			"purelymail-verification=abc123",
		},
	}}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desired, resolver, fakeFetcher{})

	if report.OK() {
		t.Fatal("two SPF records on one name is a hard failure and the audit must say so")
	}

	var txtChecks []Check
	for _, check := range report.Checks {
		if check.Name == "TXT a.com" {
			txtChecks = append(txtChecks, check)
		}
	}
	if len(txtChecks) != 2 {
		t.Fatalf("expected two TXT a.com checks (SPF and ownership), got %d", len(txtChecks))
	}
	if txtChecks[0].OK {
		t.Error("the SPF check must fail when duplicated")
	}
	if !txtChecks[1].OK {
		t.Error("the ownership check must still pass; duplicate SPF must not flip an unrelated record with the same name")
	}
}

func TestRunMXToleratesTrailingDotFromResolver(t *testing.T) {
	resolver := fakeResolver{mx: map[string][]string{"a.com": {"mailserver.purelymail.com."}}}
	desired := []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
	}

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desired, resolver, fakeFetcher{})

	for _, check := range report.Checks {
		if check.Name == "MX a.com" {
			if !check.OK {
				t.Errorf("a trailing dot on the resolved MX host must not fail the check; got %q", check.Got)
			}
			return
		}
	}
	t.Fatal("no MX check present")
}

func TestRunChecksTheMTAStsPolicyIsServed(t *testing.T) {
	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(),
		healthyResolver(), fakeFetcher{})

	for _, check := range report.Checks {
		if strings.Contains(check.Name, "mta-sts policy") {
			if check.OK {
				t.Error("an unreachable policy endpoint must fail")
			}
			return
		}
	}
	t.Fatal("no policy-fetch check present")
}

// mode: none is a published withdrawal policy, not an absence of one: it
// rotates the _mta-sts TXT id and deploys a Worker that must serve
// "mode: none". If the Worker instead keeps serving "mode: enforce",
// receivers stay pinned to their cached enforce policy while the operator
// believes it was revoked, so this must fail the audit.
func TestRunFlagsMTASTSNoneServedAsEnforce(t *testing.T) {
	resolver := fakeResolver{txt: map[string][]string{
		"_mta-sts.a.com": {"v=STSv1; id=abc123"},
	}}
	fetcher := fakeFetcher{bodies: map[string]string{
		"https://mta-sts.a.com/.well-known/mta-sts.txt": "version: STSv1\nmode: enforce\nmx: mailserver.purelymail.com\nmax_age: 604800\n",
	}}
	desired := []dns.Record{
		{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=abc123", Kind: dns.KindMTASts},
	}
	domain := config.Domain{Name: "a.com", Deliverability: config.Deliverability{MTASts: &config.MTASts{Mode: "none"}}}

	report := Run(context.Background(), domain, desired, resolver, fetcher)

	if report.OK() {
		t.Fatal("a withdrawal policy still served as mode: enforce is a failed revocation and must fail")
	}
	found := false
	for _, check := range report.Checks {
		if strings.Contains(check.Name, "mta-sts policy") && !check.OK {
			found = true
		}
	}
	if !found {
		t.Errorf("no failing mta-sts policy check present:\n%+v", report.Checks)
	}
}

func TestRunPassesWhenMTASTSNoneIsServedCorrectly(t *testing.T) {
	resolver := fakeResolver{txt: map[string][]string{
		"_mta-sts.a.com": {"v=STSv1; id=abc123"},
	}}
	fetcher := fakeFetcher{bodies: map[string]string{
		"https://mta-sts.a.com/.well-known/mta-sts.txt": "version: STSv1\nmode: none\n",
	}}
	desired := []dns.Record{
		{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=abc123", Kind: dns.KindMTASts},
	}
	domain := config.Domain{Name: "a.com", Deliverability: config.Deliverability{MTASts: &config.MTASts{Mode: "none"}}}

	report := Run(context.Background(), domain, desired, resolver, fetcher)

	if !report.OK() {
		var failures []string
		for _, check := range report.Checks {
			if !check.OK {
				failures = append(failures, check.Name+": got "+check.Got)
			}
		}
		t.Fatalf("a correctly served withdrawal policy must pass; failures: %s", strings.Join(failures, "; "))
	}
}

func TestRenderShowsFailuresFirst(t *testing.T) {
	resolver := healthyResolver()
	delete(resolver.txt, "_dmarc.a.com")

	report := Run(context.Background(), config.Domain{Name: "a.com"}, desiredRecords(), resolver, fakeFetcher{})

	var out strings.Builder
	report.Render(&out)
	rendered := out.String()

	if !strings.Contains(rendered, "FAIL") || !strings.Contains(rendered, "_dmarc") {
		t.Errorf("render should mark the failure:\n%s", rendered)
	}
	if strings.Index(rendered, "FAIL") > strings.Index(rendered, "ok  ") {
		t.Error("failures should be listed before passes so they are not scrolled past")
	}
}
