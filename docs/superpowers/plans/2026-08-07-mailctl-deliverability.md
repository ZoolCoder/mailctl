# mailctl Deliverability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish and reconcile the deliverability layer — a single merged SPF record, DMARC, TLS-RPT, BIMI, and MTA-STS including the Worker that serves the policy file.

**Architecture:** A pure-function package `internal/deliver` turns provider DNS records plus config into the final desired record set: it merges every provider's SPF include into one record, drops a provider's DMARC record when the config declares its own policy, and appends the remaining policy records. MTA-STS additionally needs a hosted policy file, so `internal/worker` uploads a generated Worker and binds `mta-sts.<domain>` to it; the TXT record's `id` is a hash of the policy text, so an edit to the policy invalidates receivers' caches.

**Tech Stack:** Go 1.26, stdlib only (`crypto/sha256`, `mime/multipart` via `cfapi`).

**Prerequisite:** the core plan (`2026-08-07-mailctl-core.md`) is complete and its tests pass.

**Spec:** `docs/superpowers/specs/2026-08-07-mailctl-design.md`, sections "Deliverability" and "MTA-STS".

## Global Constraints

- Everything in `internal/deliver` is a pure function of its inputs. No I/O, no clock, no randomness. That is what makes it cheap to table-test.
- Exactly one SPF TXT record per name. Two is a hard failure in RFC 7208, so records are merged, never appended.
- The MTA-STS policy `id` must change when and only when the policy text changes.
- The Worker is uploaded through the Cloudflare REST API, not `npx wrangler`. This is a deliberate exception to the standing "drive Workers through wrangler" preference: the script is generated, `mailctl` owns it end to end, and it has no `wrangler.jsonc` of its own. Keeping the binary Node-free is the point.
- Before every commit: `gofmt -l .` prints nothing, `go vet ./...` passes, `go test ./...` passes.
- No live API calls in the test suite.

## File structure

```
internal/deliver/spf.go        SPF parsing and merging
internal/deliver/policy.go     DMARC, TLS-RPT, BIMI record builders
internal/deliver/mtasts.go     policy text, policy id, MTA-STS TXT records
internal/deliver/merge.go      Merge: provider records + config -> final desired set
internal/worker/script.go      the generated MTA-STS Worker source
internal/worker/deploy.go      script upload and custom-domain binding
internal/engine/engine.go      (modified) call deliver.Merge, add worker actions
```

---

### Task 1: SPF merging

**Files:**
- Create: `internal/deliver/spf.go`
- Test: `internal/deliver/spf_test.go`

**Interfaces:**
- Consumes: `dns.Record`.
- Produces: `deliver.SPFMechanisms(content string) []string`, `deliver.MergeSPF(domain string, records []dns.Record, extra []string) (dns.Record, bool)`. Task 4 calls `MergeSPF`.

- [ ] **Step 1: Write the failing test**

Create `internal/deliver/spf_test.go`:

```go
package deliver

import (
	"testing"

	"github.com/zoolcoder/mailctl/internal/dns"
)

func spf(content string) dns.Record {
	return dns.Record{Type: "TXT", Name: "a.com", Content: content, Kind: dns.KindSPF}
}

func TestSPFMechanismsSplitsOnWhitespace(t *testing.T) {
	got := SPFMechanisms("v=spf1  include:_spf.one.com   include:two.com  ~all")

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

	got, ok := MergeSPF("a.com", records, []string{"include:servers.mailgun.org"})
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
		spf("v=spf1 include:_spf.purelymail.com ~all"),
	}

	got, _ := MergeSPF("a.com", records, []string{"include:_spf.purelymail.com"})
	if got.Content != "v=spf1 include:_spf.purelymail.com ~all" {
		t.Errorf("content = %q, want the mechanism exactly once", got.Content)
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
			got, _ := MergeSPF("a.com", records, nil)
			if !hasSuffix(got.Content, " "+tt.want) {
				t.Errorf("content = %q, want it to end with %q", got.Content, tt.want)
			}
		})
	}
}

func TestMergeSPFReportsNothingWhenNoSPFRecordsExist(t *testing.T) {
	if _, ok := MergeSPF("a.com", nil, nil); ok {
		t.Error("ok = true with no SPF inputs; a domain with no sending provider needs no SPF record")
	}
}

func TestMergeSPFBuildsFromConfigAloneWhenAsked(t *testing.T) {
	got, ok := MergeSPF("a.com", nil, []string{"include:servers.mailgun.org"})
	if !ok {
		t.Fatal("config includes alone should still produce a record")
	}
	if got.Content != "v=spf1 include:servers.mailgun.org ~all" {
		t.Errorf("content = %q", got.Content)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/deliver/ -v`
Expected: FAIL — `undefined: SPFMechanisms`.

- [ ] **Step 3: Implement SPF merging**

Create `internal/deliver/spf.go`:

```go
// Package deliver builds the deliverability DNS records for a domain. Every
// function here is pure: same inputs, same records, no I/O.
package deliver

import (
	"strings"

	"github.com/zoolcoder/mailctl/internal/dns"
)

// allQualifiers are ordered from most permissive to strictest. Merging keeps
// the strictest one any input asked for, because loosening a policy silently
// is the worse mistake.
var allQualifiers = []string{"+all", "?all", "~all", "-all"}

// SPFMechanisms returns the mechanisms of an SPF record, excluding the v=spf1
// prefix and any trailing all qualifier.
func SPFMechanisms(content string) []string {
	var out []string
	for _, token := range strings.Fields(content) {
		lower := strings.ToLower(token)
		if lower == "v=spf1" || strings.HasSuffix(lower, "all") && qualifierRank(lower) >= 0 {
			continue
		}
		out = append(out, token)
	}
	return out
}

// MergeSPF folds every SPF record the providers asked for, plus any extra
// mechanisms from config, into one record. It reports false when there is
// nothing to publish.
func MergeSPF(domain string, records []dns.Record, extra []string) (dns.Record, bool) {
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
		add(SPFMechanisms(record.Content))
		qualifier = strictest(qualifier, findQualifier(record.Content))
	}
	add(extra)

	if len(mechanisms) == 0 {
		return dns.Record{}, false
	}
	if qualifier == "" {
		qualifier = "~all"
	}

	content := "v=spf1 " + strings.Join(mechanisms, " ") + " " + qualifier
	return dns.Record{Type: "TXT", Name: domain, Content: content, Kind: dns.KindSPF}, true
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
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/deliver/ -v`
Expected: PASS (6 tests, including all four `TestMergeSPFKeepsTheStrictestAllQualifier` subtests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/deliver/spf.go internal/deliver/spf_test.go
git commit -m "feat(deliver): merge provider spf records into one"
```

---

### Task 2: DMARC, TLS-RPT, and BIMI records

**Files:**
- Create: `internal/deliver/policy.go`
- Test: `internal/deliver/policy_test.go`

**Interfaces:**
- Consumes: `config.DMARC`, `config.BIMI`, `dns.Record`.
- Produces: `deliver.DMARC(domain string, d config.DMARC) dns.Record`, `deliver.TLSRpt(domain, rua string) dns.Record`, `deliver.BIMI(domain string, b config.BIMI) dns.Record`. Task 4 calls all three.

- [ ] **Step 1: Write the failing test**

Create `internal/deliver/policy_test.go`:

```go
package deliver

import (
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestDMARCBuildsTheFullPolicy(t *testing.T) {
	got := DMARC("a.com", config.DMARC{
		Policy:          "quarantine",
		SubdomainPolicy: "reject",
		Pct:             50,
		RUA:             "mailto:dmarc@a.com",
		RUF:             "mailto:forensics@a.com",
	})

	if got.Name != "_dmarc.a.com" || got.Type != "TXT" || got.Kind != dns.KindDMARC {
		t.Errorf("record = %+v, want a TXT on _dmarc.a.com", got)
	}
	want := "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:dmarc@a.com; ruf=mailto:forensics@a.com"
	if got.Content != want {
		t.Errorf("content = %q,\nwant                %q", got.Content, want)
	}
}

func TestDMARCOmitsEmptyTags(t *testing.T) {
	got := DMARC("a.com", config.DMARC{Policy: "none", Pct: 100})

	if got.Content != "v=DMARC1; p=none; pct=100" {
		t.Errorf("content = %q, want no sp, rua, or ruf tags", got.Content)
	}
}

func TestTLSRptRecord(t *testing.T) {
	got := TLSRpt("a.com", "mailto:tls@a.com")

	if got.Name != "_smtp._tls.a.com" || got.Kind != dns.KindTLSRpt {
		t.Errorf("record = %+v, want a TXT on _smtp._tls.a.com", got)
	}
	if got.Content != "v=TLSRPTv1; rua=mailto:tls@a.com" {
		t.Errorf("content = %q", got.Content)
	}
}

func TestBIMIWithAndWithoutVMC(t *testing.T) {
	withVMC := BIMI("a.com", config.BIMI{Logo: "https://a.com/logo.svg", VMC: "https://a.com/vmc.pem"})
	if withVMC.Name != "default._bimi.a.com" || withVMC.Kind != dns.KindBIMI {
		t.Errorf("record = %+v, want a TXT on default._bimi.a.com", withVMC)
	}
	if withVMC.Content != "v=BIMI1; l=https://a.com/logo.svg; a=https://a.com/vmc.pem" {
		t.Errorf("content = %q", withVMC.Content)
	}

	withoutVMC := BIMI("a.com", config.BIMI{Logo: "https://a.com/logo.svg"})
	if withoutVMC.Content != "v=BIMI1; l=https://a.com/logo.svg" {
		t.Errorf("content = %q, want no a= tag", withoutVMC.Content)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/deliver/ -run 'TestDMARC|TestTLSRpt|TestBIMI' -v`
Expected: FAIL — `undefined: DMARC`.

- [ ] **Step 3: Implement the builders**

Create `internal/deliver/policy.go`:

```go
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
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/deliver/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/deliver/policy.go internal/deliver/policy_test.go
git commit -m "feat(deliver): build dmarc, tls-rpt, bimi records"
```

---

### Task 3: MTA-STS policy, id, and records

**Files:**
- Create: `internal/deliver/mtasts.go`
- Test: `internal/deliver/mtasts_test.go`

**Interfaces:**
- Consumes: `config.MTASts`, `dns.Record`.
- Produces: `deliver.MTAStsPolicy(mode string, maxAge int, mx []string) string`, `deliver.MTAStsID(policy string) string`, `deliver.MTASts(domain string, m config.MTASts, mx []string) (records []dns.Record, policy string, err error)`, `deliver.MXHosts(records []dns.Record) []string`. Tasks 4 and 5 use all of them.

**Why the id is derived from the policy:** receiving servers cache an MTA-STS policy and only refetch it when the `id` in DNS changes. A static id means a changed MX list or mode is never picked up — the domain looks configured and is not.

- [ ] **Step 1: Write the failing test**

Create `internal/deliver/mtasts_test.go`:

```go
package deliver

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestPolicyTextShape(t *testing.T) {
	got := MTAStsPolicy("enforce", 604800, []string{"mailserver.purelymail.com"})

	want := "version: STSv1\nmode: enforce\nmx: mailserver.purelymail.com\nmax_age: 604800\n"
	if got != want {
		t.Errorf("policy =\n%q\nwant\n%q", got, want)
	}
}

func TestPolicyTextListsEveryMXOnItsOwnLine(t *testing.T) {
	got := MTAStsPolicy("testing", 86400, []string{"mx1.a.com", "mx2.a.com"})

	if strings.Count(got, "mx: ") != 2 {
		t.Errorf("policy should carry one mx line per host:\n%s", got)
	}
}

func TestPolicyIDChangesWithThePolicy(t *testing.T) {
	first := MTAStsPolicy("enforce", 604800, []string{"mx1.a.com"})
	second := MTAStsPolicy("enforce", 604800, []string{"mx1.a.com", "mx2.a.com"})
	third := MTAStsPolicy("testing", 604800, []string{"mx1.a.com"})

	if MTAStsID(first) == MTAStsID(second) {
		t.Error("adding an MX must change the id, or receivers never refetch")
	}
	if MTAStsID(first) == MTAStsID(third) {
		t.Error("changing the mode must change the id")
	}
	if MTAStsID(first) != MTAStsID(MTAStsPolicy("enforce", 604800, []string{"mx1.a.com"})) {
		t.Error("the same policy must produce the same id, or every run republishes")
	}
	if len(MTAStsID(first)) != 16 {
		t.Errorf("id length = %d, want 16", len(MTAStsID(first)))
	}
}

func TestMTAStsBuildsTXTAndPolicy(t *testing.T) {
	records, policy, err := MTASts("a.com",
		config.MTASts{Mode: "enforce", MaxAge: 604800, Deploy: true},
		[]string{"mailserver.purelymail.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("records = %+v, want just the _mta-sts TXT; the policy host record is created by the Worker binding", records)
	}
	got := records[0]
	if got.Name != "_mta-sts.a.com" || got.Kind != dns.KindMTASts {
		t.Errorf("record = %+v, want a TXT on _mta-sts.a.com", got)
	}
	if !strings.HasPrefix(got.Content, "v=STSv1; id=") {
		t.Errorf("content = %q, want the STSv1 prefix", got.Content)
	}
	if !strings.Contains(got.Content, MTAStsID(policy)) {
		t.Errorf("content = %q must carry the id of the returned policy", got.Content)
	}
}

func TestMTAStsRefusesEnforceWithNoMX(t *testing.T) {
	_, _, err := MTASts("a.com", config.MTASts{Mode: "enforce", MaxAge: 604800}, nil)
	if err == nil || !strings.Contains(err.Error(), "MX") {
		t.Fatalf("err = %v, want a refusal naming MX; an enforce policy with no mx line rejects all mail", err)
	}
}

func TestMTAStsModeNoneProducesNothing(t *testing.T) {
	records, _, err := MTASts("a.com", config.MTASts{Mode: "none"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("records = %+v, want none for mode none", records)
	}
}

func TestMTAStsDefaultsMaxAge(t *testing.T) {
	_, policy, err := MTASts("a.com", config.MTASts{Mode: "testing"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if !strings.Contains(policy, "max_age: 604800") {
		t.Errorf("policy = %q, want the one-week default", policy)
	}
}

func TestMXHostsSortsAndStripsTrailingDots(t *testing.T) {
	got := MXHosts([]dns.Record{
		{Type: "MX", Name: "a.com", Content: "mx2.a.com.", Kind: dns.KindMX},
		{Type: "MX", Name: "a.com", Content: "mx1.a.com", Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "ignored", Kind: dns.KindSPF},
	})

	if len(got) != 2 || got[0] != "mx1.a.com" || got[1] != "mx2.a.com" {
		t.Errorf("hosts = %v, want [mx1.a.com mx2.a.com]; sorting keeps the policy id stable", got)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/deliver/ -run MTA -v`
Expected: FAIL — `undefined: MTAStsPolicy`.

- [ ] **Step 3: Implement MTA-STS**

Create `internal/deliver/mtasts.go`:

```go
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
	if m.Mode == "" || m.Mode == "none" {
		return nil, "", nil
	}
	if len(mx) == 0 {
		return nil, "", fmt.Errorf(
			"domain %s: MTA-STS mode %s needs at least one MX host; a policy with no mx line rejects all mail",
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
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/deliver/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/deliver/mtasts.go internal/deliver/mtasts_test.go
git commit -m "feat(deliver): build mta-sts policy and content-derived id"
```

---

### Task 4: Merge everything into the desired record set

**Files:**
- Create: `internal/deliver/merge.go`
- Test: `internal/deliver/merge_test.go`

**Interfaces:**
- Consumes: everything from Tasks 1–3, plus `config.Domain`, `dns.Record`.
- Produces: `deliver.Merge(d config.Domain, providerRecords []dns.Record) (Result, error)` and `deliver.Result{Records []dns.Record, MTAStsPolicy string, MTAStsHost string}`. Task 6 wires this into the engine; Task 5 uses `Result.MTAStsPolicy`.

- [ ] **Step 1: Write the failing test**

Create `internal/deliver/merge_test.go`:

```go
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

	first, err := Merge(d, providerRecords())
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	second, err := Merge(d, providerRecords())
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
```

Note: `dns.Record` contains a `*bool`, so the struct comparison in the last test compares
pointer identity for `Proxied`. That is intentional — the provider records are the same
slice in both calls, so the pointers match, and a `Merge` that rebuilt them would fail
the test, which is the behaviour being pinned.

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/deliver/ -run TestMerge -v`
Expected: FAIL — `undefined: Merge`.

- [ ] **Step 3: Implement Merge**

Create `internal/deliver/merge.go`:

```go
package deliver

import (
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
			// Collected and re-emitted once, below.
			continue
		case dns.KindDMARC:
			if configOwnsDMARC {
				continue
			}
		}
		out.Records = append(out.Records, record)
	}

	if spf, ok := MergeSPF(d.Name, providerRecords, v.SPFIncludes); ok {
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
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/deliver/ -v`
Expected: PASS across all four files.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/deliver/merge.go internal/deliver/merge_test.go
git commit -m "feat(deliver): merge provider and policy records"
```

---

### Task 5: The MTA-STS Worker

**Files:**
- Create: `internal/worker/script.go`
- Create: `internal/worker/deploy.go`
- Test: `internal/worker/script_test.go`
- Test: `internal/worker/deploy_test.go`

**Interfaces:**
- Consumes: `cfapi.Client`, `cfapi.Part`.
- Produces: `worker.ScriptName(domain string) string`, `worker.PolicyScript(policy string) string`, `worker.New(api *cfapi.Client, accountID string) *Deployer`, `(*Deployer).ScriptMatches(ctx, name, source string) (bool, error)`, `(*Deployer).Upload(ctx, name, source string) error`, `(*Deployer).DomainAttached(ctx, hostname, zoneID string) (bool, error)`, `(*Deployer).AttachDomain(ctx, hostname, zoneID, scriptName string) error`. Task 6 calls all of them.

- [ ] **Step 1: Write the failing script test**

Create `internal/worker/script_test.go`:

```go
package worker

import (
	"strings"
	"testing"
)

func TestScriptNameIsStablePerDomain(t *testing.T) {
	if got := ScriptName("example.com"); got != "mailctl-mta-sts-example-com" {
		t.Errorf("name = %q, want dots replaced so the name is a legal script name", got)
	}
}

func TestPolicyScriptEmbedsThePolicyAndServesTheWellKnownPath(t *testing.T) {
	policy := "version: STSv1\nmode: enforce\nmx: mx.a.com\nmax_age: 604800\n"

	got := PolicyScript(policy)

	if !strings.Contains(got, "/.well-known/mta-sts.txt") {
		t.Error("script must route the well-known path")
	}
	if !strings.Contains(got, "text/plain") {
		t.Error("the policy must be served as text/plain or receivers reject it")
	}
	if !strings.Contains(got, "mode: enforce") {
		t.Error("script must embed the policy body")
	}
	if !strings.Contains(got, "export default") {
		t.Error("script must be an ES module, matching the main_module upload metadata")
	}
}

func TestPolicyScriptEscapesBackticksAndInterpolation(t *testing.T) {
	got := PolicyScript("weird `backtick` and ${injection}\n")

	if strings.Contains(got, "${injection}") {
		t.Error("a ${...} sequence in the policy must not survive as live template interpolation")
	}
	if !strings.Contains(got, "\\`backtick\\`") {
		t.Errorf("backticks must be escaped; got:\n%s", got)
	}
}

func TestPolicyScriptIsDeterministic(t *testing.T) {
	policy := "version: STSv1\nmode: testing\nmx: mx.a.com\nmax_age: 86400\n"

	if PolicyScript(policy) != PolicyScript(policy) {
		t.Error("the same policy must produce byte-identical source, or every run redeploys")
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/worker/ -v`
Expected: FAIL — `undefined: ScriptName`.

- [ ] **Step 3: Implement the script generator**

Create `internal/worker/script.go`:

```go
// Package worker uploads the generated Worker that serves a domain's MTA-STS
// policy, and binds it to mta-sts.<domain>.
package worker

import (
	"strings"
)

// CompatibilityDate pins the Workers runtime behaviour for the generated
// script. It is a constant so that redeploying an unchanged policy produces
// byte-identical source and therefore no diff.
const CompatibilityDate = "2025-01-01"

// ScriptName is the Worker script name for a domain. Dots are not allowed in a
// script name, so they become hyphens.
func ScriptName(domain string) string {
	return "mailctl-mta-sts-" + strings.ReplaceAll(domain, ".", "-")
}

// PolicyScript renders an ES module Worker serving the policy at the
// well-known path and 404ing everything else.
func PolicyScript(policy string) string {
	return `// Generated by mailctl. Do not edit; edit the mailctl config instead.
const POLICY = ` + "`" + escapeTemplate(policy) + "`" + `;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/.well-known/mta-sts.txt") {
      return new Response("Not Found", { status: 404 });
    }
    return new Response(POLICY, {
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "public, max-age=3600",
      },
    });
  },
};
`
}

// escapeTemplate makes a string safe inside a JavaScript template literal.
// A policy is generated from config, but config is user input, and a stray
// backtick or ${ would otherwise produce a Worker that fails to compile.
func escapeTemplate(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "${", "\\${")
	return s
}
```

- [ ] **Step 4: Run the script tests and verify they pass**

Run: `go test ./internal/worker/ -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Write the failing deploy test**

Create `internal/worker/deploy_test.go`:

```go
package worker

import (
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

func TestUploadSendsMultipartModule(t *testing.T) {
	var gotMetadata, gotModule, gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path

		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse content type: %v", err)
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			body, _ := io.ReadAll(part)
			switch part.FormName() {
			case "metadata":
				gotMetadata = string(body)
			case "worker.mjs":
				gotModule = string(body)
			}
		}
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"s1"}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")
	if err := deployer.Upload(context.Background(), "mailctl-mta-sts-a-com", "export default {};"); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotPath != "/accounts/acc-1/workers/scripts/mailctl-mta-sts-a-com" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotMetadata, `"main_module":"worker.mjs"`) {
		t.Errorf("metadata = %q, want main_module worker.mjs", gotMetadata)
	}
	if !strings.Contains(gotMetadata, CompatibilityDate) {
		t.Errorf("metadata = %q, want the pinned compatibility date", gotMetadata)
	}
	if gotModule != "export default {};" {
		t.Errorf("module = %q", gotModule)
	}
}

func TestScriptMatchesComparesLiveSource(t *testing.T) {
	const source = "export default { fetch() {} };"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript+module")
		fmt.Fprint(w, source)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	same, err := deployer.ScriptMatches(context.Background(), "s", source)
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if !same {
		t.Error("identical source should report a match, so an unchanged policy does not redeploy")
	}

	different, err := deployer.ScriptMatches(context.Background(), "s", "export default { fetch() { return 1; } };")
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if different {
		t.Error("changed source must report a mismatch")
	}
}

func TestScriptMatchesTreatsMissingScriptAsMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10007,"message":"workers.api.error.script_not_found"}]}`)
	}))
	defer server.Close()

	same, err := New(cfapi.New(server.URL, "tok"), "acc-1").ScriptMatches(context.Background(), "s", "anything")
	if err != nil {
		t.Fatalf("a missing script is a normal first-run state, not an error: %v", err)
	}
	if same {
		t.Error("a missing script must report a mismatch so it gets uploaded")
	}
}

func TestAttachDomainSendsHostnameAndZone(t *testing.T) {
	var gotBody map[string]any
	var gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		decodeJSON(t, body, &gotBody)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"d1"}}`)
	}))
	defer server.Close()

	err := New(cfapi.New(server.URL, "tok"), "acc-1").
		AttachDomain(context.Background(), "mta-sts.a.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("AttachDomain: %v", err)
	}

	if gotMethod != http.MethodPut || gotPath != "/accounts/acc-1/workers/domains" {
		t.Errorf("%s %s, want PUT /accounts/acc-1/workers/domains", gotMethod, gotPath)
	}
	for key, want := range map[string]any{
		"hostname":    "mta-sts.a.com",
		"zone_id":     "z1",
		"service":     "mailctl-mta-sts-a-com",
		"environment": "production",
	} {
		if gotBody[key] != want {
			t.Errorf("body[%q] = %v, want %v", key, gotBody[key], want)
		}
	}
}

func TestDomainAttachedFiltersByHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"d1","hostname":"mta-sts.a.com","zone_id":"z1","service":"mailctl-mta-sts-a-com"}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	attached, err := deployer.DomainAttached(context.Background(), "mta-sts.a.com", "z1")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if !attached {
		t.Error("the listed hostname should report as attached")
	}

	missing, err := deployer.DomainAttached(context.Background(), "mta-sts.b.com", "z1")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if missing {
		t.Error("an unlisted hostname must report as not attached")
	}
}
```

Add this helper at the bottom of the same file, and import `"encoding/json"`:

```go
func decodeJSON(t *testing.T, data []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode body %q: %v", data, err)
	}
}
```

- [ ] **Step 6: Run it and confirm it fails**

Run: `go test ./internal/worker/ -run 'TestUpload|TestScriptMatches|TestAttach|TestDomain' -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 7: Add a raw GET to the shared Cloudflare client**

The script-download endpoint returns JavaScript, not a JSON envelope, so `cfapi.Do`
cannot read it. Add this to `internal/cfapi/client.go`:

```go
// Raw performs a GET and returns the response body unparsed, for endpoints that
// answer with something other than the JSON envelope. found is false when the
// resource does not exist, which is a normal state rather than an error.
func (c *Client) Raw(ctx context.Context, path string) (body []byte, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build Cloudflare GET %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("Cloudflare GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read Cloudflare GET %s response: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("Cloudflare GET %s returned %s: %s",
			path, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, true, nil
}
```

- [ ] **Step 8: Implement the deployer**

Create `internal/worker/deploy.go`:

```go
package worker

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

// moduleFilename is both the uploaded part name and the main_module value.
const moduleFilename = "worker.mjs"

type Deployer struct {
	api       *cfapi.Client
	accountID string
}

func New(api *cfapi.Client, accountID string) *Deployer {
	return &Deployer{api: api, accountID: accountID}
}

func (d *Deployer) scriptPath(name string) string {
	return "/accounts/" + d.accountID + "/workers/scripts/" + name
}

// ScriptMatches reports whether the deployed script is byte-identical to
// source. A script that does not exist reports false, not an error.
func (d *Deployer) ScriptMatches(ctx context.Context, name, source string) (bool, error) {
	body, found, err := d.api.Raw(ctx, d.scriptPath(name))
	if err != nil {
		return false, fmt.Errorf("read Worker script %s: %w", name, err)
	}
	if !found {
		return false, nil
	}
	return strings.TrimSpace(string(body)) == strings.TrimSpace(source), nil
}

// Upload replaces the script. The upload is a multipart form with a JSON
// metadata part naming the entry module, plus the module itself.
func (d *Deployer) Upload(ctx context.Context, name, source string) error {
	metadata := fmt.Sprintf(`{"main_module":%q,"compatibility_date":%q}`, moduleFilename, CompatibilityDate)

	parts := []cfapi.Part{
		{Name: "metadata", ContentType: "application/json", Data: []byte(metadata)},
		{
			Name:        moduleFilename,
			Filename:    moduleFilename,
			ContentType: "application/javascript+module",
			Data:        []byte(source),
		},
	}
	if err := d.api.Multipart(ctx, http.MethodPut, d.scriptPath(name), parts, nil); err != nil {
		return fmt.Errorf("upload Worker script %s: %w", name, err)
	}
	return nil
}

type attachedDomain struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	ZoneID   string `json:"zone_id"`
	Service  string `json:"service"`
}

// DomainAttached reports whether a custom domain is already bound.
func (d *Deployer) DomainAttached(ctx context.Context, hostname, zoneID string) (bool, error) {
	domains, err := cfapi.List[attachedDomain](ctx, d.api, "/accounts/"+d.accountID+"/workers/domains")
	if err != nil {
		return false, fmt.Errorf("list Worker custom domains: %w", err)
	}
	for _, domain := range domains {
		if strings.EqualFold(domain.Hostname, hostname) && domain.ZoneID == zoneID {
			return true, nil
		}
	}
	return false, nil
}

// AttachDomain binds hostname to a script. Cloudflare provisions the DNS record
// and the certificate, which is why mailctl publishes no record for this name.
func (d *Deployer) AttachDomain(ctx context.Context, hostname, zoneID, scriptName string) error {
	payload := map[string]any{
		"environment": "production",
		"hostname":    hostname,
		"service":     scriptName,
		"zone_id":     zoneID,
	}
	if err := d.api.Do(ctx, http.MethodPut, "/accounts/"+d.accountID+"/workers/domains", payload, nil); err != nil {
		return fmt.Errorf("bind %s to Worker %s: %w", hostname, scriptName, err)
	}
	return nil
}
```

- [ ] **Step 9: Run the tests and verify they pass**

Run: `go test ./internal/worker/ ./internal/cfapi/ -v`
Expected: PASS (9 worker tests, plus the existing cfapi tests still green).

- [ ] **Step 10: Confirm the two Workers endpoints against the live API**

The spec flagged both of these as documented but unverified. Confirm with read-only
calls before Task 6 depends on them:

```bash
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/workers/domains" \
  | python3 -m json.tool
```

Expected: `success: true` and a `result` array whose objects carry `hostname`, `zone_id`,
and `service`. If a field is named differently, update `attachedDomain` and the literal
in `TestDomainAttachedFiltersByHostname`.

The script upload is a write, so it is exercised for real in Task 6 Step 5 against
`example.com`. If `PUT .../workers/scripts/{name}` is rejected, the fallback is
`POST` to the same path — change the method in `Upload` and in
`TestUploadSendsMultipartModule` together.

- [ ] **Step 11: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/worker/ internal/cfapi/client.go
git commit -m "feat(worker): deploy and bind the mta-sts policy worker"
```

---

### Task 6: Wire deliverability into the engine

**Files:**
- Modify: `internal/engine/engine.go`
- Test: `internal/engine/deliverability_test.go`

**Interfaces:**
- Consumes: `deliver.Merge`, `deliver.Result`, `worker.New`, `worker.ScriptName`, `worker.PolicyScript`.
- Produces: `engine.Options` gains no new fields; `engine.New` gains a `*worker.Deployer` parameter. `cmd/mailctl` passes it.

- [ ] **Step 1: Write the failing test**

Create `internal/engine/deliverability_test.go`:

```go
package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
	"github.com/zoolcoder/mailctl/internal/worker"
)

func mailProviderWithMX() *fakeMail {
	return &fakeMail{name: "fake", desired: []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.fake.com ~all", Kind: dns.KindSPF},
	}}
}

func deliverabilityConfig(v config.Deliverability) config.Config {
	return config.Config{
		Version: config.SchemaVersion,
		Domains: []config.Domain{{
			Name:           "a.com",
			ZoneName:       "a.com",
			Mail:           config.Mail{Providers: []string{"fake"}},
			Deliverability: v,
		}},
	}
}

func countDetail(p plan.Plan, needle string) int {
	n := 0
	for _, a := range p.Actions {
		if strings.Contains(a.Detail, needle) {
			n++
		}
	}
	return n
}

func TestPlanPublishesConfiguredDMARC(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		DMARC: &config.DMARC{Policy: "reject", Pct: 100, RUA: "mailto:d@a.com"},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=DMARC1; p=reject") != 1 {
		t.Errorf("plan should create the DMARC record exactly once:\n%+v", got.Actions)
	}
}

func TestPlanPublishesOneMergedSPFRecord(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{SPFIncludes: []string{"include:extra.com"}})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=spf1") != 1 {
		t.Fatalf("want exactly one SPF action; two SPF records on one name is a hard failure:\n%+v", got.Actions)
	}
	if countDetail(got, "include:extra.com") != 1 || countDetail(got, "include:_spf.fake.com") != 1 {
		t.Errorf("the merged record must carry both includes:\n%+v", got.Actions)
	}
}

func TestPlanDeploysTheWorkerWhenMTAStsAsksForIt(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "enforce", MaxAge: 604800, Deploy: true},
	})
	deployer := worker.New(cfapi.New("http://127.0.0.1:1", "tok"), "acc-1")
	e := New(cfg, &fakeDNS{}, deployer, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if countDetail(got, "v=STSv1; id=") != 1 {
		t.Errorf("plan should create the _mta-sts TXT record:\n%+v", got.Actions)
	}
	if countDetail(got, worker.ScriptName("a.com")) < 2 {
		t.Errorf("plan should both upload the script and bind the custom domain:\n%+v", got.Actions)
	}
}

func TestPlanSkipsTheWorkerWhenDeployIsFalse(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "testing", MaxAge: 86400, Deploy: false},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=STSv1; id=") != 1 {
		t.Errorf("the TXT record is still published when the policy is hosted elsewhere:\n%+v", got.Actions)
	}
	if countDetail(got, "Worker") != 0 {
		t.Errorf("deploy: false must not plan any Worker action:\n%+v", got.Actions)
	}
}

func TestPlanFailsWhenMTAStsDeployHasNoAccountID(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "enforce", Deploy: true},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	_, err := e.Plan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "accountId") {
		t.Fatalf("err = %v, want an error naming the missing accountId", err)
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/engine/ -run 'TestPlanPublishes|TestPlanDeploys|TestPlanSkips|TestPlanFailsWhenMTA' -v`
Expected: FAIL — `New` takes four arguments, not five.

- [ ] **Step 3: Add the deployer to the engine**

In `internal/engine/engine.go`, change the struct and constructor:

```go
type Engine struct {
	cfg      config.Config
	zone     dns.Provider
	deployer *worker.Deployer
	deps     mail.Deps
	opts     Options
}

// New builds an engine. deployer may be nil when no domain deploys an MTA-STS
// policy Worker; a domain that asks for one then fails with a clear message.
func New(cfg config.Config, zone dns.Provider, deployer *worker.Deployer, deps mail.Deps, opts Options) *Engine {
	if opts.Secrets == nil {
		opts.Secrets = secret.NewResolver(nil)
	}
	return &Engine{cfg: cfg, zone: zone, deployer: deployer, deps: deps, opts: opts}
}
```

Add `"github.com/zoolcoder/mailctl/internal/deliver"` and
`"github.com/zoolcoder/mailctl/internal/worker"` to the imports.

Update the five `New(...)` calls in `internal/engine/engine_test.go` to pass `nil` for
the new parameter.

- [ ] **Step 4: Fold deliverability into planDomain**

In `planDomain`, replace the block that ends with `out.Add(dnsActions...)` so the
provider union runs through `deliver.Merge` first, and the Worker actions are appended
after the DNS actions:

```go
	// desired is the union across providers, built in the loop above.
	merged, err := deliver.Merge(d, desired)
	if err != nil {
		return out, err
	}

	zone, err := e.zone.Zone(ctx, d.ZoneName)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	actualRecords, err := e.zone.Records(ctx, zone.ID)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	dnsActions, err := dns.Diff(e.zone, zone.ID, d.Name, actualRecords, merged.Records,
		dns.DiffOptions{ReplaceConflicts: e.opts.ReplaceDNS})
	if err != nil {
		return out, err
	}
	out.Add(dnsActions...)

	workerActions, err := e.planWorker(ctx, d, zone.ID, merged)
	if err != nil {
		return out, err
	}
	out.Add(workerActions...)
```

- [ ] **Step 5: Implement planWorker**

Append to `internal/engine/engine.go`:

```go
// planWorker plans the upload and binding of the MTA-STS policy Worker. It is a
// no-op unless the domain sets mtaSts.deploy.
func (e *Engine) planWorker(ctx context.Context, d config.Domain, zoneID string, merged deliver.Result) ([]plan.Action, error) {
	if merged.MTAStsPolicy == "" || d.Deliverability.MTASts == nil || !d.Deliverability.MTASts.Deploy {
		return nil, nil
	}
	if e.deployer == nil {
		return nil, fmt.Errorf(
			"domain %s: mtaSts.deploy is true but cloudflare.accountId is not set in the config",
			d.Name)
	}

	name := worker.ScriptName(d.Name)
	source := worker.PolicyScript(merged.MTAStsPolicy)
	var actions []plan.Action

	matches, err := e.deployer.ScriptMatches(ctx, name, source)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if !matches {
		actions = append(actions, plan.Action{
			Op:       plan.OpUpdate,
			Resource: "worker",
			Domain:   d.Name,
			Provider: "cloudflare",
			Detail:   "upload MTA-STS policy Worker " + name,
			Do: func(ctx context.Context) error {
				return e.deployer.Upload(ctx, name, source)
			},
		})
	}

	attached, err := e.deployer.DomainAttached(ctx, merged.MTAStsHost, zoneID)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if !attached {
		host := merged.MTAStsHost
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "worker",
			Domain:   d.Name,
			Provider: "cloudflare",
			Detail:   fmt.Sprintf("bind %s to Worker %s", host, name),
			Do: func(ctx context.Context) error {
				return e.deployer.AttachDomain(ctx, host, zoneID, name)
			},
		})
	}
	return actions, nil
}
```

Note the ordering guarantee this relies on: `ScriptMatches` and `DomainAttached` are
reads performed during `Plan`, so `plan` stays read-only. In
`TestPlanDeploysTheWorkerWhenMTAStsAsksForIt` the deployer points at a dead address, so
both reads fail — which is why that test must instead use a live `httptest` server.
Rewrite that one test to build a `httptest.Server` returning `404` for the script GET and
an empty `result` array for the domains list, matching Task 5's fakes, so both reads
succeed and report "not deployed".

- [ ] **Step 6: Pass the deployer from the CLI**

In `cmd/mailctl/main.go`, build a deployer when an account ID is configured and pass it
to `engine.New`:

```go
	var deployer *worker.Deployer
	if cfg.Cloudflare.AccountID != "" {
		deployer = worker.New(api, cfg.Cloudflare.AccountID)
	}

	runner := engine.New(cfg, cfdns.New(api, cfg.Cloudflare.TTL), deployer, mail.Deps{
```

Add `"github.com/zoolcoder/mailctl/internal/worker"` to the imports.

- [ ] **Step 7: Run the whole suite and verify it passes**

Run: `go test ./... -v`
Expected: PASS in every package.

- [ ] **Step 8: Apply deliverability to example**

Add to `mailctl.yaml` under `example.com`:

```yaml
    deliverability:
      dmarc:
        policy: quarantine
        subdomainPolicy: reject
        pct: 100
        rua: mailto:dmarc@example.com
      mtaSts:
        mode: testing
        maxAge: 604800
        deploy: true
      tlsRpt: mailto:tls@example.com
```

`mode: testing` first, deliberately: an enforce policy with a wrong MX list silently
rejects inbound mail, and testing mode reports without rejecting. Move to `enforce` after
a week of clean reports.

```bash
go build -o mailctl ./cmd/mailctl
./mailctl plan -domain example.com
```

Expected actions: replace the Purelymail `_dmarc` CNAME with the configured TXT (this
needs `-replace-dns`, since a CNAME on `_dmarc` conflicts with the desired TXT), create
`_mta-sts` TXT, create `_smtp._tls` TXT, upload the Worker, bind `mta-sts.example.com`.

```bash
./mailctl apply -domain example.com -replace-dns
```

- [ ] **Step 9: Verify the published policy is actually reachable**

```bash
curl -s https://mta-sts.example.com/.well-known/mta-sts.txt
dig +short TXT _mta-sts.example.com
dig +short TXT _dmarc.example.com
```

Expected: the policy body served as text, and the TXT record carrying an `id` equal to
the first 16 hex characters of the policy's SHA-256. Certificate provisioning for the new
hostname can take a few minutes; a TLS error immediately after apply is expected, a TLS
error an hour later is not.

- [ ] **Step 10: Prove idempotence**

```bash
./mailctl plan -domain example.com
```

Expected: `No changes.` A repeated Worker upload here means `PolicyScript` is not
byte-stable or `ScriptMatches` is comparing wrongly; a repeated `_mta-sts` create means
`MXHosts` is not sorting.

- [ ] **Step 11: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/engine/ cmd/mailctl/main.go
git commit -m "feat(engine): publish deliverability records and mta-sts worker"
```

---

## Self-review

**Spec coverage.** SPF merged into a single record with provider and config includes
(Task 1); DMARC, TLS-RPT, and BIMI builders (Task 2); MTA-STS policy text with an id
derived from the policy so edits reach receivers, plus the refusal to publish an enforce
policy with no MX (Task 3); the merge that makes the configured DMARC policy win over a
provider's CNAME and keeps exactly one SPF record (Task 4); the Worker uploaded through
the REST API with a `main_module` multipart, and the custom-domain binding that
provisions the DNS record and certificate (Task 5); `deploy: false` emitting the TXT
records without the Worker (Tasks 4 and 6); everything reconciled idempotently and
verified against the live domain (Task 6, Steps 8–10).

**Placeholder scan.** No TBDs. The two endpoints the spec flagged as unverified —
`PUT /accounts/{a}/workers/domains` and the script upload method — have an explicit
verification step (Task 5, Step 10) naming the exact fallback and the two places to
change together.

**Type consistency.** `deliver.Result` fields `Records`/`MTAStsPolicy`/`MTAStsHost` are
used identically in Tasks 4 and 6. `worker.Deployer` methods `ScriptMatches`/`Upload`/
`DomainAttached`/`AttachDomain` match between Task 5's implementation and Task 6's
`planWorker`. `engine.New` gains its fifth parameter in Task 6 Step 3, and the same step
updates the existing call sites in `engine_test.go` and Task 6 Step 6 updates the CLI.

**Known soft spot.** Task 6 Step 5 flags a test that cannot work as first written:
`TestPlanDeploysTheWorkerWhenMTAStsAsksForIt` points the deployer at a dead address while
`planWorker` performs live reads. The step says to rewrite it against an `httptest`
server. Do that rather than making `planWorker` swallow read errors — a plan that cannot
read current Worker state must fail loudly, not guess.
