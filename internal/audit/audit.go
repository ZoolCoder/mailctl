// Package audit checks published DNS through a real resolver rather than
// through the provider API, because the API reports what you asked for and not
// what the internet sees.
package audit

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type Resolver interface {
	LookupMX(ctx context.Context, name string) ([]string, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupCNAME(ctx context.Context, name string) (string, error)
}

type Fetcher interface {
	Get(ctx context.Context, url string) (string, error)
}

type Check struct {
	Name string
	Want string
	Got  string
	OK   bool
}

type Report struct {
	Domain string
	Checks []Check
	Notes  []string
}

func (r Report) OK() bool {
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return true
}

// Render writes failures first; a long list of passes should not hide the one
// line that matters.
func (r Report) Render(w io.Writer) {
	fmt.Fprintf(w, "\naudit %s\n", r.Domain)

	ordered := make([]Check, len(r.Checks))
	copy(ordered, r.Checks)
	sort.SliceStable(ordered, func(i, j int) bool { return !ordered[i].OK && ordered[j].OK })

	for _, check := range ordered {
		if check.OK {
			fmt.Fprintf(w, "  ok    %s\n", check.Name)
			continue
		}
		fmt.Fprintf(w, "  FAIL  %s\n          want %s\n          got  %s\n", check.Name, check.Want, orNone(check.Got))
	}
	for _, note := range r.Notes {
		fmt.Fprintf(w, "  note  %s\n", note)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(nothing published)"
	}
	return s
}

// Run resolves every desired record and, when MTA-STS is configured, fetches
// the policy endpoint. mode: none is included: it is a published withdrawal
// policy (a rotated _mta-sts TXT id plus a Worker serving mode: none), not an
// absence of publication, so it is audited like any other mode.
func Run(ctx context.Context, d config.Domain, desired []dns.Record, resolver Resolver, fetcher Fetcher) Report {
	report := Report{Domain: d.Name}
	spfCount := 0
	// spfIndex identifies the SPF check by position, not by name: a
	// purelymail domain's desired set carries two TXT checks named
	// "TXT <domain>" (SPF and the ownership-proof record), and matching by
	// name would flip both when SPF is duplicated, misdiagnosing the
	// unrelated ownership record as failed.
	spfIndex := -1

	for _, want := range desired {
		check := Check{Name: want.Type + " " + want.Name, Want: want.Content}

		switch strings.ToUpper(want.Type) {
		case "MX":
			hosts, err := resolver.LookupMX(ctx, want.Name)
			if err != nil {
				check.Got = err.Error()
			} else {
				check.Got = strings.Join(hosts, ", ")
				check.OK = containsHost(hosts, want.Content)
			}
		case "TXT":
			values, err := resolver.LookupTXT(ctx, want.Name)
			if err != nil {
				check.Got = err.Error()
			} else {
				check.Got = strings.Join(values, " | ")
				check.OK = containsExact(values, want.Content)
				if want.Kind == dns.KindSPF {
					spfCount = countSPF(values)
				}
			}
		case "CNAME":
			target, err := resolver.LookupCNAME(ctx, want.Name)
			if err != nil {
				check.Got = err.Error()
			} else {
				check.Got = target
				check.OK = equalHost(target, want.Content)
			}
		default:
			check.Got = "unchecked record type"
			check.OK = true
		}
		report.Checks = append(report.Checks, check)
		if want.Kind == dns.KindSPF {
			spfIndex = len(report.Checks) - 1
		}
	}

	if spfCount > 1 && spfIndex >= 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"%d SPF records are published on %s; RFC 7208 requires exactly one, and receivers treat more as a permanent error",
			spfCount, d.Name))
		report.Checks[spfIndex].OK = false
	}

	// The check's presence is driven by desired, not by config, keeping it
	// consistent with every other check above: those all audit what desired
	// asked for, and this one should too. If desired has no MTA-STS record,
	// the record loop above wouldn't have checked it either, so skipping the
	// fetch is the coherent "not configured here" state rather than a hole.
	//
	// Assertion strength, in contrast, must come from the config: the
	// _mta-sts TXT carries only the id, never the mode, so there is no way
	// to know which mode to demand except by asking Deliverability.MTASts.
	// Do not fold these two back into one source (e.g. gating presence on
	// Deliverability.MTASts) — that is what made the presence check
	// impossible to satisfy for a desired set built without a matching
	// config, which is exactly what audit_test.go's fixtures do.
	if hasMTASts(desired) {
		url := "https://mta-sts." + d.Name + "/.well-known/mta-sts.txt"
		var wantMode string
		if d.Deliverability.MTASts != nil && d.Deliverability.MTASts.Mode != "" {
			wantMode = d.Deliverability.MTASts.Mode
		}
		check := Check{Name: "mta-sts policy at " + url, Want: mtaStsWant(wantMode)}
		body, err := fetcher.Get(ctx, url)
		if err != nil {
			check.Got = err.Error()
		} else {
			check.Got = summarizeSTSBody(body)
			// An empty wantMode means the config didn't specify a mode (or
			// wasn't populated at all); fall back to a version-only check
			// rather than demanding a mode nothing asked for.
			check.OK = strings.Contains(body, "version: STSv1") && (wantMode == "" || stsMode(body) == wantMode)
		}
		report.Checks = append(report.Checks, check)
	}

	return report
}

func countSPF(values []string) int {
	n := 0
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "v=spf1") {
			n++
		}
	}
	return n
}

func containsHost(hosts []string, want string) bool {
	for _, host := range hosts {
		if equalHost(host, want) {
			return true
		}
	}
	return false
}

func containsExact(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func equalHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// hasMTASts reports whether an MTA-STS record is among the desired records.
func hasMTASts(desired []dns.Record) bool {
	for _, record := range desired {
		if record.Kind == dns.KindMTASts {
			return true
		}
	}
	return false
}

// mtaStsWant describes the expected policy body for the report; it names the
// mode when one is known and stays generic otherwise.
func mtaStsWant(mode string) string {
	if mode == "" {
		return "a text/plain STSv1 policy"
	}
	return fmt.Sprintf("a text/plain STSv1 policy declaring mode: %s", mode)
}

// stsMode returns the value of the "mode:" line in an MTA-STS policy body, or
// "" if none is present.
func stsMode(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "mode:"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// summarizeSTSBody condenses a policy body to its version and mode lines, so
// a mode mismatch (an "enforce" body under a "none" config) is visible
// directly in the rendered report without dumping the whole policy.
func summarizeSTSBody(body string) string {
	var version, mode string
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "version:"):
			version = line
		case strings.HasPrefix(line, "mode:"):
			mode = line
		}
	}
	return strings.TrimSpace(version + " " + mode)
}

// NetResolver returns a Resolver backed by the system resolver.
func NetResolver() Resolver { return netResolver{r: net.DefaultResolver} }

type netResolver struct{ r *net.Resolver }

func (n netResolver) LookupMX(ctx context.Context, name string) ([]string, error) {
	records, err := n.r.LookupMX(ctx, name)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		hosts = append(hosts, record.Host)
	}
	return hosts, nil
}

func (n netResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return n.r.LookupTXT(ctx, name)
}

func (n netResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	return n.r.LookupCNAME(ctx, name)
}

// HTTPFetcher returns a Fetcher backed by net/http.
func HTTPFetcher() Fetcher {
	return httpFetcher{client: &http.Client{Timeout: 15 * time.Second}}
}

type httpFetcher struct{ client *http.Client }

func (h httpFetcher) Get(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return string(body), nil
}
