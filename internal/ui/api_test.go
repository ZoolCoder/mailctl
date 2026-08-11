package ui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

type fakePlanner struct {
	domains        []config.Domain
	planned        plan.Plan
	planErr        error
	planned_       int // times Plan was called
	domainsCalled_ int // times Domains was called
	// desiredErr maps a domain name to the error Desired should return for it.
	// A domain absent from this map succeeds with no records.
	desiredErr map[string]error
}

func (f *fakePlanner) Domains() ([]config.Domain, error) {
	f.domainsCalled_++
	return f.domains, nil
}
func (f *fakePlanner) Plan(context.Context) (plan.Plan, error) {
	f.planned_++
	return f.planned, f.planErr
}
func (f *fakePlanner) Desired(_ context.Context, d config.Domain) ([]dns.Record, error) {
	if err, ok := f.desiredErr[d.Name]; ok {
		return nil, err
	}
	return nil, nil
}

func fakeAudit(context.Context, config.Domain, []dns.Record) audit.Report {
	return audit.Report{Domain: "example.com"}
}

func testServer(t *testing.T, p Planner) http.Handler {
	t.Helper()
	handler, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: p,
		Audit: fakeAudit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return handler
}

func authed(method, target string) *http.Request {
	req := httptest.NewRequest(method, "http://127.0.0.1:1234"+target, nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "secret")
	req.Header.Set("Origin", "http://127.0.0.1:1234")
	return req
}

func TestDomainsEndpointReadsConfigWithoutTouchingProviders(t *testing.T) {
	fake := &fakePlanner{domains: []config.Domain{
		{Name: "example.com", ZoneName: "example.com"},
		{Name: "example.net", ZoneName: "example.net"},
	}}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/domains"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Domains []struct {
			Name string `json:"name"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v — %s", err, rec.Body.String())
	}
	if len(doc.Domains) != 2 || doc.Domains[0].Name != "example.com" {
		t.Errorf("domains = %+v", doc.Domains)
	}
	// The first paint must be instant and must not spend a provider call.
	if fake.planned_ != 0 {
		t.Errorf("Plan was called %d times serving /api/domains; it must reach no provider", fake.planned_)
	}
}

func TestAPIRequiresAuthentication(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/domains", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for an unauthenticated api call, want 403", rec.Code)
	}
}

// A GET carrying a valid token must still be refused with a 404, not fall
// through to the SPA shell. With a "/" catch-all registered, ServeMux does not
// answer 405 for a method-pattern mismatch on a path it otherwise recognizes —
// "GET /api/plan" falls through to "/" and would answer 200 with HTML absent
// the explicit /api/ guard in New. Asserting only the status would pass
// against a route that quietly serves the shell with a 200-disguised-as-404
// body, so this also asserts the body is not the app shell.
func TestUnmatchedAPIMethodIsNotTheShell(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/plan"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for GET /api/plan, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("GET /api/plan served the html shell: %s", rec.Body.String())
	}
}

// This is the exact shape a real browser produces loading the app's own
// bundle: the shell (loaded with ?token=... in the URL) requests "./app.js"
// as a relative subresource with no query string, and a browser cannot
// attach a custom header such as X-Mailctl-Token to that request — script,
// style, font, and image loads simply do not carry one. If static assets
// required the token, the bundle could never load and the app would render
// blank. Accept: */* is what a <script src> fetch sends.
func TestBrowserSubresourceLoadsWithoutToken(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/app.js", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("Accept", "*/*")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the bundle loaded with no token, the browser's own shape", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "function") {
		t.Errorf("body does not look like javascript: %s", rec.Body.String()[:min(200, len(rec.Body.String()))])
	}
}

// Static assets are deliberately NOT token-guarded. This inverts what this
// test asserted before: it used to require 403 without a token, which broke
// the app in a real browser, because the shell's own "<script
// src=./app.js>" load can never carry the token — a browser cannot attach a
// custom header to a subresource request. The bundle is not a secret either
// way: it is compiled into a public binary and its source lives in a public
// repository. Do not "fix" this back to requiring the token; see
// newHostOriginGuard and TestBrowserSubresourceLoadsWithoutToken above for
// why a token requirement here cannot work at all, not merely why it's
// undesirable.
func TestStaticAssetsAreNotTokenGuarded(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d for an unauthenticated request to /, want 200; static assets carry no secret and cannot be token-guarded", rec.Code)
	}
}

// Static assets still sit behind Host and Origin: a DNS-rebound page cannot
// load the shell at all, because rebinding sends a foreign Host.
func TestStaticAssetsRejectForeignHost(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/", nil)
	req.Host = "attacker.example"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for a foreign Host requesting /, want 403", rec.Code)
	}
}

// Static assets still sit behind Host and Origin: a cross-origin page cannot
// fetch the shell either, because its Origin will not be ours.
func TestStaticAssetsRejectForeignOrigin(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/app.js", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("Origin", "http://evil.example")

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for a foreign Origin requesting /app.js, want 403", rec.Code)
	}
}

// A correctly authenticated request must still reach the static handler and
// get the real app shell, not merely a non-403 status that a black-hole
// middleware would also produce. The token header here is incidental — the
// launch URL's browser sends it on the initial navigation before it has even
// loaded the app that would stop sending it — and must not be required by
// the guard; the point of this test is that Host and Origin still let it
// through.
func TestStaticAssetsServeTheShellOnceAuthenticated(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("body does not look like the app shell: %s", rec.Body.String())
	}
}

// Each New* rejection test below asserts the error names its own field, not
// merely that New returned some error. A copy-paste bug that returned the
// same generic message from every branch, or a reordering that let one check
// shadow another, would still pass a bare err == nil assertion.

func TestNewRejectsEmptyToken(t *testing.T) {
	_, err := New(Deps{
		Token: "", Host: "127.0.0.1:1234", Planner: &fakePlanner{}, Audit: fakeAudit,
	})
	if err == nil {
		t.Fatal("New with an empty Token returned nil error, want a validation error")
	}
	if !strings.Contains(err.Error(), "Token") {
		t.Errorf("error = %q, want it to name Token", err)
	}
}

func TestNewRejectsEmptyHost(t *testing.T) {
	_, err := New(Deps{
		Token: "secret", Host: "", Planner: &fakePlanner{}, Audit: fakeAudit,
	})
	if err == nil {
		t.Fatal("New with an empty Host returned nil error, want a validation error")
	}
	if !strings.Contains(err.Error(), "Host") {
		t.Errorf("error = %q, want it to name Host", err)
	}
}

func TestNewRejectsNilPlanner(t *testing.T) {
	_, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: nil, Audit: fakeAudit,
	})
	if err == nil {
		t.Fatal("New with a nil Planner returned nil error, want a validation error")
	}
	if !strings.Contains(err.Error(), "Planner") {
		t.Errorf("error = %q, want it to name Planner", err)
	}
}

func TestNewRejectsNilAuditor(t *testing.T) {
	_, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: &fakePlanner{}, Audit: nil,
	})
	if err == nil {
		t.Fatal("New with a nil Audit returned nil error, want a validation error")
	}
	if !strings.Contains(err.Error(), "Audit") {
		t.Errorf("error = %q, want it to name Audit", err)
	}
}

// TestPlanEndpointReturnsTheProjectedPlan pins the positive counterpart to
// TestPlanEndpointRefusesGET below: an authenticated POST must reach the real
// planjson projection, not merely a non-error status. httptest.NewRecorder
// starts at 200, so a handler that writes nothing would pass a bare status
// check; asserting on the body's shape is what catches that.
func TestPlanEndpointReturnsTheProjectedPlan(t *testing.T) {
	fake := &fakePlanner{planned: plan.Plan{Actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "example.com",
			Provider: "purelymail", Detail: "create contact@example.com"},
	}}}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodPost, "/api/plan"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Actions       []struct {
			Op     string `json:"op"`
			Detail string `json:"detail"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v — %s", err, rec.Body.String())
	}
	if doc.SchemaVersion != 1 || len(doc.Actions) != 1 || doc.Actions[0].Op != "CREATE" {
		t.Errorf("plan body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "func") {
		t.Error("the response must not carry anything executable")
	}
}

// A GET must not plan: planning calls provider APIs, and a GET is what a
// prefetch, a crawler, or an address-bar visit issues.
func TestPlanEndpointRefusesGET(t *testing.T) {
	fake := &fakePlanner{}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/plan"))

	if rec.Code == http.StatusOK {
		t.Error("GET /api/plan returned 200; planning must require an explicit POST")
	}
	if strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Error("GET /api/plan served the html shell; an api path must never fall through to the spa")
	}
	if fake.planned_ != 0 {
		t.Errorf("Plan ran %d times for a GET; a prefetch must not spend provider calls", fake.planned_)
	}
}

// The audit mirror of TestPlanEndpointRefusesGET: auditing calls provider APIs
// through Domains and Desired, and a GET is what a prefetch, a crawler, or an
// address-bar visit issues.
func TestAuditEndpointRefusesGET(t *testing.T) {
	fake := &fakePlanner{domains: []config.Domain{{Name: "example.com"}}}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/audit"))

	if rec.Code == http.StatusOK {
		t.Error("GET /api/audit returned 200; auditing must require an explicit POST")
	}
	if strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Error("GET /api/audit served the html shell; an api path must never fall through to the spa")
	}
	if fake.domainsCalled_ != 0 {
		t.Errorf("Domains ran %d times for a GET; a prefetch must not spend provider calls", fake.domainsCalled_)
	}
}

// An unknown /api/ path must be a 404, not the html shell.
func TestUnknownAPIPathIsNotTheShell(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/nonexistent"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for an unknown api path, want 404 — body: %s", rec.Code, rec.Body.String())
	}
}

func TestPlanStubRequiresAuthentication(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api/plan", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for unauthenticated POST /api/plan, want 403", rec.Code)
	}
}

// TestAuditEndpointReturnsOneReportPerDomain pins the positive counterpart to
// TestAuditReportsPerDomainErrorsWithoutFailingTheRun below: an authenticated
// POST must reach the real per-domain audit, with each domain's own Audit
// result reflected in the response rather than a shared or default value.
func TestAuditEndpointReturnsOneReportPerDomain(t *testing.T) {
	fake := &fakePlanner{domains: []config.Domain{
		{Name: "good.example"}, {Name: "bad.example"},
	}}
	handler, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: fake,
		Audit: func(_ context.Context, d config.Domain, _ []dns.Record) audit.Report {
			return audit.Report{Domain: d.Name, Checks: []audit.Check{
				{Name: "MX", OK: d.Name == "good.example"},
			}}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authed(http.MethodPost, "/api/audit"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Reports []struct {
			Domain string `json:"domain"`
			OK     bool   `json:"ok"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v", err)
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("got %d reports, want one per domain", len(doc.Reports))
	}
	if !doc.Reports[0].OK || doc.Reports[1].OK {
		t.Errorf("reports = %+v, want good.example passing and bad.example failing", doc.Reports)
	}
}

// One domain's Desired call failing must not blank the whole view: the
// operator needs to see the domains that did resolve, with the failing one
// carrying its own error inline.
func TestAuditReportsPerDomainErrorsWithoutFailingTheRun(t *testing.T) {
	fake := &fakePlanner{
		domains: []config.Domain{{Name: "good.example"}, {Name: "bad.example"}},
		desiredErr: map[string]error{
			"bad.example": errors.New("resolve desired records: dns lookup failed"),
		},
	}
	handler, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: fake,
		Audit: func(_ context.Context, d config.Domain, _ []dns.Record) audit.Report {
			return audit.Report{Domain: d.Name, Checks: []audit.Check{{Name: "MX", OK: true}}}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authed(http.MethodPost, "/api/audit"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a single domain's error must not fail the run: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Reports []struct {
			Domain string `json:"domain"`
			OK     bool   `json:"ok"`
			Error  string `json:"error,omitempty"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v — %s", err, rec.Body.String())
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("got %d reports, want one per domain even though one failed", len(doc.Reports))
	}
	if doc.Reports[0].Domain != "good.example" || doc.Reports[0].Error != "" {
		t.Errorf("good.example report = %+v, want no error", doc.Reports[0])
	}
	if doc.Reports[1].Domain != "bad.example" || doc.Reports[1].Error == "" {
		t.Errorf("bad.example report = %+v, want its own error inline", doc.Reports[1])
	}
	if fake.planned_ != 0 {
		t.Errorf("Plan ran %d times serving /api/audit; audit must not run a full plan", fake.planned_)
	}
}

func TestAuditStubRequiresAuthentication(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api/audit", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for unauthenticated POST /api/audit, want 403", rec.Code)
	}
}

// A payload encoding/json cannot marshal at all — a func or channel field —
// fails before the first byte is written. Encoding straight to the
// ResponseWriter would leave the status unset, and Go answers an unset status
// with 200: a successful, empty response for a request that actually failed,
// with no server-side trail either since this request path never logs.
// writeJSON must catch that failure and answer 500 with a non-empty body.
func TestWriteJSONRefusesAnUnmarshallablePayload(t *testing.T) {
	rec := httptest.NewRecorder()

	writeJSON(rec, struct{ Do func() }{Do: func() {}})

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a payload encoding/json cannot marshal", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("body is empty; a marshal failure must not look like a successful empty response")
	}
}
