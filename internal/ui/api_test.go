package ui

import (
	"context"
	"encoding/json"
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
	domains  []config.Domain
	planned  plan.Plan
	planErr  error
	planned_ int // times Plan was called
}

func (f *fakePlanner) Domains() ([]config.Domain, error) { return f.domains, nil }
func (f *fakePlanner) Plan(context.Context) (plan.Plan, error) {
	f.planned_++
	return f.planned, f.planErr
}
func (f *fakePlanner) Desired(context.Context, config.Domain) ([]dns.Record, error) {
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

// Static assets must sit behind the same guard as the API: an attacker who
// merely wants to fingerprint that mailctl ui is running should not be able to
// read the bundle without the token.
func TestStaticAssetsRequireAuthentication(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for an unauthenticated request to /, want 403", rec.Code)
	}
}

// The positive counterpart to TestStaticAssetsRequireAuthentication: a
// correctly authenticated request must still reach the static handler and get
// the real app shell, not merely a non-403 status that a black-hole middleware
// would also produce.
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

// handlePlan and handleAudit are 501 stubs pending Task 8's real bodies, but
// the routes themselves — POST /api/plan and POST /api/audit — are this
// task's wiring, and Task 8 needs a red test if it moves either handler off
// its method or out from behind the auth wrapper. Each stub is pinned in
// both directions: authenticated reaches the stub (501), unauthenticated
// never does (403).

func TestPlanStubIsReachableOnceAuthenticated(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodPost, "/api/plan"))

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d for authenticated POST /api/plan, want 501", rec.Code)
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

func TestAuditStubIsReachableOnceAuthenticated(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodPost, "/api/audit"))

	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d for authenticated POST /api/audit, want 501", rec.Code)
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
