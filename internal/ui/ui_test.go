package ui

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/zcadmin"
)

// fakePlanner is the engine seam with no provider behind it.
type fakePlanner struct {
	domains     []config.Domain
	planned     plan.Plan
	planErr     error
	planCalls   int
	domainCalls []string // PlanDomain targets
	// desiredErr maps a domain name to the error Desired should return for it.
	// A domain absent from this map succeeds with one MX record.
	desiredErr map[string]error
}

func (f *fakePlanner) Domains() ([]config.Domain, error) { return f.domains, nil }
func (f *fakePlanner) Plan(context.Context) (plan.Plan, error) {
	f.planCalls++
	return f.planned, f.planErr
}
func (f *fakePlanner) Desired(_ context.Context, d config.Domain) ([]dns.Record, error) {
	if err, ok := f.desiredErr[d.Name]; ok {
		return nil, err
	}
	return []dns.Record{{Type: "MX", Name: d.Name, Content: "mx." + d.Name, Priority: 10, Kind: dns.KindMX}}, nil
}

// scopedPlanner adds PlanDomain, so the page can narrow a run.
type scopedPlanner struct{ *fakePlanner }

func (f scopedPlanner) PlanDomain(_ context.Context, d config.Domain) (plan.Plan, error) {
	f.domainCalls = append(f.domainCalls, d.Name)
	var out plan.Plan
	for _, a := range f.planned.Actions {
		if a.Domain == d.Name {
			out.Add(a)
		}
	}
	return out, f.planErr
}

func fakeAudit(_ context.Context, d config.Domain, desired []dns.Record) audit.Report {
	return audit.Report{Domain: d.Name, Checks: []audit.Check{
		{Name: "MX", Want: desired[0].Content, Got: desired[0].Content, OK: true},
		{Name: "SPF", Want: "v=spf1 -all", Got: "", OK: d.Name == "example.com"},
	}, Notes: []string{"note for " + d.Name}}
}

// memStore keeps the password hash in memory.
type memStore struct{ hash string }

func (m *memStore) PasswordHash() (string, error)  { return m.hash, nil }
func (m *memStore) SetPasswordHash(h string) error { m.hash = h; return nil }

var twoDomains = []config.Domain{
	{Name: "example.com", ZoneName: "example.com", Mail: config.Mail{Providers: []string{"purelymail"}},
		Mailboxes: []config.Mailbox{{Address: "contact@example.com"}},
		Aliases:   []config.Alias{{Match: "hello", To: []string{"contact@example.com"}}}},
	{Name: "example.net", ZoneName: "example.net", Mail: config.Mail{Providers: []string{"cfrouting"}}},
}

var samplePlan = plan.Plan{Actions: []plan.Action{
	{Op: plan.OpCreate, Resource: "dns", Domain: "example.com", Provider: "purelymail", Detail: "MX example.com -> mailserver.purelymail.com"},
	{Op: plan.OpUpdate, Resource: "dns", Domain: "example.com", Provider: "cloudflare", Detail: "TXT example.com SPF merge"},
	{Op: plan.OpDelete, Resource: "mailbox", Domain: "example.net", Provider: "cfrouting", Detail: "delete old@example.net"},
	{Op: plan.OpManual, Resource: "domain", Domain: "example.net", Provider: "ms365", Detail: "verify the domain in the admin centre"},
}}

type harness struct {
	t      *testing.T
	srv    *httptest.Server
	client *http.Client
	store  *memStore
	fake   *fakePlanner
	server *Server
	log    *zcadmin.ActivityLog
}

func newHarness(t *testing.T, p Planner) *harness {
	t.Helper()
	store := &memStore{}
	logPath := filepath.Join(t.TempDir(), "activity.jsonl")
	log := &zcadmin.ActivityLog{Path: logPath}
	handler, err := New(Deps{
		Planner: p, Audit: fakeAudit, Passwords: store, Activity: log,
		ConfigPath: "/etc/mailctl.yaml", DataDir: "/data",
		Getenv: func(k string) string {
			if k == "CLOUDFLARE_API_TOKEN" {
				return "present"
			}
			return ""
		},
		Now: func() time.Time { return time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := handler.(*Server)
	s.auth.Sleep = func(time.Duration) {}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	h := &harness{t: t, srv: srv, client: &http.Client{Jar: jar}, store: store, server: s, log: log}
	if f, ok := p.(*fakePlanner); ok {
		h.fake = f
	}
	return h
}

// reply is what a test needs from a response, body already read and closed.
type reply struct {
	StatusCode int
	Path       string // where the client ended up after redirects
	Location   string // the Location header when redirects were not followed
}

func (h *harness) get(path string) (reply, string) {
	h.t.Helper()
	resp, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return summarise(resp), string(body)
}

func (h *harness) post(path string, form url.Values) (reply, string) {
	h.t.Helper()
	resp, err := h.client.PostForm(h.srv.URL+path, form)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return summarise(resp), string(body)
}

func summarise(resp *http.Response) reply {
	return reply{StatusCode: resp.StatusCode, Path: resp.Request.URL.Path, Location: resp.Header.Get("Location")}
}

// setup sets the first password and leaves the client signed in.
func (h *harness) setup(password string) {
	h.t.Helper()
	resp, body := h.post("/setup", url.Values{"password": {password}, "confirm": {password}})
	if resp.StatusCode != http.StatusOK || strings.Contains(body, "not the password") {
		h.t.Fatalf("setup: status %d, body %.200s", resp.StatusCode, body)
	}
	if h.store.hash == "" {
		h.t.Fatal("setup did not store a password hash")
	}
}

func TestSetupThenDashboardListsDomains(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	h.setup("correct horse battery")

	resp, body := h.get("/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d", resp.StatusCode)
	}
	for _, want := range []string{"example.com", "example.net", "purelymail", "cfrouting", "Run plan", "Run audit", "/etc/mailctl.yaml"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	if !strings.Contains(body, `<b>example.com</b>`) && !strings.Contains(body, "example.com") {
		t.Errorf("owner missing")
	}
	// The first paint must be instant and must not spend a provider call.
	if h.fake.planCalls != 0 {
		t.Errorf("Plan was called %d times serving the dashboard; it must reach no provider", h.fake.planCalls)
	}
}

func TestPlanRendersActionsWithOpChips(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planned: samplePlan})
	h.setup("correct horse battery")

	// Before a run: the empty state, and still no provider call.
	_, body := h.get("/plan")
	if !strings.Contains(body, "Run plan") || h.fake.planCalls != 0 {
		t.Fatalf("GET /plan ran a plan or lacks the button: calls=%d", h.fake.planCalls)
	}

	resp, body := h.post("/plan/run", url.Values{"return_to": {"/plan"}})
	if resp.StatusCode != http.StatusOK || resp.Path != "/plan" {
		t.Fatalf("after run: status %d at %s", resp.StatusCode, resp.Path)
	}
	if h.fake.planCalls != 1 {
		t.Errorf("Plan called %d times, want 1", h.fake.planCalls)
	}
	for _, want := range []string{
		`<span class="chip on">CREATE</span>`,
		`<span class="chip warn">UPDATE</span>`,
		`<span class="chip bad">DELETE</span>`,
		`<span class="chip violet">MANUAL</span>`,
		"MX example.com -&gt; mailserver.purelymail.com",
		"verify the domain in the admin centre",
		`<span class="chip plain">purelymail</span>`,
		"4 actions: 1 create, 1 update, 1 delete, 1 need a human",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("plan page lacks %q", want)
		}
	}
	if strings.Contains(strings.ToLower(body), `action="/apply`) {
		t.Errorf("the plan page must not offer an apply form")
	}
	// Grouped by domain, example.com first.
	if strings.Index(body, `href="/domains/example.com"`) > strings.Index(body, `href="/domains/example.net"`) {
		t.Errorf("groups are not sorted by domain")
	}

	// The dashboard now summarises the run.
	_, body = h.get("/")
	if !strings.Contains(body, "1 create · 1 update · 1 delete · 1 manual") {
		t.Errorf("dashboard lacks the plan summary: %.300s", body)
	}
	// And the activity log recorded it.
	rows, _ := h.log.Recent(10)
	if len(rows) == 0 || rows[0].Kind != "plan" || !rows[0].OK {
		t.Errorf("activity = %+v, want a plan row", rows)
	}
}

func TestPlanFailureIsShownNotSwallowed(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planErr: errors.New("purelymail: 401 unauthorized")})
	h.setup("correct horse battery")
	_, body := h.post("/plan/run", url.Values{"return_to": {"/plan"}})
	if !strings.Contains(body, "purelymail: 401 unauthorized") || !strings.Contains(body, "Plan failed") {
		t.Errorf("failed plan not reported: %.300s", body)
	}
}

func TestScopedPlanUsesDomainPlanner(t *testing.T) {
	fake := &fakePlanner{domains: twoDomains, planned: samplePlan}
	h := newHarness(t, scopedPlanner{fake})
	h.setup("correct horse battery")
	_, body := h.post("/plan/run", url.Values{"domain": {"example.net"}, "return_to": {"/plan"}})
	if fake.planCalls != 0 {
		t.Errorf("a scoped run called the full Plan %d times", fake.planCalls)
	}
	if strings.Contains(body, "MX example.com") || !strings.Contains(body, "delete old@example.net") {
		t.Errorf("scoped plan shows the wrong actions: %.300s", body)
	}
	if !strings.Contains(body, "scoped to <strong>example.net</strong>") {
		t.Errorf("scope not shown")
	}
}

func TestScopedPlanFallsBackToFilteredFullPlan(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planned: samplePlan})
	h.setup("correct horse battery")
	_, body := h.post("/plan/run", url.Values{"domain": {"example.net"}, "return_to": {"/plan"}})
	if h.fake.planCalls != 1 {
		t.Errorf("Plan called %d times, want 1", h.fake.planCalls)
	}
	if strings.Contains(body, "MX example.com") || !strings.Contains(body, "delete old@example.net") {
		t.Errorf("filtered plan shows the wrong actions")
	}
}

func TestAuditRendersPerDomainChecks(t *testing.T) {
	fake := &fakePlanner{domains: twoDomains, desiredErr: map[string]error{}}
	h := newHarness(t, fake)
	h.setup("correct horse battery")

	resp, body := h.post("/audit/run", url.Values{"return_to": {"/audit"}})
	if resp.Path != "/audit" {
		t.Fatalf("landed on %s", resp.Path)
	}
	for _, want := range []string{
		`<a href="/domains/example.com">example.com</a> <span class="chip on">pass</span>`,
		`<a href="/domains/example.net">example.net</a> <span class="chip bad">1 failing</span>`,
		`<span class="chip on">pass</span>`, `<span class="chip bad">fail</span>`,
		"v=spf1 -all", "(none)", "note for example.com",
		"1 domains passed, 1 failed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page lacks %q", want)
		}
	}

	// A domain whose desired records cannot be computed reports its own
	// error and does not blank the others.
	fake.desiredErr["example.net"] = errors.New("cfrouting: boom")
	_, body = h.post("/audit/run", url.Values{"return_to": {"/audit"}})
	if !strings.Contains(body, "cfrouting: boom") || !strings.Contains(body, `<span class="chip bad">error</span>`) {
		t.Errorf("desired error not shown: %.300s", body)
	}
	if !strings.Contains(body, `example.com</a> <span class="chip on">pass</span>`) {
		t.Errorf("the healthy domain vanished")
	}
}

func TestDomainPagesShowConfigAndDesired(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	h.setup("correct horse battery")

	_, body := h.get("/domains")
	if !strings.Contains(body, `href="/domains/example.com"`) || !strings.Contains(body, `href="/domains/example.net"`) {
		t.Errorf("domains list lacks the domains")
	}
	_, body = h.get("/domains/example.com")
	for _, want := range []string{"contact@example.com", "generated on create", ">hello<", "Load desired records"} {
		if !strings.Contains(body, want) {
			t.Errorf("domain page lacks %q", want)
		}
	}
	_, body = h.post("/domains/example.com/desired", url.Values{"return_to": {"/domains/example.com"}})
	if !strings.Contains(body, "mx.example.com") || !strings.Contains(body, "desired records loaded") {
		t.Errorf("desired records not shown: %.300s", body)
	}
	resp, _ := h.get("/domains/nope.example")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown domain status = %d", resp.StatusCode)
	}
}

func TestUnauthenticatedGETRedirectsToLogin(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, path := range []string{"/", "/plan", "/audit", "/domains/example.com", "/settings", "/activity"} {
		resp, _ := h.get(path)
		if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Location, "/login") {
			t.Errorf("GET %s: status %d, location %q; want a redirect to /login", path, resp.StatusCode, resp.Location)
		}
	}
	// A POST without a session must not run anything.
	resp, _ := h.post("/plan/run", nil)
	if resp.StatusCode != http.StatusSeeOther || h.fake.planCalls != 0 {
		t.Errorf("unauthenticated POST /plan/run: status %d, plan calls %d", resp.StatusCode, h.fake.planCalls)
	}
}

func TestWrongPasswordIsRefused(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	h.setup("correct horse battery")

	// A fresh browser.
	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar}
	resp, body := h.post("/login", url.Values{"password": {"wrong"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "not the password") {
		t.Fatalf("wrong password: status %d, body %.200s", resp.StatusCode, body)
	}
	h.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if resp, _ := h.get("/"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("a refused login still got a session: status %d", resp.StatusCode)
	}
	h.client.CheckRedirect = nil
	if resp, _ := h.post("/login", url.Values{"password": {"correct horse battery"}}); resp.Path != "/" {
		t.Errorf("right password landed on %s", resp.Path)
	}
	rows, _ := h.log.Recent(10)
	if len(rows) < 2 || rows[1].Kind != "auth" || rows[1].OK {
		t.Errorf("the refused sign-in was not logged: %+v", rows)
	}
}

func TestSettingsPasswordChange(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	h.setup("correct horse battery")

	_, body := h.get("/settings")
	for _, want := range []string{"/etc/mailctl.yaml", "/data", "CLOUDFLARE_API_TOKEN", `<span class="chip on">set</span>`,
		`PURELYMAIL_API_TOKEN</code><span class="for">purelymail</span></span><span class="chip bad">missing</span>`,
		`MS365_TENANT_ID</code><span class="for">ms365</span></span><span class="chip off">not set</span>`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings lacks %q", want)
		}
	}
	if strings.Contains(body, "present") {
		t.Errorf("settings printed a credential value")
	}

	_, body = h.post("/settings/password", url.Values{"current": {"nope"}, "password": {"new password here"}, "confirm": {"new password here"}, "return_to": {"/settings"}})
	if !strings.Contains(body, "current password is wrong") {
		t.Errorf("wrong current password accepted: %.300s", body)
	}
	before := h.store.hash
	_, body = h.post("/settings/password", url.Values{"current": {"correct horse battery"}, "password": {"new password here"}, "confirm": {"new password here"}, "return_to": {"/settings"}})
	if !strings.Contains(body, "password changed") || h.store.hash == before {
		t.Errorf("password not changed: %.300s", body)
	}

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar}
	if resp, _ := h.post("/login", url.Values{"password": {"new password here"}}); resp.Path != "/" {
		t.Errorf("new password refused; landed on %s", resp.Path)
	}
}

func TestActivityPageListsWhatRan(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planned: samplePlan})
	h.setup("correct horse battery")
	h.post("/plan/run", url.Values{"return_to": {"/"}})
	_, body := h.get("/activity")
	if !strings.Contains(body, "4 actions: 1 create") || !strings.Contains(body, `<span class="chip on plain">auth</span>`) {
		t.Errorf("activity page lacks the rows: %.400s", body)
	}
	_, body = h.get("/activity?kind=auth")
	if strings.Contains(body, "4 actions") {
		t.Errorf("kind filter did not apply")
	}
}

func TestForeignHostIsForbidden(t *testing.T) {
	handler, err := New(Deps{Planner: &fakePlanner{}, Audit: fakeAudit, Passwords: &memStore{}, Host: "127.0.0.1:1234"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{
		"127.0.0.1:1234": http.StatusSeeOther, // the printed address
		"localhost:1234": http.StatusSeeOther, // a loopback name
		"[::1]:1234":     http.StatusSeeOther,
		"evil.example":   http.StatusForbidden, // DNS rebinding sends the foreign name
		"10.0.0.5:1234":  http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: status %d, want %d", host, rec.Code, want)
		}
	}
}

func TestNewValidatesDeps(t *testing.T) {
	if _, err := New(Deps{Audit: fakeAudit, Passwords: &memStore{}}); err == nil {
		t.Error("nil Planner accepted")
	}
	if _, err := New(Deps{Planner: &fakePlanner{}, Passwords: &memStore{}}); err == nil {
		t.Error("nil Audit accepted")
	}
	if _, err := New(Deps{Planner: &fakePlanner{}, Audit: fakeAudit}); err == nil {
		t.Error("nil Passwords accepted")
	}
}
