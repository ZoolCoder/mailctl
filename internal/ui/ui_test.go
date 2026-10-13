package ui

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/toolshell/activity"
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
	fake   *fakePlanner
	server *Server
	log    *activity.Log
}

func newHarness(t *testing.T, p Planner) *harness {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "activity.jsonl")
	log := &activity.Log{Path: logPath}
	handler, err := New(Deps{
		Planner: p, Audit: fakeAudit, Activity: log,
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
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	h := &harness{t: t, srv: srv, client: &http.Client{}, server: s, log: log}
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

func TestDashboardListsDomains(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
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
		`<span class="chip p-blue" data-provider="purelymail">Purelymail</span>`,
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
	_, body := h.post("/plan/run", url.Values{"return_to": {"/plan"}})
	if !strings.Contains(body, "purelymail: 401 unauthorized") || !strings.Contains(body, "Plan failed") {
		t.Errorf("failed plan not reported: %.300s", body)
	}
}

func TestScopedPlanUsesDomainPlanner(t *testing.T) {
	fake := &fakePlanner{domains: twoDomains, planned: samplePlan}
	h := newHarness(t, scopedPlanner{fake})
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
	_, body := h.get("/domains")
	if !strings.Contains(body, `href="/domains/example.com"`) || !strings.Contains(body, `href="/domains/example.net"`) {
		t.Errorf("domains list lacks the domains")
	}
	if !strings.Contains(body, "cfrouting cloudflare") {
		t.Errorf("domain search does not index the provider's display name")
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

func TestCrossSitePostIsRefused(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	for name, header := range map[string][2]string{
		"foreign Origin":     {"Origin", "https://evil.example"},
		"cross-site fetch":   {"Sec-Fetch-Site", "cross-site"},
		"unparseable Origin": {"Origin", "://"},
		"same-site fetch":    {"Sec-Fetch-Site", "same-site"},
	} {
		req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/plan/run", strings.NewReader("return_to=%2Fplan"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(header[0], header[1])
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, resp.StatusCode)
		}
	}
	if h.fake.planCalls != 0 {
		t.Errorf("a refused POST still ran %d plans", h.fake.planCalls)
	}

	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/plan/run", strings.NewReader("return_to=%2Fplan"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", h.srv.URL)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || h.fake.planCalls != 1 {
		t.Errorf("same-origin POST: status %d, plan calls %d", resp.StatusCode, h.fake.planCalls)
	}

	// What Chrome sends for the page's own form when no referrer leaves it.
	req, _ = http.NewRequest(http.MethodPost, h.srv.URL+"/plan/run", strings.NewReader("return_to=%2Fplan"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err = h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || h.fake.planCalls != 2 {
		t.Errorf("same-origin POST with Origin null: status %d, plan calls %d", resp.StatusCode, h.fake.planCalls)
	}
}

func TestNoLoginRoutes(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	for _, path := range []string{"/login", "/setup"} {
		if resp, _ := h.get(path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", path, resp.StatusCode)
		}
	}
}

func TestSettingsShowsPresenceOnly(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
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
	if strings.Contains(body, `action="/settings/`) {
		t.Errorf("settings still has a form")
	}
}

func TestActivityPageListsWhatRan(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planned: samplePlan})
	h.post("/plan/run", url.Values{"return_to": {"/"}})
	_, body := h.get("/activity")
	if !strings.Contains(body, "4 actions: 1 create") || !strings.Contains(body, `<span class="chip on plain">plan</span>`) {
		t.Errorf("activity page lacks the rows: %.400s", body)
	}
	_, body = h.get("/activity?kind=audit")
	if strings.Contains(body, "4 actions") {
		t.Errorf("kind filter did not apply")
	}
}

func TestForeignHostIsForbidden(t *testing.T) {
	handler, err := New(Deps{Planner: &fakePlanner{}, Audit: fakeAudit, Host: "127.0.0.1:1234"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]int{
		"127.0.0.1:1234": http.StatusOK, // the printed address
		"localhost:1234": http.StatusOK, // a loopback name
		"[::1]:1234":     http.StatusOK,
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
	if _, err := New(Deps{Audit: fakeAudit}); err == nil {
		t.Error("nil Planner accepted")
	}
	if _, err := New(Deps{Planner: &fakePlanner{}}); err == nil {
		t.Error("nil Audit accepted")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	resp, err := h.client.Get(h.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	for name, want := range map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "same-origin",
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "frame-ancestors 'none'",
	} {
		if got := resp.Header.Get(name); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", name, got, want)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "https:") {
		t.Errorf("CSP %q allows inline code or another origin", csp)
	}
}

func TestThemeIsACookieTheShellReads(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	_, body := h.get("/")
	if !strings.Contains(body, `data-theme="auto"`) {
		t.Error("the default theme should follow the OS")
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(h.srv.URL + "/theme?set=dark&back=/plan")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/plan" {
		t.Errorf("redirect to %q, want /plan", loc)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "mailctl-theme" {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value != "dark" {
		t.Fatalf("theme cookie = %v, want dark", cookie)
	}
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/", nil)
	req.AddCookie(cookie)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(page), `data-theme="dark"`) {
		t.Error("the shell should render the cookie's theme")
	}

	resp, err = client.Get(h.srv.URL + "/theme?set=dark&back=//evil.example")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Errorf("off-site back went to %q, want /", loc)
	}
}

func TestPlanShowsTheApplyCommand(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains, planned: samplePlan})
	h.post("/plan/run", url.Values{"return_to": {"/plan"}})
	_, body := h.get("/plan")
	if !strings.Contains(body, "mailctl apply -config /etc/mailctl.yaml</code>") {
		t.Error("the plan page should show the command that applies it")
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	body := "return_to=" + strings.Repeat("a", 32<<10)
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/plan/run", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", resp.StatusCode)
	}
	if h.fake.planCalls != 0 {
		t.Errorf("an oversized POST still ran %d plans", h.fake.planCalls)
	}
}

func TestPaletteOffersRunsAndDomains(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	_, body := h.get("/_ts/palette.json")
	for _, want := range []string{`"label":"Run plan"`, `"post":"/plan/run"`, `"label":"Run audit"`, `"href":"/domains/` + twoDomains[0].Name + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("palette lacks %s: %s", want, body)
		}
	}
}

// TestArabicCoversEveryTemplateString keeps the catalog in step with the
// templates: every literal a template translates has an Arabic entry.
func TestArabicCoversEveryTemplateString(t *testing.T) {
	keys := regexp.MustCompile(`\.TH? "((?:[^"\\]|\\.)*)"`)
	nouns := regexp.MustCompile(`plural \$ (?:\([^)]*\)|\S+) "([^"]+)"`)
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		b, err := fs.ReadFile(assets, name)
		if err != nil {
			t.Fatal(err)
		}
		var want []string
		for _, m := range keys.FindAllStringSubmatch(string(b), -1) {
			want = append(want, m[1])
		}
		for _, m := range nouns.FindAllStringSubmatch(string(b), -1) {
			want = append(want, "1 "+m[1], "%d "+m[1]+"s")
		}
		for _, k := range want {
			if _, ok := messages["ar"][k]; !ok {
				t.Errorf("%s: no Arabic for %q", name, k)
			}
		}
	}
}

func TestUnknownPagesGetTheStyledNotFound(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	for _, path := range []string{"/nope", "/domains/nope.example"} {
		resp, body := h.get(path)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, `class="errpage"`) || !strings.Contains(body, "Page not found") {
			t.Errorf("GET %s: status %d, want the shell's 404 page: %.200s", path, resp.StatusCode, body)
		}
	}
}

// brokenPlanner cannot read its config.
type brokenPlanner struct{ fakePlanner }

func (brokenPlanner) Domains() ([]config.Domain, error) {
	return nil, errors.New("mailctl.yaml: line 3: bad indent")
}

func TestABrokenConfigGetsTheStyledError(t *testing.T) {
	h := newHarness(t, &brokenPlanner{})
	resp, body := h.get("/domains")
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, `class="errpage"`) || !strings.Contains(body, "line 3: bad indent") {
		t.Errorf("status %d, want the shell's 500 page naming the error: %.300s", resp.StatusCode, body)
	}
}

func TestArabicTurnsThePagesAndFlashesRightToLeft(t *testing.T) {
	h := newHarness(t, &fakePlanner{domains: twoDomains})
	get := func(path string) string {
		req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: "mailctl-lang", Value: "ar"})
		resp, err := h.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	body := get("/")
	for _, want := range []string{`dir="rtl"`, "لوحة التحكم", "شغّل الخطة", "النطاقات"} {
		if !strings.Contains(body, want) {
			t.Errorf("Arabic dashboard lacks %q", want)
		}
	}

	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/plan/run", strings.NewReader("return_to=/plan"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "mailctl-lang", Value: "ar"})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if msg := loc.Query().Get("msg"); !strings.Contains(msg, "لا تغييرات") {
		t.Errorf("flash = %q, want it in Arabic", msg)
	}
	acts, _ := h.log.Recent(1)
	if len(acts) != 1 || !strings.HasPrefix(acts[0].Detail, "no changes") {
		t.Errorf("the activity log should stay in English: %+v", acts)
	}
}
