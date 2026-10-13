// Package ui is mailctl's local admin page: server-rendered inside the shared
// toolshell (github.com/zoolcoder/toolshell), reachable from this machine
// only, and every provider call made through the engine. Duplicating the
// engine's ordering and safety logic behind an HTTP handler is how the two
// would come to disagree, so the package holds no reconciliation logic of its
// own — it asks the Planner and shows the answer.
//
// Files: server.go is the shell (deps, routes, chrome, helpers); results.go
// remembers the last plan and audit for the life of the process; pages_*.go
// are the sections.
package ui

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/toolshell"
	"github.com/zoolcoder/toolshell/activity"
)

//go:embed templates/*.html
var assets embed.FS

// activityLimit is how many rows the activity page shows.
const activityLimit = 200

// Planner is the slice of the engine this server needs. It is an interface so
// handler tests need neither a provider nor a network.
type Planner interface {
	Domains() ([]config.Domain, error)
	Plan(ctx context.Context) (plan.Plan, error)
	Desired(ctx context.Context, d config.Domain) ([]dns.Record, error)
}

// DomainPlanner is the optional narrower run: a Planner that can plan one
// domain without reading every other domain's live state. The engine
// implements it; a Planner that does not falls back to a full Plan filtered
// afterwards.
type DomainPlanner interface {
	PlanDomain(ctx context.Context, d config.Domain) (plan.Plan, error)
}

// Auditor runs one domain's audit. Injected so tests do not perform DNS lookups.
type Auditor func(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report

// Deps is everything the page needs from the command that starts it.
type Deps struct {
	Planner Planner
	Audit   Auditor
	// Activity records what the page did; nil records nothing.
	Activity *activity.Log
	// ConfigPath and DataDir are shown on Settings; neither is read here.
	ConfigPath string
	DataDir    string
	// Host is the address the page is served on. When set, a browser must
	// address the page by it or by a loopback name; see hostAllowed. Empty
	// skips the Host check, which only a test should want; the cross-origin
	// check runs either way.
	Host string
	// Getenv answers whether a provider credential is present. nil means
	// os.Getenv. Values are never rendered, only their presence.
	Getenv func(string) string
	// Now is swapped in tests.
	Now func() time.Time
}

// Server is the handler's state.
type Server struct {
	deps    Deps
	shell   *toolshell.Shell
	tmpl    *template.Template
	mux     *http.ServeMux
	results *results
}

// New wires the routes and returns the guarded handler. It validates deps
// itself so a caller-supplied Deps fails with an error, not a crash.
func New(deps Deps) (http.Handler, error) {
	if deps.Planner == nil {
		return nil, errors.New("ui: Planner must not be nil")
	}
	if deps.Audit == nil {
		return nil, errors.New("ui: Audit must not be nil")
	}
	if deps.Getenv == nil {
		deps.Getenv = os.Getenv
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	s := &Server{deps: deps, mux: http.NewServeMux(), results: newResults()}
	s.shell = toolshell.New(toolshell.Config{
		Brand:   toolshell.Brand{Name: "mail", Accent: "ctl", Tagline: "by ZoolCoder"},
		Status:  toolshell.Status{Label: "Local only"},
		Cookie:  "mailctl",
		Palette: s.palette,
		User:    toolshell.User{Name: localUser(), Detail: hostLabel(deps.Host)},
		Menu: []toolshell.NavItem{
			{Href: "/settings", Label: "Settings", Icon: "gear", Hotkey: "s"},
			{Href: "/activity", Label: "Activity", Icon: "pulse", Hotkey: "l"},
		},
		Langs:    []toolshell.Lang{{Code: "en", Name: "English"}, {Code: "ar", Name: "العربية", Dir: "rtl"}},
		Messages: messages,
	})
	tmpl, err := s.shell.Templates(assets, "templates/*.html", s.templateFuncs())
	if err != nil {
		return nil, err
	}
	s.tmpl = tmpl
	s.shell.Mount(s.mux)

	s.mux.HandleFunc("GET /{$}", s.dashboard)
	s.mux.HandleFunc("GET /domains", s.domains)
	s.mux.HandleFunc("GET /domains/{name}", s.domainPage)
	s.mux.HandleFunc("POST /domains/{name}/desired", s.loadDesired)
	s.mux.HandleFunc("GET /plan", s.planPage)
	s.mux.HandleFunc("POST /plan/run", s.runPlan)
	s.mux.HandleFunc("GET /audit", s.auditPage)
	s.mux.HandleFunc("POST /audit/run", s.runAudit)
	s.mux.HandleFunc("GET /activity", s.activity)
	s.mux.HandleFunc("GET /settings", s.settingsPage)
	s.mux.HandleFunc("GET /robots.txt", robots)
	s.mux.HandleFunc("GET /", s.notFound)
	return s, nil
}

// templateFuncs are mailctl's own; the shell adds icon, the charts and the
// text helpers.
func (s *Server) templateFuncs() template.FuncMap {
	return template.FuncMap{"opChip": opChip, "join": strings.Join, "run": run, "provider": provider, "kindIcon": kindIcon, "plural": plural,
		"list":  func(v ...string) []string { return v },
		"lower": strings.ToLower,
		"add":   func(a, b int) int { return a + b },
		"ago":   func(t translator, at time.Time) string { return ago(t, at, s.deps.Now()) },
		"stamp": func(at time.Time) string { return at.Local().Format("2006-01-02 15:04:05") }}
}

// providerChip is how a provider reads on a page: its name and the chip hue
// that tells integrations apart.
type providerChip struct{ Name, Tone string }

func provider(id string) providerChip {
	switch id {
	case "purelymail":
		return providerChip{"Purelymail", "p-blue"}
	case "cfrouting":
		return providerChip{"Cloudflare", "p-amber"}
	case "ms365":
		return providerChip{"Microsoft 365", "p-sky"}
	}
	return providerChip{id, "plain"}
}

// kindIcon picks the glyph for an activity row's kind.
func kindIcon(kind string) string {
	switch kind {
	case "plan":
		return "list"
	case "audit":
		return "check"
	}
	return "globe"
}

// runButton is a form that runs a plan or an audit; see the "run" template.
type runButton struct {
	Action, Kind, Label, Busy, Back, Domain, Title string
	Primary                                        bool
}

// run builds the button for kind "plan" or "audit", scoped to domain when it
// is set, sending the user back to back, in the page's language.
// {{template "run" run $ "plan" "/" "" true}}
func run(t translator, kind, back, domain string, primary bool) runButton {
	b := runButton{Action: "/" + kind + "/run", Kind: kind, Back: back, Domain: domain, Primary: primary}
	if kind == "plan" {
		b.Label, b.Busy, b.Title = t.T("Run plan"), t.T("Planning…"), t.T("reads live provider state; changes nothing")
	} else {
		b.Label, b.Busy, b.Title = t.T("Run audit"), t.T("Auditing…"), t.T("resolves live DNS through a real resolver")
	}
	return b
}

// translator is a page: every page embeds the shell's Chrome, whose T puts
// English text into the page's language.
type translator interface {
	T(text string, args ...any) string
}

// english is the translator for what is not shown to one reader, such as
// the activity log.
type english struct{}

func (english) T(text string, args ...any) string {
	if len(args) == 0 {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// tr is the translator for a request a handler answers without a page.
type tr struct {
	shell *toolshell.Shell
	r     *http.Request
}

func (t tr) T(text string, args ...any) string { return t.shell.T(t.r, text, args...) }

// opChip maps a plan op to its chip class. The colours keep their meaning
// across both themes: green creates, amber changes, red removes, violet is
// a decision a human has to make.
func opChip(op plan.Op) string {
	switch op {
	case plan.OpCreate:
		return "on"
	case plan.OpUpdate:
		return "warn"
	case plan.OpDelete:
		return "bad"
	case plan.OpManual:
		return "violet"
	}
	return "off"
}

// ServeHTTP stands in for a login: the page listens on loopback only, so it
// refuses a Host that is not this page's (DNS rebinding) and any write
// another site starts (CSRF).
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.deps.Host != "" && !hostAllowed(r.Host, s.deps.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && crossSite(r) {
		http.Error(w, "cross-origin request refused", http.StatusForbidden)
		return
	}
	toolshell.SetHeaders(w.Header())
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	// Handlers read fields with FormValue, which drops a parse error; parse
	// here so a body over the cap is refused instead of read as empty.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusRequestEntityTooLarge)
			return
		}
	}
	s.mux.ServeHTTP(w, r)
}

// maxBody caps a request body; every form here is a button with at most a
// return path.
const maxBody = 16 << 10

// crossSite reports whether another site started the request. Browsers send
// Sec-Fetch-Site on every request, and it wins when present: under a strict
// referrer policy a same-origin form still sends Origin: null. same-site is
// refused too, since another port on this machine is the same site. Without
// it, an Origin naming a foreign host is enough to refuse.
func crossSite(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site != "same-origin" && site != "none"
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err != nil || u.Host != r.Host
}

// hostAllowed reports whether a browser addressed this page by a name that
// cannot be an attacker's. DNS rebinding lets an attacker-controlled name
// resolve to 127.0.0.1, and in that attack the browser still sends the
// foreign Host it was told to use — so the Host must be the address the
// server was started on, or a loopback literal, which no public DNS name can
// be. It is not meant to stop a local process that forges Host; that process
// already has the port.
func hostAllowed(host, expected string) bool {
	if host == expected {
		return true
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if strings.EqualFold(name, "localhost") {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// --- shared page chrome ----------------------------------------------------

// chrome is the shared shell data; pages embed it.
type chrome = toolshell.Chrome

func (s *Server) chrome(r *http.Request, active string) chrome {
	n := 0
	if domains, err := s.deps.Planner.Domains(); err == nil {
		n = len(domains)
	}
	c := s.shell.Chrome(r, active, []toolshell.NavGroup{
		{Items: []toolshell.NavItem{
			{Href: "/", Label: "Dashboard", Key: "dashboard", Icon: "grid", Hotkey: "h"},
		}},
		{Title: "Mail estate", Items: []toolshell.NavItem{
			{Href: "/domains", Label: "Domains", Key: "domains", Icon: "globe", Count: n, Hotkey: "d"},
			{Href: "/plan", Label: "Plan", Key: "plan", Icon: "list", Hotkey: "p"},
			{Href: "/audit", Label: "Audit", Key: "audit", Icon: "check", Hotkey: "a"},
		}},
		{Title: "System", Items: []toolshell.NavItem{
			{Href: "/activity", Label: "Activity", Key: "activity", Icon: "pulse", Hotkey: "l"},
			{Href: "/settings", Label: "Settings", Key: "settings", Icon: "gear", Hotkey: "s"},
		}},
	})
	c.Status.Detail = hostLabel(s.deps.Host) + " · " + c.T("no login")
	c.Footer = c.TH("mailctl · this page reads and plans; %s in a terminal changes things", template.HTML("<code>mailctl apply</code>"))
	return c
}

// palette adds the run buttons and every domain to the Ctrl-K list; the
// pages come from the sidebar.
func (s *Server) palette(r *http.Request) []toolshell.PaletteItem {
	t := tr{s.shell, r}
	items := []toolshell.PaletteItem{
		{Label: t.T("Run plan"), Hint: t.T("reads live provider state; changes nothing"), Post: "/plan/run", Fields: map[string]string{"return_to": "/plan"}},
		{Label: t.T("Run audit"), Hint: t.T("resolves live DNS through a real resolver"), Post: "/audit/run", Fields: map[string]string{"return_to": "/audit"}},
	}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		return items
	}
	for _, d := range domains {
		items = append(items, toolshell.PaletteItem{Label: d.Name, Hint: t.T("Domain · zone %s", d.ZoneName), Href: "/domains/" + d.Name})
	}
	return items
}

// localUser names who runs the page, for the profile menu; the page has no
// login, so the account is the machine's.
func localUser() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

// hostLabel is the address shown at the foot of the sidebar.
func hostLabel(host string) string {
	if host == "" {
		return "loopback"
	}
	return host
}

// --- helpers ---------------------------------------------------------------

func (s *Server) log(kind, target, detail string, ok bool) {
	if s.deps.Activity == nil {
		return
	}
	_ = s.deps.Activity.Append(activity.Entry{At: s.deps.Now(), Kind: kind, Target: target, Detail: detail, OK: ok})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	toolshell.Render(w, s.tmpl, http.StatusOK, name, data)
}

// fail answers with the shell's error page. The detail is the error itself:
// the engine's errors are the ones the CLI prints, and none carries a secret.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	c := s.chrome(r, "")
	s.errorPage(w, toolshell.ErrorPage{Chrome: c, Code: http.StatusInternalServerError, Heading: c.T("This page failed"), Detail: err.Error()})
}

// notFound answers any address the page does not serve, and a domain the
// config does not declare.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	c := s.chrome(r, "")
	s.errorPage(w, toolshell.ErrorPage{Chrome: c, Code: http.StatusNotFound, Heading: c.T("Page not found"), Detail: c.T("Nothing lives at this address.")})
}

func (s *Server) errorPage(w http.ResponseWriter, p toolshell.ErrorPage) {
	p.Title = p.Heading
	toolshell.Render(w, s.tmpl, p.Code, "ts-error", p)
}

// domain finds one configured domain by name.
func (s *Server) domain(name string) (config.Domain, error) {
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		return config.Domain{}, err
	}
	for _, d := range domains {
		if strings.EqualFold(d.Name, name) {
			return d, nil
		}
	}
	return config.Domain{}, errors.New("domain " + name + " is not in the config")
}

// ago says how long before now t was, in the page's language.
func ago(t translator, at, now time.Time) string {
	if at.IsZero() {
		return "—"
	}
	d := now.Sub(at)
	switch {
	case d < time.Minute:
		return t.T("just now")
	case d < time.Hour:
		return t.T("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return t.T("%dh ago", int(d.Hours()))
	case d < 60*24*time.Hour:
		return t.T("%dd ago", int(d.Hours()/24))
	}
	return at.Local().Format("2006-01-02")
}

// robots answers crawlers that somehow reach a loopback page.
func robots(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}
