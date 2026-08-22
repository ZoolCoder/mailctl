// Package ui is mailctl's local admin page: server-rendered on the zcadmin
// shell, one password in front of it, and every provider call made through
// the engine. Duplicating the engine's ordering and safety logic behind an
// HTTP handler is how the two would come to disagree, so the package holds
// no reconciliation logic of its own — it asks the Planner and shows the
// answer.
//
// Files: server.go is the shell (deps, routes, chrome, helpers); results.go
// remembers the last plan and audit for the life of the process; pages_*.go
// are the sections.
package ui

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/zcadmin"
	"github.com/zoolcoder/zcadmin/auth"
)

//go:embed templates/*.html
var templateFS embed.FS

// brand is the wordmark: mail + ctl.
var brand = zcadmin.Brand{Name: "mail", Accent: "ctl"}

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
	// Passwords holds the one password hash. The first visit sets it.
	Passwords auth.PasswordStore
	// Activity records what the page did; nil records nothing.
	Activity *zcadmin.ActivityLog
	// ConfigPath and DataDir are shown on Settings; neither is read here.
	ConfigPath string
	DataDir    string
	// Host is the address the page is served on. When set, a browser must
	// address the page by it or by a loopback name; see hostAllowed. Empty
	// skips the check, which only a test should want.
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
	owner   string
	tmpl    *template.Template
	auth    *zcadmin.Auth
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
	if deps.Passwords == nil {
		return nil, errors.New("ui: Passwords must not be nil")
	}
	if deps.Getenv == nil {
		deps.Getenv = os.Getenv
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	tmpl, err := zcadmin.Templates(templateFS, "templates/*.html", funcs)
	if err != nil {
		return nil, err
	}
	// The owner shown in the sidebar is the first domain: the page is about
	// that operator's mail, and the config has no other name for them.
	owner := "mailctl"
	if domains, err := deps.Planner.Domains(); err == nil && len(domains) > 0 {
		owner = domains[0].Name
	}
	s := &Server{deps: deps, owner: owner, tmpl: tmpl, mux: http.NewServeMux(), results: newResults()}
	s.auth = zcadmin.NewAuth(brand, owner, deps.Passwords, tmpl, deps.Now)
	s.auth.Log = func(detail string, ok bool) { s.log("auth", "", detail, ok) }
	s.auth.Routes(s.mux)
	s.mux.Handle("GET /static/", zcadmin.Static("/static/"))

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
	s.mux.HandleFunc("POST /settings/password", s.settingsPassword)
	return s, nil
}

// funcs are the template helpers beyond zcadmin.Funcs.
var funcs = template.FuncMap{
	"opChip": opChip,
	"join":   strings.Join,
}

// opChip maps a plan op to its chip class. The colours keep their meaning
// from the brand brief: teal creates, amber changes, coral removes, violet
// is a decision a human has to make.
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

// ServeHTTP puts the host check and zcadmin's login guard in front of every
// route. zcadmin refuses cross-origin POSTs; the host check is what stops a
// DNS-rebound page from reaching even the login form.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.deps.Host != "" && !hostAllowed(r.Host, s.deps.Host) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.auth.Guard(s.mux).ServeHTTP(w, r)
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

type chrome = zcadmin.Chrome

func (s *Server) chrome(r *http.Request, active string) chrome {
	n := 0
	if domains, err := s.deps.Planner.Domains(); err == nil {
		n = len(domains)
	}
	nav := []zcadmin.NavItem{
		{Href: "/", Label: "Dashboard", Key: "dashboard", Icon: zcadmin.Icons["grid"]},
		{Href: "/domains", Label: "Domains", Key: "domains", Icon: zcadmin.Icons["globe"], Count: n},
		{Href: "/plan", Label: "Plan", Key: "plan", Icon: zcadmin.Icons["list"]},
		{Href: "/audit", Label: "Audit", Key: "audit", Icon: zcadmin.Icons["check"]},
		{Href: "/activity", Label: "Activity", Key: "activity", Icon: zcadmin.Icons["pulse"]},
		{Href: "/settings", Label: "Settings", Key: "settings", Icon: zcadmin.Icons["gear"]},
	}
	return zcadmin.NewChrome(r, brand, s.owner, nav, active)
}

// --- helpers ---------------------------------------------------------------

func (s *Server) log(kind, target, detail string, ok bool) {
	if s.deps.Activity == nil {
		return
	}
	_ = s.deps.Activity.Append(zcadmin.Activity{At: s.deps.Now(), Kind: kind, Target: target, Detail: detail, OK: ok})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	zcadmin.Render(w, s.tmpl, name, data)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
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

func ago(t, now time.Time) string { return zcadmin.Ago(t, now) }
