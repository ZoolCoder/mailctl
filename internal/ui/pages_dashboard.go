package ui

// Dashboard: "what is the state of my mail?" — the config at a glance, the
// last plan and audit this process ran, and the two buttons that run them.

import (
	"net/http"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
)

type domainCard struct {
	Name      string
	Zone      string
	Providers []string
	Mailboxes int
	Aliases   int
	CatchAll  bool
	Plan      *planView
	Audit     *auditDomainView
	// Health is ok, warn, bad or unknown; HealthText says why.
	Health     string
	HealthText string
}

type dashboardPage struct {
	chrome
	ConfigPath string
	Domains    []domainCard
	Providers  []string
	Mailboxes  int
	Aliases    int
	Plan       *planView
	Audit      *auditView
	Activity   []activityRow
	Healthy    int
	Issues     int
	Next       nextStep
	// Pending and Failing split Issues; Unchecked counts domains nothing
	// has looked at yet.
	Pending, Failing, Unchecked int
	// PerDomain series feed the summary cards' bar charts.
	MailboxSeries, AliasSeries []int
	// Runs is the activity of the last fortnight, a column a day.
	Runs runChart
	// ProviderMix is how many domains use each provider, for the donut.
	ProviderMix shares
}

// share is one slice of a donut: what it counts, its tone, how many.
type share struct {
	Name, Tone string
	N          int
}

// shares feed one donut and its legend.
type shares []share

// Tones and Values are the donut's arguments.
func (s shares) Tones() string {
	t := make([]string, len(s))
	for i, sh := range s {
		t[i] = sh.Tone
	}
	return strings.Join(t, " ")
}

func (s shares) Values() []int {
	v := make([]int, len(s))
	for i, sh := range s {
		v[i] = sh.N
	}
	return v
}

func (s shares) Total() int {
	n := 0
	for _, sh := range s {
		n += sh.N
	}
	return n
}

// nextStep is the one thing the dashboard suggests doing now. Run, when
// set, is a plan or audit button; otherwise Href links to the page to read.
type nextStep struct {
	Tone, Title, Text string
	Run               *runButton
	Href, Label       string
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	p := dashboardPage{chrome: s.chrome(r, "dashboard"), ConfigPath: s.deps.ConfigPath}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	providers := map[string]int{}
	for _, d := range domains {
		card := s.domainCard(p, d)
		p.Mailboxes += card.Mailboxes
		p.Aliases += card.Aliases
		for _, name := range d.Mail.Providers {
			providers[name]++
		}
		p.Domains = append(p.Domains, card)
		p.MailboxSeries = append(p.MailboxSeries, card.Mailboxes)
		p.AliasSeries = append(p.AliasSeries, card.Aliases)
		switch card.Health {
		case "ok":
			p.Healthy++
		case "warn":
			p.Pending++
		case "bad":
			p.Failing++
		default:
			p.Unchecked++
		}
	}
	for name := range providers {
		p.Providers = append(p.Providers, name)
	}
	sort.Strings(p.Providers)
	for _, name := range p.Providers {
		chip := provider(name)
		p.ProviderMix = append(p.ProviderMix, share{Name: chip.Name, Tone: chip.Tone, N: providers[name]})
	}
	p.Plan = s.planView(s.results.lastPlan(), "")
	p.Audit = s.auditView(s.results.lastAudit())
	p.Issues = p.Pending + p.Failing
	p.Activity = s.recentActivity(6)
	p.Runs = dailyRuns(s.recentActivity(activityLimit), s.deps.Now(), chartDays)
	p.Next = next(p)
	s.render(w, "dashboard.html", p)
}

func (s *Server) domainCard(t translator, d config.Domain) domainCard {
	card := domainCard{Name: d.Name, Zone: d.ZoneName, Providers: d.Mail.Providers,
		Mailboxes: len(d.Mailboxes), Aliases: len(d.Aliases), CatchAll: d.CatchAll != nil}
	card.Plan = s.planView(s.results.planFor(d.Name), d.Name)
	card.Audit = s.auditDomainView(s.results.auditFor(d.Name))
	card.Health, card.HealthText = health(t, card.Plan, card.Audit)
	return card
}

// health folds a domain's last plan and audit into one verdict: an error or
// a failing check is bad, pending changes need a look, and a domain is only
// healthy once something has checked it.
func health(t translator, p *planView, a *auditDomainView) (string, string) {
	switch {
	case a != nil && a.Err != "", p != nil && p.Err != "":
		return "bad", t.T("error")
	case a != nil && a.Fail > 0:
		return "bad", plural(t, a.Fail, "failing check")
	case p != nil && p.Counts.Total > 0:
		return "warn", plural(t, p.Counts.Total, "pending change")
	case a != nil:
		return "ok", t.T("healthy")
	case p != nil:
		return "ok", t.T("converged")
	}
	return "unknown", t.T("not checked")
}

// HealthTone colours the dashboard's health ring: red when a domain fails,
// amber when one has pending changes, none until something was checked.
func (p dashboardPage) HealthTone() string {
	switch {
	case p.Failing > 0:
		return "bad"
	case p.Pending > 0:
		return "warn"
	case p.Healthy == 0:
		return "none"
	}
	return "ok"
}

// HealthPct is the share of domains that are healthy.
func (p dashboardPage) HealthPct() int {
	if len(p.Domains) == 0 {
		return 0
	}
	return p.Healthy * 100 / len(p.Domains)
}

// plural counts noun in the page's language. The catalog keys are the
// English forms, "1 change" and "%d changes".
func plural(t translator, n int, noun string) string {
	if n == 1 {
		// The key is text, not a format; the empty spread tells vet so.
		return t.T("1 "+noun, []any{}...)
	}
	return t.T("%d "+noun+"s", n)
}

// next picks the dashboard's suggestion: plan first, then review, then
// audit, then fix — the order an operator would work through it.
func next(p dashboardPage) nextStep {
	plan, audit, t := p.Plan, p.Audit, p.chrome
	switch {
	case len(p.Domains) == 0:
		return nextStep{Tone: "warn", Title: t.T("Declare a domain"), Text: t.T("The config declares no domains. Add one to %s and restart mailctl ui.", p.ConfigPath)}
	case plan == nil:
		b := run(t, "plan", "/plan", "", true)
		return nextStep{Title: t.T("Run a plan"), Text: t.T("See what mailctl apply would change. It reads live provider state and changes nothing."), Run: &b}
	case plan.Err != "":
		return nextStep{Tone: "bad", Title: t.T("The last plan failed"), Text: plan.Err, Href: "/plan", Label: t.T("Open plan")}
	case plan.Counts.Total > 0:
		return nextStep{Tone: "warn", Title: t.T("Review %s", plural(t, plan.Counts.Total, "change")), Text: t.T("Read the plan, then apply it from a terminal with the command at its foot."), Href: "/plan", Label: t.T("Review plan")}
	case audit == nil:
		b := run(t, "audit", "/audit", "", true)
		return nextStep{Title: t.T("Run an audit"), Text: t.T("The plan is clean. Check that the world sees the records, through a real resolver."), Run: &b}
	case audit.Fail > 0:
		return nextStep{Tone: "bad", Title: t.T("Fix %s", plural(t, audit.Fail, "failing domain")), Text: t.T("Each failing check shows the value the config wants."), Href: "/audit", Label: t.T("Open audit")}
	}
	b := run(t, "audit", "/", "", false)
	return nextStep{Tone: "ok", Title: t.T("Everything matches"), Text: t.T("Live state matches the config and every check passes."), Run: &b}
}
