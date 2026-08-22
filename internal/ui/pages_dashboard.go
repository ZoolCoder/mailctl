package ui

// Dashboard: "what is the state of my mail?" — the config at a glance, the
// last plan and audit this process ran, and the two buttons that run them.

import (
	"net/http"
	"sort"

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
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	p := dashboardPage{chrome: s.chrome(r, "dashboard"), ConfigPath: s.deps.ConfigPath}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		s.fail(w, err)
		return
	}
	providers := map[string]bool{}
	for _, d := range domains {
		card := s.domainCard(d)
		p.Mailboxes += card.Mailboxes
		p.Aliases += card.Aliases
		for _, name := range d.Mail.Providers {
			providers[name] = true
		}
		p.Domains = append(p.Domains, card)
	}
	for name := range providers {
		p.Providers = append(p.Providers, name)
	}
	sort.Strings(p.Providers)
	p.Plan = s.planView(s.results.lastPlan(), "")
	p.Audit = s.auditView(s.results.lastAudit())
	p.Activity = s.recentActivity(8)
	s.render(w, "dashboard.html", p)
}

func (s *Server) domainCard(d config.Domain) domainCard {
	card := domainCard{Name: d.Name, Zone: d.ZoneName, Providers: d.Mail.Providers,
		Mailboxes: len(d.Mailboxes), Aliases: len(d.Aliases), CatchAll: d.CatchAll != nil}
	card.Plan = s.planView(s.results.planFor(d.Name), d.Name)
	card.Audit = s.auditDomainView(s.results.auditFor(d.Name))
	return card
}
