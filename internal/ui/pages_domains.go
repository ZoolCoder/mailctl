package ui

// Domains: what the config declares for each domain, and the DNS records the
// engine wants published for it. The config part renders from memory; the
// desired records come from the providers, so they load on request.

import (
	"net/http"

	"github.com/zoolcoder/zcadmin"
)

type domainsPage struct {
	chrome
	Domains []domainCard
}

func (s *Server) domains(w http.ResponseWriter, r *http.Request) {
	p := domainsPage{chrome: s.chrome(r, "domains")}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, d := range domains {
		p.Domains = append(p.Domains, s.domainCard(d))
	}
	s.render(w, "domains.html", p)
}

// credentialFor names the environment variable a mailbox's password comes
// from, or says the engine generates one.
type mailboxRow struct {
	Address     string
	Credential  string
	DisplayName string
	Recovery    int
}

type domainPage struct {
	chrome
	Card       domainCard
	Mailboxes  []mailboxRow
	Aliases    []aliasRow
	CatchAllTo []string
	Settings   []kv
	Policy     []kv
	Desired    *desiredView
	// Scoped says whether "Run plan" here plans only this domain.
	Scoped bool
}

type aliasRow struct {
	Match string
	To    []string
}

type kv struct{ K, V string }

func (s *Server) domainPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.domain(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, scoped := s.deps.Planner.(DomainPlanner)
	p := domainPage{chrome: s.chrome(r, "domains"), Card: s.domainCard(d), Desired: s.desiredView(s.results.desiredFor(d.Name)), Scoped: scoped}
	for _, m := range d.Mailboxes {
		row := mailboxRow{Address: m.Address, Credential: "generated on create", DisplayName: m.DisplayName, Recovery: len(m.Recovery)}
		if m.PasswordEnv != "" {
			row.Credential = "$" + m.PasswordEnv
		}
		p.Mailboxes = append(p.Mailboxes, row)
	}
	for _, a := range d.Aliases {
		p.Aliases = append(p.Aliases, aliasRow{Match: a.Match, To: a.To})
	}
	if d.CatchAll != nil {
		p.CatchAllTo = d.CatchAll.To
	}
	p.Settings = domainSettings(d)
	p.Policy = deliverabilityPolicy(d)
	s.render(w, "domain.html", p)
}

// loadDesired asks the engine for the domain's desired DNS records. A POST
// because providers are consulted to answer it.
func (s *Server) loadDesired(w http.ResponseWriter, r *http.Request) {
	d, err := s.domain(r.PathValue("name"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	back := "/domains/" + d.Name
	records, err := s.deps.Planner.Desired(r.Context(), d)
	s.results.setDesired(d.Name, &desiredRun{At: s.deps.Now(), Records: records, Err: err})
	if err != nil {
		s.log("desired", d.Name, "desired records failed: "+err.Error(), false)
		zcadmin.Back(w, r, back, "", err)
		return
	}
	zcadmin.Back(w, r, back, "desired records loaded", nil)
}
