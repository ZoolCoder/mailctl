package ui

// Audit: ask the resolver whether the world can see what the config wants,
// one domain at a time, and show every check with a pass/fail chip.

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/zcadmin"
)

// auditDomainView is one domain's report shaped for a template.
type auditDomainView struct {
	Domain string
	When   time.Time
	OK     bool
	Err    string
	Pass   int
	Fail   int
	Report domainReportBody
}

// domainReportBody is the audit.Report fields a template reads.
type domainReportBody struct {
	Checks []auditCheck
	Notes  []string
}

type auditCheck struct {
	Name, Want, Got string
	OK              bool
}

func (s *Server) auditDomainView(rep *domainReport) *auditDomainView {
	if rep == nil {
		return nil
	}
	v := &auditDomainView{Domain: rep.Domain, When: rep.At, OK: rep.OK()}
	if rep.Err != nil {
		v.Err = rep.Err.Error()
		return v
	}
	for _, c := range rep.Report.Checks {
		v.Report.Checks = append(v.Report.Checks, auditCheck{Name: c.Name, Want: orNone(c.Want), Got: orNone(c.Got), OK: c.OK})
		if c.OK {
			v.Pass++
		} else {
			v.Fail++
		}
	}
	v.Report.Notes = rep.Report.Notes
	return v
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// auditView is one audit run shaped for a template.
type auditView struct {
	When    time.Time
	Scope   string
	Pass    int // domains that passed every check
	Fail    int // domains with a failing check or an error
	Domains []*auditDomainView
}

func (s *Server) auditView(run *auditRun) *auditView {
	if run == nil {
		return nil
	}
	v := &auditView{When: run.At, Scope: run.Scope}
	for i := range run.Reports {
		dv := s.auditDomainView(&run.Reports[i])
		if dv.OK {
			v.Pass++
		} else {
			v.Fail++
		}
		v.Domains = append(v.Domains, dv)
	}
	return v
}

type auditPage struct {
	chrome
	Audit   *auditView
	Domains []string
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	p := auditPage{chrome: s.chrome(r, "audit"), Audit: s.auditView(s.results.lastAudit())}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, d := range domains {
		p.Domains = append(p.Domains, d.Name)
	}
	s.render(w, "audit.html", p)
}

// runAudit is a POST for the same reason runPlan is: it resolves live DNS
// and asks providers for their desired records. A domain field narrows it.
func (s *Server) runAudit(w http.ResponseWriter, r *http.Request) {
	scope := r.FormValue("domain")
	var domains []config.Domain
	if scope == "" {
		all, err := s.deps.Planner.Domains()
		if err != nil {
			zcadmin.Back(w, r, "/audit", "", err)
			return
		}
		domains = all
	} else {
		d, err := s.domain(scope)
		if err != nil {
			zcadmin.Back(w, r, "/audit", "", errors.New(s.shell.T(r, "domain %s is not in the config", scope)))
			return
		}
		domains = []config.Domain{d}
	}

	now := s.deps.Now()
	run := &auditRun{At: now, Scope: scope}
	for _, d := range domains {
		desired, err := s.deps.Planner.Desired(r.Context(), d)
		s.results.setDesired(d.Name, &desiredRun{At: now, Records: desired, Err: err})
		if err != nil {
			run.Reports = append(run.Reports, domainReport{At: now, Domain: d.Name, Err: err})
			continue
		}
		run.Reports = append(run.Reports, domainReport{At: now, Domain: d.Name, Report: s.deps.Audit(r.Context(), d, desired)})
	}
	s.results.setAudit(run)

	v := s.auditView(run)
	s.log("audit", scope, fmt.Sprintf("%d domains passed, %d failed", v.Pass, v.Fail), v.Fail == 0)
	flash := s.shell.T(r, "audit: %d domains passed, %d failed", v.Pass, v.Fail)
	if v.Fail > 0 {
		zcadmin.Back(w, r, "/audit", "", errors.New(flash))
		return
	}
	zcadmin.Back(w, r, "/audit", flash, nil)
}

// desiredView is one domain's desired DNS shaped for a template.
type desiredView struct {
	When    time.Time
	Err     string
	Records []dns.Record
}

func (s *Server) desiredView(run *desiredRun) *desiredView {
	if run == nil {
		return nil
	}
	v := &desiredView{When: run.At, Records: run.Records}
	if run.Err != nil {
		v.Err = run.Err.Error()
	}
	return v
}
