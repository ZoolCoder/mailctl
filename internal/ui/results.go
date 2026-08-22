package ui

// results is the page's memory of what it last saw. mailctl has no state
// file — the live provider APIs are the state — so this lives in the process
// and dies with it. It exists so a dashboard can say "last plan: 3 creates"
// without spending a provider call on every page load.

import (
	"sync"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// planRun is one Plan, over every domain or one.
type planRun struct {
	At      time.Time
	Scope   string // "" for every domain, else the domain name
	Actions []plan.Action
	Err     error
}

// forDomain narrows a run to one domain's actions.
func (p *planRun) forDomain(name string) []plan.Action {
	var out []plan.Action
	for _, a := range p.Actions {
		if a.Domain == name {
			out = append(out, a)
		}
	}
	return out
}

// domainReport is one domain's audit. A domain whose desired records cannot
// be computed reports its own error rather than blanking every other one.
type domainReport struct {
	At     time.Time
	Domain string
	Report audit.Report
	Err    error
}

// OK is true only for a report that ran and passed every check.
func (d domainReport) OK() bool { return d.Err == nil && d.Report.OK() }

// auditRun is one Audit, over every domain or one.
type auditRun struct {
	At      time.Time
	Scope   string
	Reports []domainReport
}

// desiredRun is one Desired for one domain.
type desiredRun struct {
	At      time.Time
	Records []dns.Record
	Err     error
}

type results struct {
	mu          sync.Mutex
	plan        *planRun
	audit       *auditRun
	domainPlan  map[string]*planRun      // latest run that covered the domain
	domainAudit map[string]*domainReport // latest report for the domain
	desired     map[string]*desiredRun
}

func newResults() *results {
	return &results{domainPlan: map[string]*planRun{}, domainAudit: map[string]*domainReport{}, desired: map[string]*desiredRun{}}
}

// setPlan records a run; covered names the domains it planned.
func (r *results) setPlan(run *planRun, covered []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plan = run
	for _, name := range covered {
		r.domainPlan[name] = run
	}
}

func (r *results) setAudit(run *auditRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.audit = run
	for i := range run.Reports {
		rep := run.Reports[i]
		r.domainAudit[rep.Domain] = &rep
	}
}

func (r *results) setDesired(name string, run *desiredRun) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.desired[name] = run
}

func (r *results) lastPlan() *planRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.plan
}

func (r *results) lastAudit() *auditRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.audit
}

func (r *results) planFor(name string) *planRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.domainPlan[name]
}

func (r *results) auditFor(name string) *domainReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.domainAudit[name]
}

func (r *results) desiredFor(name string) *desiredRun {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.desired[name]
}
