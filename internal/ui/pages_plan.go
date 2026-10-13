package ui

// Plan: run the engine's Plan and show the action list, grouped by domain.
// Read-only on purpose — there is no apply here. The CLI applies, with its
// confirmation prompts and -prune gates; a button would have to re-grow all
// of that or skip it, and skipping it is how mail gets deleted.

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/plan"

	"github.com/zoolcoder/toolshell"
)

// opCounts is a plan's shape: how many of each op.
type opCounts struct {
	Create, Update, Delete, Manual, Total int
}

func countOps(actions []plan.Action) opCounts {
	var c opCounts
	for _, a := range actions {
		c.Total++
		switch a.Op {
		case plan.OpCreate:
			c.Create++
		case plan.OpUpdate:
			c.Update++
		case plan.OpDelete:
			c.Delete++
		case plan.OpManual:
			c.Manual++
		}
	}
	return c
}

// planGroup is one domain's slice of a plan.
type planGroup struct {
	Domain  string
	Actions []plan.Action
	Counts  opCounts
}

// planView is a plan run shaped for a template.
type planView struct {
	When   time.Time
	Scope  string
	Err    string
	Counts opCounts
	Groups []planGroup
}

func (s *Server) planView(run *planRun, only string) *planView {
	if run == nil {
		return nil
	}
	actions := run.Actions
	if only != "" {
		actions = run.forDomain(only)
	}
	v := &planView{When: run.At, Scope: run.Scope, Counts: countOps(actions)}
	if run.Err != nil {
		v.Err = run.Err.Error()
	}
	byDomain := map[string][]plan.Action{}
	for _, a := range actions {
		byDomain[a.Domain] = append(byDomain[a.Domain], a)
	}
	names := make([]string, 0, len(byDomain))
	for name := range byDomain {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v.Groups = append(v.Groups, planGroup{Domain: name, Actions: byDomain[name], Counts: countOps(byDomain[name])})
	}
	return v
}

type planPage struct {
	chrome
	Plan    *planView
	Domains []string
	// Apply is the terminal command that applies what this page shows.
	Apply string
}

// applyCommand is what to run in a terminal for a plan over scope ("" for
// every domain). Deletions are left to the user: they need -prune, which
// this page never suggests.
func applyCommand(configPath, scope string) string {
	cmd := "mailctl apply"
	if configPath != "" {
		cmd += " -config " + shellQuote(configPath)
	}
	if scope != "" {
		cmd += " -domain " + shellQuote(scope)
	}
	return cmd
}

// shellQuote leaves a plain path alone and single-quotes anything else.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./~") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (s *Server) planPage(w http.ResponseWriter, r *http.Request) {
	p := planPage{chrome: s.chrome(r, "plan"), Plan: s.planView(s.results.lastPlan(), "")}
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, d := range domains {
		p.Domains = append(p.Domains, d.Name)
	}
	if p.Plan != nil {
		p.Apply = applyCommand(s.deps.ConfigPath, p.Plan.Scope)
	}
	s.render(w, "plan.html", p)
}

// runPlan is a POST because planning reads live provider state: a GET is
// what a prefetch or an address-bar visit issues, and neither should spend a
// provider call or a rate-limit token. A domain field narrows the run.
func (s *Server) runPlan(w http.ResponseWriter, r *http.Request) {
	scope := r.FormValue("domain")
	run := &planRun{At: s.deps.Now(), Scope: scope}
	var covered []string
	var built plan.Plan
	var err error
	if scope == "" {
		var domains []string
		if all, derr := s.deps.Planner.Domains(); derr == nil {
			for _, d := range all {
				domains = append(domains, d.Name)
			}
		}
		covered = domains
		built, err = s.deps.Planner.Plan(r.Context())
	} else {
		d, derr := s.domain(scope)
		if derr != nil {
			toolshell.Back(w, r, "/plan", "", errors.New(s.shell.T(r, "domain %s is not in the config", scope)))
			return
		}
		covered = []string{d.Name}
		if dp, ok := s.deps.Planner.(DomainPlanner); ok {
			built, err = dp.PlanDomain(r.Context(), d)
		} else {
			// No narrower run available: plan everything and keep this
			// domain's share. It costs the same provider calls a full plan
			// does, which the page says on the button.
			built, err = s.deps.Planner.Plan(r.Context())
			built.Actions = (&planRun{Actions: built.Actions}).forDomain(d.Name)
		}
	}
	run.Actions, run.Err = built.Actions, err
	s.results.setPlan(run, covered)

	target := scope
	if err != nil {
		s.log("plan", target, "plan failed: "+err.Error(), false)
		toolshell.Back(w, r, "/plan", "", errors.New(s.shell.T(r, "plan failed: %s", err.Error())))
		return
	}
	c := countOps(built.Actions)
	s.log("plan", target, planSummary(english{}, c), true)
	toolshell.Back(w, r, "/plan", planSummary(tr{s.shell, r}, c), nil)
}

// planSummary is the one-line outcome for the flash and the activity log.
func planSummary(t translator, c opCounts) string {
	if c.Total == 0 {
		return t.T("no changes — the live configuration already matches the config file")
	}
	s := t.T("%d actions: %d create, %d update, %d delete", c.Total, c.Create, c.Update, c.Delete)
	if c.Manual > 0 {
		s += t.T(", %d need a human", c.Manual)
	}
	return s
}
