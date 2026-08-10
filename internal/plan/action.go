// Package plan holds the ordered list of changes mailctl intends to make.
package plan

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
)

type Op string

const (
	OpCreate Op = "CREATE"
	OpUpdate Op = "UPDATE"
	OpDelete Op = "DELETE"
	// OpManual is a change a human must complete outside mailctl. It renders in
	// the plan but is never executed, so a converged plan that still lists a
	// manual action is not a failure to converge.
	OpManual Op = "MANUAL"
)

// Action is one intended change. Do performs it and must be idempotent: a rerun
// after a partial apply has to be safe. Do is nil exactly when Op is OpManual.
type Action struct {
	Op       Op
	Resource string // dns, domain, mailbox, alias, catchall, recovery, worker, destination
	Domain   string
	Provider string
	Detail   string
	Do       func(context.Context) error
}

type Plan struct {
	Actions []Action
}

func (p *Plan) Add(actions ...Action) {
	p.Actions = append(p.Actions, actions...)
}

func (p *Plan) Extend(other Plan) {
	p.Actions = append(p.Actions, other.Actions...)
}

func (p Plan) Empty() bool { return len(p.Actions) == 0 }

// Executable returns the actions apply should run, in order.
func (p Plan) Executable() []Action {
	out := make([]Action, 0, len(p.Actions))
	for _, a := range p.Actions {
		if a.Op != OpManual && a.Do != nil {
			out = append(out, a)
		}
	}
	return out
}

// Destructive returns every action that removes something. The apply path uses
// this to build the -prune confirmation prompt.
func (p Plan) Destructive() []Action {
	out := make([]Action, 0)
	for _, a := range p.Actions {
		if a.Op == OpDelete {
			out = append(out, a)
		}
	}
	return out
}

// Render writes a human-readable plan grouped by domain. Detail strings must
// never contain secrets; callers are responsible for that.
func (p Plan) Render(w io.Writer) {
	if p.Empty() {
		fmt.Fprintln(w, "No changes. The live configuration already matches the config file.")
		return
	}

	byDomain := map[string][]Action{}
	for _, a := range p.Actions {
		byDomain[a.Domain] = append(byDomain[a.Domain], a)
	}

	names := make([]string, 0, len(byDomain))
	for name := range byDomain {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Fprintf(w, "\n%s\n%s\n", name, strings.Repeat("-", len(name)))
		for _, a := range byDomain[name] {
			fmt.Fprintf(w, "  %-7s %-11s %s  [%s]\n", a.Op, a.Resource, a.Detail, a.Provider)
		}
	}

	manual := 0
	for _, a := range p.Actions {
		if a.Op == OpManual {
			manual++
		}
	}
	fmt.Fprintf(w, "\n%d actions", len(p.Actions))
	if manual > 0 {
		fmt.Fprintf(w, " (%d need a human)", manual)
	}
	fmt.Fprintln(w)
}
