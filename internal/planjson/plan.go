// Package planjson projects mailctl's plan and audit results into a stable JSON
// schema. Both `mailctl plan -json` and the local UI server render through it,
// so a script gating a pipeline and the UI can never disagree about what a run
// intends to do.
package planjson

import (
	"strconv"

	"github.com/zoolcoder/mailctl/internal/plan"
)

// SchemaVersion is incremented when a change would break an existing consumer.
// Adding a field is not such a change; removing or repurposing one is.
const SchemaVersion = 1

// Action is one intended change, described but not executable.
//
// plan.Action carries Do, a closure over live provider clients. It is
// deliberately absent here: this type describes intent, and a plan that has been
// through JSON must never be a way to ask for work. Apply resolves actions from
// a plan it holds itself.
type Action struct {
	// ID identifies the action within this plan only. It is a position, not a
	// durable identity, and it is not stable across runs.
	ID       string `json:"id"`
	Op       string `json:"op"`
	Resource string `json:"resource"`
	Domain   string `json:"domain"`
	Provider string `json:"provider,omitempty"`
	Detail   string `json:"detail"`
	// Manual marks an action a human completes outside mailctl. It renders in
	// the plan and is never executed, so a converged plan may still list one.
	Manual bool `json:"manual"`
}

type Plan struct {
	SchemaVersion int      `json:"schemaVersion"`
	Actions       []Action `json:"actions"`
}

func FromPlan(p plan.Plan) Plan {
	// Non-nil so an empty plan marshals as [] rather than null.
	actions := make([]Action, 0, len(p.Actions))
	for i, a := range p.Actions {
		actions = append(actions, Action{
			ID:       strconv.Itoa(i),
			Op:       string(a.Op),
			Resource: a.Resource,
			Domain:   a.Domain,
			Provider: a.Provider,
			Detail:   a.Detail,
			Manual:   a.Op == plan.OpManual,
		})
	}
	return Plan{SchemaVersion: SchemaVersion, Actions: actions}
}
