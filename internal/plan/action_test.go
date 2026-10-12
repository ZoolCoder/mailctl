package plan

import (
	"context"
	"strings"
	"testing"
)

func TestRenderGroupsByDomainAndMarksManual(t *testing.T) {
	var p Plan
	p.Add(Action{Op: OpCreate, Resource: "dns", Domain: "a.com", Provider: "cloudflare",
		Detail: "MX a.com -> mailserver.purelymail.com priority=50", Do: noop})
	p.Add(Action{Op: OpDelete, Resource: "dns", Domain: "a.com", Provider: "cloudflare",
		Detail: "TXT a.com -> v=spf1 include:old ~all", Do: noop})
	p.Add(Action{Op: OpManual, Resource: "destination", Domain: "a.com", Provider: "cfrouting",
		Detail: "verify ops@example.com by clicking the emailed link"})

	var out strings.Builder
	p.Render(&out)
	got := out.String()

	for _, want := range []string{
		"a.com",
		"CREATE  dns",
		"DELETE  dns",
		"MANUAL  destination",
		"3 actions",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("render should contain %q; got:\n%s", want, got)
		}
	}
}

func TestRenderEmptyPlanSaysConverged(t *testing.T) {
	var p Plan
	var out strings.Builder
	p.Render(&out)

	if !strings.Contains(out.String(), "already matches") {
		t.Errorf("empty plan should report convergence; got:\n%s", out.String())
	}
}

func TestExecutableSkipsManualActions(t *testing.T) {
	var p Plan
	p.Add(Action{Op: OpCreate, Resource: "dns", Do: noop})
	p.Add(Action{Op: OpManual, Resource: "destination"})

	if got := len(p.Executable()); got != 1 {
		t.Errorf("Executable() returned %d actions, want 1", got)
	}
}

func TestDestructiveSelectsDeletes(t *testing.T) {
	var p Plan
	p.Add(Action{Op: OpCreate, Resource: "mailbox", Do: noop})
	p.Add(Action{Op: OpDelete, Resource: "mailbox", Detail: "delete old@a.com", Do: noop})

	got := p.Destructive()
	if len(got) != 1 || got[0].Detail != "delete old@a.com" {
		t.Errorf("Destructive() = %v, want the single delete", got)
	}
}

func noop(_ context.Context) error { return nil }
