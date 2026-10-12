package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/plan"
)

func destructivePlan() plan.Plan {
	var p plan.Plan
	p.Add(plan.Action{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Detail: "create new@a.com"})
	p.Add(plan.Action{Op: plan.OpDelete, Resource: "mailbox", Domain: "a.com",
		Detail: "delete legacy@a.com and all mail it holds"})
	p.Add(plan.Action{Op: plan.OpDelete, Resource: "alias", Domain: "b.com", Detail: "delete unmanaged alias old"})
	return p
}

func TestConfirmAcceptsTheExactDomainList(t *testing.T) {
	var out strings.Builder

	if err := Confirm(strings.NewReader("a.com,b.com\n"), &out, destructivePlan()); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !strings.Contains(out.String(), "legacy@a.com") {
		t.Errorf("prompt must name every object individually; got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "a.com,b.com") {
		t.Errorf("prompt must tell the user exactly what to type; got:\n%s", out.String())
	}
}

func TestConfirmToleratesSpacingAndCase(t *testing.T) {
	var out strings.Builder

	if err := Confirm(strings.NewReader("  A.com , b.COM \n"), &out, destructivePlan()); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
}

func TestConfirmRejectsAnythingElse(t *testing.T) {
	for _, answer := range []string{"yes\n", "a.com\n", "\n", "y\n"} {
		var out strings.Builder
		err := Confirm(strings.NewReader(answer), &out, destructivePlan())
		if err == nil {
			t.Errorf("answer %q should not confirm a destructive plan", answer)
		}
	}
}

func TestConfirmSkipsPromptWhenNothingIsDeleted(t *testing.T) {
	var p plan.Plan
	p.Add(plan.Action{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Detail: "create new@a.com"})

	var out strings.Builder
	if err := Confirm(strings.NewReader(""), &out, p); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("a plan with no deletions must not prompt; got:\n%s", out.String())
	}
}

func TestConfirmRejectsAnswerWithoutTrailingNewline(t *testing.T) {
	var out strings.Builder
	// A reader that returns the exact correct answer but no trailing newline
	reader := strings.NewReader("a.com,b.com")
	err := Confirm(reader, &out, destructivePlan())
	if err == nil {
		t.Errorf("answer without trailing newline should not confirm, even if it's exactly correct")
	}
}

func TestConfirmRejectsReadError(t *testing.T) {
	var out strings.Builder
	// A reader that returns an error before a complete line
	errorReader := &errReader{err: errors.New("read failed")}
	err := Confirm(errorReader, &out, destructivePlan())
	if err == nil {
		t.Errorf("a read error should abort confirmation")
	}
}

func TestConfirmRejectsExtraTextAroundCorrectAnswer(t *testing.T) {
	var out strings.Builder
	err := Confirm(strings.NewReader("sure, a.com,b.com works\n"), &out, destructivePlan())
	if err == nil {
		t.Errorf("extra text around the correct answer should not confirm")
	}
}

// errReader is a custom reader that always returns an error
type errReader struct {
	err error
}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, r.err
}
