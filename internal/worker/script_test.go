package worker

import (
	"strings"
	"testing"
)

func TestScriptNameIsStablePerDomain(t *testing.T) {
	got, err := ScriptName("example.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}
	if !strings.HasPrefix(got, "mailctl-mta-sts-example-com-") {
		t.Errorf("name = %q, want dots replaced and a hash suffix appended", got)
	}

	again, err := ScriptName("example.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}
	if got != again {
		t.Error("ScriptName must be stable across calls for the same domain")
	}
}

func TestScriptNameDoesNotCollideOnDotVsHyphen(t *testing.T) {
	a, err := ScriptName("my.site.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}
	b, err := ScriptName("my-site.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}
	if a == b {
		t.Errorf("my.site.com and my-site.com produced the same script name %q; they would silently overwrite each other's policy", a)
	}
}

func TestScriptNameRejectsNamesOverTheLengthLimit(t *testing.T) {
	longDomain := strings.Repeat("a", 60) + ".com"

	_, err := ScriptName(longDomain)
	if err == nil {
		t.Fatal("expected an error for an over-length script name")
	}
	if !strings.Contains(err.Error(), longDomain) {
		t.Errorf("err = %v, want it to name the offending domain", err)
	}
}

func TestPolicyScriptEmbedsThePolicyAndServesTheWellKnownPath(t *testing.T) {
	policy := "version: STSv1\nmode: enforce\nmx: mx.a.com\nmax_age: 604800\n"

	got := PolicyScript(policy)

	if !strings.Contains(got, "/.well-known/mta-sts.txt") {
		t.Error("script must route the well-known path")
	}
	if !strings.Contains(got, "text/plain") {
		t.Error("the policy must be served as text/plain or receivers reject it")
	}
	if !strings.Contains(got, "mode: enforce") {
		t.Error("script must embed the policy body")
	}
	if !strings.Contains(got, "export default") {
		t.Error("script must be an ES module, matching the main_module upload metadata")
	}
}

func TestPolicyScriptEscapesBackticksAndInterpolation(t *testing.T) {
	got := PolicyScript("weird `backtick` and ${injection}\n")

	if !strings.Contains(got, "\\`backtick\\`") {
		t.Errorf("backticks must be escaped; got:\n%s", got)
	}
	if !strings.Contains(got, "\\${injection}") {
		t.Errorf("the dollar-brace sequence must be escaped; got:\n%s", got)
	}

	// Every ${ must be backslash-escaped. Remove the escaped ones, and any
	// ${ still standing would interpolate for real when the Worker runs.
	neutralised := strings.ReplaceAll(got, "\\${", "")
	if strings.Contains(neutralised, "${") {
		t.Errorf("an unescaped ${ survived and would interpolate at runtime; got:\n%s", got)
	}
}

func TestPolicyScriptIsDeterministic(t *testing.T) {
	policy := "version: STSv1\nmode: testing\nmx: mx.a.com\nmax_age: 86400\n"

	if PolicyScript(policy) != PolicyScript(policy) {
		t.Error("the same policy must produce byte-identical source, or every run redeploys")
	}
}
