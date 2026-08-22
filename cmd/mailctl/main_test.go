package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/configedit"
	"github.com/zoolcoder/mailctl/internal/engine"
	"github.com/zoolcoder/mailctl/internal/mail"
)

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

// fakeServer answers both the Cloudflare (/zones...) and Purelymail
// (/api/v0/...) paths mailctl's apply path needs, just enough to converge a
// single domain with one mailbox to be created: an empty zone, no existing
// records, a domain Purelymail does not know about yet, and success on every
// write.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"test.com"}],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodGet:
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/zones/z1/dns_records" && r.Method == http.MethodPost:
			fmt.Fprint(w, `{"success":true,"result":{"id":"r1"}}`)
		case r.URL.Path == "/zones/z1/email/routing":
			fmt.Fprint(w, `{"success":true,"result":{"enabled":true,"name":"test.com","status":"unlocked"}}`)
		case r.URL.Path == "/zones/z1/email/routing/rules":
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/zones/z1/email/routing/rules/catch_all":
			fmt.Fprint(w, `{"success":true,"result":{"tag":"catch","enabled":false,"matchers":[{"type":"all"}],"actions":[]}}`)
		case r.URL.Path == "/accounts/acc-1/email/routing/addresses":
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/api/v0/getOwnershipCode":
			fmt.Fprint(w, `{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`)
		case r.URL.Path == "/api/v0/listDomains":
			fmt.Fprint(w, `{"type":"success","result":{"domains":[]}}`)
		case r.URL.Path == "/api/v0/addDomain":
			fmt.Fprint(w, `{"type":"success","result":null}`)
		case r.URL.Path == "/api/v0/createUser":
			fmt.Fprint(w, `{"type":"success","result":null}`)
		case r.URL.Path == "/api/v0/modifyUser":
			fmt.Fprint(w, `{"type":"success","result":null}`)
		case r.URL.Path == "/api/v0/createRoutingRule":
			fmt.Fprint(w, `{"type":"success","result":null}`)
		case r.URL.Path == "/api/v0/createAppPassword":
			fmt.Fprint(w, `{"type":"success","result":{"appPassword":"generated-app-pw"}}`)
		case r.URL.Path == "/api/v0/deleteAppPassword":
			fmt.Fprint(w, `{"type":"success","result":null}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fmt.Fprint(w, `{"success":false,"type":"error","code":"UNEXPECTED","message":"unexpected request"}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func writeTestConfig(t *testing.T, serverURL string) string {
	t.Helper()
	body := fmt.Sprintf(`
version: 1
cloudflare:
  accountId: acc-1
  baseUrl: %s
purelymail:
  baseUrl: %s
domains:
  - name: test.com
    mail:
      provider: purelymail
    mailboxes:
      - address: box@test.com
`, serverURL, serverURL)

	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestApplyNeverPrintsGeneratedCredentialToStdout is the seam guard for F3/F8:
// a generated credential must land on the error writer, and never on the
// writer apply's own progress output goes to.
func TestApplyNeverPrintsGeneratedCredentialToStdout(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-config", configPath, "-yes"}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	match := regexp.MustCompile(`box@test\.com\t(\S+)`).FindStringSubmatch(stderr.String())
	if match == nil {
		t.Fatalf("stderr should report the generated credential for box@test.com; got:\n%s", stderr.String())
	}
	credential := match[1]

	if strings.Contains(stdout.String(), credential) {
		t.Errorf("generated credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "box@test.com") {
		t.Errorf("stderr should name the mailbox; got:\n%s", stderr.String())
	}
}

// TestApplyReportsCredentialWhenSecretsOutFails is the regression guard for
// finding C3: a failed -secrets-out write used to be the only trace of a
// credential that was already live at the provider — WriteFile's error came
// back with the value nowhere. unwritablePath's parent directory does not
// exist, so the write fails without any chmod tricks the sandbox might block.
func TestApplyReportsCredentialWhenSecretsOutFails(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	unwritablePath := filepath.Join(t.TempDir(), "no-such-dir", "out.secrets")

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-config", configPath, "-yes", "-secrets-out", unwritablePath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected an error for the unwritable -secrets-out path")
	}

	match := regexp.MustCompile(`box@test\.com\t(\S+)`).FindStringSubmatch(stderr.String())
	if match == nil {
		t.Fatalf("stderr should still report the generated credential for box@test.com even though the write failed; got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), match[1]) {
		t.Errorf("generated credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
}

// TestMailboxPasswdReportsCredentialWhenSecretsOutFails mirrors
// TestApplyReportsCredentialWhenSecretsOutFails for the passwd path: for
// apppass create and passwd, a failed write is unrecoverable, since the
// provider does not let a credential be read back.
func TestMailboxPasswdReportsCredentialWhenSecretsOutFails(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	unwritablePath := filepath.Join(t.TempDir(), "no-such-dir", "out.secrets")

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "passwd", "box@test.com", "-config", configPath, "-secrets-out", unwritablePath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected an error for the unwritable -secrets-out path")
	}

	match := regexp.MustCompile(`box@test\.com\t(\S+)`).FindStringSubmatch(stderr.String())
	if match == nil {
		t.Fatalf("stderr should still report the generated credential for box@test.com even though the write failed; got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), match[1]) {
		t.Errorf("credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
}

// TestApppassCreateReportsCredentialWhenSecretsOutFails mirrors
// TestApplyReportsCredentialWhenSecretsOutFails for the apppass create path.
func TestApppassCreateReportsCredentialWhenSecretsOutFails(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	unwritablePath := filepath.Join(t.TempDir(), "no-such-dir", "out.secrets")

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apppass", "create", "box@test.com", "-name", "phone", "-config", configPath, "-secrets-out", unwritablePath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil {
		t.Fatalf("expected an error for the unwritable -secrets-out path")
	}

	if !strings.Contains(stderr.String(), "generated-app-pw") {
		t.Fatalf("stderr should still report the app credential even though the write failed; got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "generated-app-pw") {
		t.Errorf("app credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
}

func writeEmptyConfigWithCloudflareSettings(t *testing.T, serverURL string) string {
	t.Helper()
	body := fmt.Sprintf(`
version: 1
cloudflare:
  accountId: acc-1
  baseUrl: %s
purelymail:
  baseUrl: %s
domains: []
`, serverURL, serverURL)

	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// TestImportSucceedsWithEmptyDomains verifies that the import command can work
// with a config that has no domains, since its purpose is to import the first domain.
func TestImportSucceedsWithEmptyDomains(t *testing.T) {
	server := fakeServer(t)
	configPath := writeEmptyConfigWithCloudflareSettings(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")

	// Use cfrouting provider (routing-only) for simplicity; it needs only Cloudflare.
	// The fakeServer already handles /zones and /zones/.../dns_records endpoints.
	var stdout, stderr strings.Builder
	err := run([]string{"import", "-config", configPath, "-domain", "test.com", "-provider", "cfrouting"},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run import: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	// Verify output contains the domain block.
	if !strings.Contains(stdout.String(), "- name: test.com") {
		t.Errorf("import output should contain domain block; got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "provider: cfrouting") {
		t.Errorf("import output should contain provider; got:\n%s", stdout.String())
	}
}

// TestPlanFailsWithEmptyDomains verifies that other commands still reject an
// empty domains list.
func TestPlanFailsWithEmptyDomains(t *testing.T) {
	server := fakeServer(t)
	configPath := writeEmptyConfigWithCloudflareSettings(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"plan", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)

	if err == nil {
		t.Fatalf("plan should fail with empty domains, but succeeded")
	}
	if !strings.Contains(err.Error(), "no domains") {
		t.Errorf("error should mention domain requirement; got: %v", err)
	}
}

// TestImportExpandsEnvVarsEvenWithEmptyDomains is the acceptance test for the
// bug where an empty domains: list made run re-parse the config with a plain
// yaml.Unmarshal, bypassing ${VAR} expansion entirely: accountId:
// ${CLOUDFLARE_ACCOUNT_ID} would reach Cloudflare as the literal string
// "${CLOUDFLARE_ACCOUNT_ID}". There is now exactly one config-loading path
// (config.Load), so the accountId here must reach the fake server expanded.
func TestImportExpandsEnvVarsEvenWithEmptyDomains(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			fmt.Fprint(w, `{"success":true,"result":[{"id":"z1","name":"test.com"}],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/zones/z1/email/routing":
			fmt.Fprint(w, `{"success":true,"result":{"enabled":true,"name":"test.com","status":"unlocked"}}`)
		case r.URL.Path == "/zones/z1/email/routing/rules":
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`)
		case r.URL.Path == "/zones/z1/email/routing/rules/catch_all":
			fmt.Fprint(w, `{"success":true,"result":{"tag":"catch","enabled":false,"matchers":[{"type":"all"}],"actions":[]}}`)
		case strings.HasPrefix(r.URL.Path, "/accounts/"):
			gotPath = r.URL.Path
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"page":1,"total_pages":1}}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fmt.Fprint(w, `{"success":false,"type":"error","code":"UNEXPECTED","message":"unexpected request"}`)
		}
	}))
	t.Cleanup(server.Close)

	body := fmt.Sprintf(`
version: 1
cloudflare:
  accountId: ${CLOUDFLARE_ACCOUNT_ID}
  baseUrl: %s
domains: []
`, server.URL)
	configPath := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("CLOUDFLARE_ACCOUNT_ID", "expanded-acc-id")

	var stdout, stderr strings.Builder
	err := run([]string{"import", "-config", configPath, "-domain", "test.com", "-provider", "cfrouting"},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run import: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	if !strings.Contains(gotPath, "expanded-acc-id") {
		t.Errorf("request path = %q, want the expanded account id, not the literal ${CLOUDFLARE_ACCOUNT_ID}", gotPath)
	}
}

// TestAliasAddParsesFlagsAfterThePositionalArguments is a regression guard:
// flag.Parse stops at the first non-flag token, so "-alias-domain" and "-to"
// coming after the verb and local-part must be shifted off before
// flags.Parse ever sees them, or they would silently never be recognized.
func TestAliasAddParsesFlagsAfterThePositionalArguments(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	// -yes is omitted: alias add is now rejected outright for that flag (C1),
	// and it is unneeded regardless, since adding an alias plans no deletion
	// for Confirm to gate.
	var stdout, stderr strings.Builder
	err := run([]string{
		"alias", "add", "info", "-alias-domain", "test.com", "-to", "box@test.com",
		"-config", configPath,
	}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	got := read(t, configPath)
	if !strings.Contains(got, "match: info") {
		t.Fatalf("alias-domain and to flags were not applied; config:\n%s", got)
	}
}

// TestMailboxAddFallsThroughToApply verifies mailbox add edits the config and
// then reconciles it against the provider in the same command.
func TestMailboxAddFallsThroughToApply(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	// -yes is omitted: mailbox add is now rejected outright for that flag (C1),
	// and it is unneeded regardless, since adding a mailbox plans no deletion
	// for Confirm to gate.
	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "new@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	if !strings.Contains(read(t, configPath), "new@test.com") {
		t.Errorf("mailbox should be in the config after add")
	}
	if !strings.Contains(stderr.String(), "new@test.com") {
		t.Errorf("stderr should report the generated credential for new@test.com; got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "\t") && regexp.MustCompile(`new@test\.com\t\S+`).MatchString(stdout.String()) {
		t.Errorf("generated credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
}

// TestMailboxAddRejectsADuplicate verifies the config-edit error surfaces
// through the CLI without ever reaching apply.
func TestMailboxAddRejectsADuplicate(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "box@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "box@test.com") {
		t.Fatalf("err = %v, want a duplicate error naming box@test.com", err)
	}
}

// TestMailboxRmOnlyEditsConfig verifies rm never calls the provider: fakeServer
// fails the test on any unexpected request.
func TestMailboxRmOnlyEditsConfig(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "rm", "box@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	if strings.Contains(read(t, configPath), "box@test.com") {
		t.Errorf("mailbox should be gone from the config")
	}
	if !strings.Contains(stderr.String(), "apply -prune") {
		t.Errorf("stderr should note the mailbox still exists at the provider; got:\n%s", stderr.String())
	}
}

// TestMailboxRmSucceedsWithoutCloudflareToken is the regression guard for
// finding I8: rm only edits the config file, so it must not demand
// CLOUDFLARE_API_TOKEN the way plan, apply, and audit legitimately do.
// CLOUDFLARE_API_TOKEN is deliberately left unset; fakeServer fails the test
// on any request, so a regression that moves the check back above rm's early
// return would be caught either way.
func TestMailboxRmSucceedsWithoutCloudflareToken(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "rm", "box@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	if strings.Contains(read(t, configPath), "box@test.com") {
		t.Errorf("mailbox should be gone from the config")
	}
}

// TestAliasRmOnlyEditsConfig mirrors TestMailboxRmOnlyEditsConfig for aliases.
func TestAliasRmOnlyEditsConfig(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	// Add directly through configedit so this test isolates rm; going through
	// the CLI would exercise apply again, which the add tests already cover.
	if err := configedit.AddAlias(configPath, "test.com", "info", []string{"box@test.com"}); err != nil {
		t.Fatalf("seed alias: %v", err)
	}

	var stdout, stderr strings.Builder
	err := run([]string{"alias", "rm", "info", "-alias-domain", "test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	if strings.Contains(read(t, configPath), "match: info") {
		t.Errorf("alias should be gone from the config")
	}
	if !strings.Contains(stderr.String(), "apply -prune") {
		t.Errorf("stderr should note the rule still exists at the provider; got:\n%s", stderr.String())
	}
}

// TestApppassCreateNeverPrintsCredentialToStdout mirrors the apply seam guard
// for the apppass path: an app credential is shown exactly once and must land
// on stderr, never stdout.
func TestApppassCreateNeverPrintsCredentialToStdout(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apppass", "create", "box@test.com", "-name", "phone", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	if !strings.Contains(stderr.String(), "generated-app-pw") {
		t.Errorf("stderr should report the app credential; got:\n%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "generated-app-pw") {
		t.Errorf("app credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
}

// TestApppassRmRequiresName verifies -name is mandatory for apppass rm, since
// Purelymail identifies an app credential by name, not by value.
func TestApppassRmRequiresName(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apppass", "rm", "box@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "-name") {
		t.Fatalf("err = %v, want an error naming -name", err)
	}
}

// TestApppassCreateRejectsAddressOutsideConfig and
// TestApppassRmRejectsAddressOutsideConfig are the regression guard for
// finding I3: apppass never checked the address's domain was in the config
// and used the purelymail provider. "apppass rm nobody@not-in-config.example
// -name x" issued deleteAppPassword for a domain mailctl does not manage;
// apppass rm is the only provider-side deletion outside the -prune/Confirm
// gate, so a typo would delete at the provider with nothing to stop it.
func TestApppassCreateRejectsAddressOutsideConfig(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apppass", "create", "nobody@not-in-config.example", "-name", "x", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "not-in-config.example") {
		t.Fatalf("err = %v, want an error naming not-in-config.example", err)
	}
}

func TestApppassRmRejectsAddressOutsideConfig(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apppass", "rm", "nobody@not-in-config.example", "-name", "x", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "not-in-config.example") {
		t.Fatalf("err = %v, want an error naming not-in-config.example", err)
	}
}

// TestPlanNeverAppliesEvenIfTheGateBreaks pins the "if command == "mailbox"
// || ..." gate around the reload-and-apply fallthrough. Without it, "plan"
// falls through the inner switch's unmatched cases straight into the reload
// and command = "apply". Confirmed this test fails under the mutation
// described in review (replacing the gate with "if true"): with this
// fixture's all-CREATE plan, engine.Confirm has no deletions to confirm and
// returns immediately without even reading stdin, so the mutated run does
// not error at all — it silently applies (9 actions against the fake
// server) and returns nil. The assertion that catches it is stdout missing
// the plan-only "Run `mailctl apply`" message, not an error.
func TestPlanNeverAppliesEvenIfTheGateBreaks(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"plan", "-config", configPath}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Run `mailctl apply`") {
		t.Errorf("plan must render the plan-only message, not apply; stdout:\n%s", stdout.String())
	}
}

// TestPlanJSONEmitsOnlyJSON asserts that -json is a rendering concern only: a
// consumer piping this into jq must get the document and nothing else, not
// the human summary line or the "Run `mailctl apply`" hint interleaved with
// it.
func TestPlanJSONEmitsOnlyJSON(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr bytes.Buffer
	err := run([]string{"plan", "-json", "-config", configPath}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}

	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Actions       []struct {
			Op     string `json:"op"`
			Domain string `json:"domain"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid json: %v\ngot: %s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", doc.SchemaVersion)
	}

	// stdout must be the document and nothing else. Assert the shape directly:
	// a prose check of the form `contains(prose) && !contains("\"actions\"")`
	// can never fire, because the document always contains "actions".
	out := stdout.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("stdout does not begin with a json object: %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Errorf("stdout does not end with a json object; something was appended: %q", out)
	}
	for _, prose := range []string{"Run `mailctl apply`", "No changes.", " actions\n"} {
		if strings.Contains(out, prose) {
			t.Errorf("stdout carries the human rendering %q, which breaks a jq consumer", prose)
		}
	}
}

// TestApplyRejectsJSONFlag pins -json's scoping the opposite way from
// -prune/-yes: it is a plan-only rendering concern, so apply must refuse it
// rather than silently ignore it.
func TestApplyRejectsJSONFlag(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-json", "-config", configPath, "-yes"},
		strings.NewReader(""), &stdout, &stderr)

	wantSubstr := "flag -json is not valid for apply"
	if err == nil || !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("err = %v, want it to contain %q", err, wantSubstr)
	}
}

// TestMailboxPasswdNeverPrintsCredentialToStdoutOrConfig is the seam guard
// for the passwd path: a credential must never enter the config file (the
// reason passwd bypasses configedit entirely) and must land on stderr, never
// stdout.
func TestMailboxPasswdNeverPrintsCredentialToStdoutOrConfig(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "passwd", "box@test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}

	match := regexp.MustCompile(`box@test\.com\t(\S+)`).FindStringSubmatch(stderr.String())
	if match == nil {
		t.Fatalf("stderr should report the generated credential for box@test.com; got:\n%s", stderr.String())
	}
	credential := match[1]

	if strings.Contains(stdout.String(), credential) {
		t.Errorf("credential leaked onto stdout: stdout =\n%s", stdout.String())
	}
	if strings.Contains(read(t, configPath), credential) {
		t.Errorf("credential leaked into the config file")
	}
}

// TestScopedFlagsAreRejectedOutsidePlanAndApply is the regression guard for
// finding C1: "mailctl mailbox add new@test.com -prune -yes" used to pass
// -prune and -yes straight into engine.Options, so a command named "add"
// could delete a mailbox never named on the command line, with no prompt.
// Each of -prune, -replace-dns, and -yes must now be rejected before any
// config is loaded, for every command other than plan and apply.
func TestScopedFlagsAreRejectedOutsidePlanAndApply(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		label   string
	}{
		{"mailbox", []string{"mailbox", "add", "new@test.com"}, "mailbox add"},
		{"alias", []string{"alias", "add", "info", "-alias-domain", "test.com", "-to", "box@test.com"}, "alias add"},
		{"apppass", []string{"apppass", "create", "box@test.com"}, "apppass create"},
		{"import", []string{"import", "-domain", "test.com", "-provider", "cfrouting"}, "import"},
		{"audit", []string{"audit"}, "audit"},
	}
	flagsToReject := []string{"-prune", "-prune-mailboxes", "-replace-dns", "-yes"}

	for _, tt := range tests {
		for _, flag := range flagsToReject {
			t.Run(tt.command+flag, func(t *testing.T) {
				var stdout, stderr strings.Builder
				args := append(append([]string{}, tt.args...), flag)
				err := run(args, strings.NewReader(""), &stdout, &stderr)

				wantSubstr := fmt.Sprintf("flag %s is not valid for %s", flag, tt.label)
				if err == nil || !strings.Contains(err.Error(), wantSubstr) {
					t.Fatalf("err = %v, want it to contain %q", err, wantSubstr)
				}
			})
		}
	}
}

// TestApplyStillAcceptsPrune guards against rejectScopedFlags overreaching:
// apply -prune is exactly the case C1's fix must continue to allow.
func TestApplyStillAcceptsPrune(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-config", configPath, "-prune", "-yes"},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
}

// TestHelpSpellingsExitZeroWithUsageOnStdout is the regression guard for
// finding I7: the prefix guard at the top of run only promotes a non-dash
// token to command, so "-h" and "--help" left command at its "plan" default
// and fell into flag.Parse as an unrecognized flag, exiting 1 with usage on
// stderr instead of the zero-exit, stdout usage "help" already got.
func TestHelpSpellingsExitZeroWithUsageOnStdout(t *testing.T) {
	for _, spelling := range []string{"help", "-h", "--help"} {
		t.Run(spelling, func(t *testing.T) {
			var stdout, stderr strings.Builder
			err := run([]string{spelling}, strings.NewReader(""), &stdout, &stderr)
			if err != nil {
				t.Fatalf("run(%q): %v\nstderr:\n%s", spelling, err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("run(%q): stdout should contain usage; got:\n%s", spelling, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%q): stderr should be empty; got:\n%s", spelling, stderr.String())
			}
		})
	}
}

// TestSubcommandHelpExitsZeroWithUsageOnStdout is the regression guard for
// the follow-up to I7: bare "-h"/"--help"/"help" were fixed, but a
// subcommand-scoped "-h" reaches flags.Parse, which returns flag.ErrHelp.
// run used to propagate that as an ordinary error, so main printed
// "error: flag: help requested" and exited 1 even though "plan -h" is a
// common invocation asking for help, not reporting a failure.
func TestSubcommandHelpExitsZeroWithUsageOnStdout(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"plan -h", []string{"plan", "-h"}},
		{"apply --help", []string{"apply", "--help"}},
		{"mailbox passwd -h", []string{"mailbox", "passwd", "box@test.com", "-h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			err := run(tt.args, strings.NewReader(""), &stdout, &stderr)
			if err != nil {
				t.Fatalf("run(%v): %v\nstderr:\n%s", tt.args, err, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("run(%v): stdout should contain usage; got:\n%s", tt.args, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("run(%v): stderr should be empty; got:\n%s", tt.args, stderr.String())
			}
		})
	}
}

// TestMailboxAddRejectsAnAddressWithoutAt is the regression guard for finding
// M2: "mailbox add not-an-address" used to fail with an unhelpful empty-domain
// error (domainOf returns "" when there is no @), because nothing checked the
// address shape before deriving the domain from it.
func TestMailboxAddRejectsAnAddressWithoutAt(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "not-an-address", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "not-an-address") {
		t.Fatalf("err = %v, want an error naming not-an-address", err)
	}
}

// TestMailboxAddRejectsADomainFlagExcludingTheEditedDomain is the regression
// guard for finding I2: "mailbox add new@a.com -domain other.com" used to
// edit a.com's config and then apply only other.com, so the mailbox landed
// in the file, never reached the provider, and the command still exited 0.
func TestMailboxAddRejectsADomainFlagExcludingTheEditedDomain(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "new@test.com", "-domain", "other.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "other.com") || !strings.Contains(err.Error(), "test.com") {
		t.Fatalf("err = %v, want an error naming both other.com and test.com", err)
	}
	if strings.Contains(read(t, configPath), "new@test.com") {
		t.Errorf("config should not have been edited when -domain excludes the edited domain")
	}
}

// TestMailboxAddAcceptsADomainFlagIncludingTheEditedDomain guards against
// requireDomainInScope overreaching: -domain naming the edited domain (among
// others) must still work.
func TestMailboxAddAcceptsADomainFlagIncludingTheEditedDomain(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "new@test.com", "-domain", "test.com", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(read(t, configPath), "new@test.com") {
		t.Errorf("mailbox should be in the config after add")
	}
}

// TestAliasAddRejectsADomainFlagExcludingTheEditedDomain mirrors
// TestMailboxAddRejectsADomainFlagExcludingTheEditedDomain for alias add.
func TestAliasAddRejectsADomainFlagExcludingTheEditedDomain(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{
		"alias", "add", "info", "-alias-domain", "test.com", "-to", "box@test.com",
		"-domain", "other.com", "-config", configPath,
	}, strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "other.com") || !strings.Contains(err.Error(), "test.com") {
		t.Fatalf("err = %v, want an error naming both other.com and test.com", err)
	}
	if strings.Contains(read(t, configPath), "match: info") {
		t.Errorf("config should not have been edited when -domain excludes the edited domain")
	}
}

// TestMailboxRejectsAFlagAsTheAddress is the regression guard for finding 5:
// "mailbox add -password-env X" must not consume "-password-env" as the
// address, leaving "X" as a stray positional argument.
func TestMailboxRejectsAFlagAsTheAddress(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"mailbox", "add", "-password-env", "X", "-config", configPath},
		strings.NewReader(""), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "usage: mailctl mailbox") {
		t.Fatalf("err = %v, want the usage message", err)
	}
}

// TestPruneMailboxesRequiresPrune guards the ms365 mailbox-deletion opt-in:
// -prune-mailboxes alone would do nothing (mail.Options.PruneMailboxes only
// matters when Prune is also set), which would let an operator believe their
// tenant had no unmanaged mailboxes when the flag never took effect. The
// combination must be rejected before any network call, so this needs
// neither CLOUDFLARE_API_TOKEN nor a fake server.
func TestPruneMailboxesRequiresPrune(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"plan", "-prune-mailboxes", "-config", writeEmptyConfigWithCloudflareSettings(t, "http://unused.invalid")},
		strings.NewReader(""), &out, &errOut)
	if err == nil {
		t.Fatal("want an error: -prune-mailboxes without -prune does nothing")
	}
	if !strings.Contains(err.Error(), "-prune") {
		t.Errorf("error = %q, want it to explain the dependency", err)
	}
}

// TestUsageMentionsPruneMailboxes guards the operator-visible surface of the
// flag: a flag an operator cannot discover from -h is as good as undocumented.
func TestUsageMentionsPruneMailboxes(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"-h"}, strings.NewReader(""), &out, &errOut)
	combined := out.String() + errOut.String()
	if !strings.Contains(combined, "-prune-mailboxes") {
		t.Error("usage does not mention -prune-mailboxes")
	}
}

// TestUsageMentionsMS365EnvVars guards the operator-visible surface of the
// ms365 provider's credentials: an operator reading -h has no other way to
// learn what to set before using it.
func TestUsageMentionsMS365EnvVars(t *testing.T) {
	var out, errOut bytes.Buffer
	_ = run([]string{"-h"}, strings.NewReader(""), &out, &errOut)
	combined := out.String() + errOut.String()
	for _, want := range []string{"MS365_TENANT_ID", "MS365_CLIENT_ID", "MS365_CLIENT_SECRET"} {
		if !strings.Contains(combined, want) {
			t.Errorf("usage does not mention %s", want)
		}
	}
}

// TestApplyAcceptsPruneWithPruneMailboxes guards against overreach in both the
// scoped-flag rejection and the -prune-mailboxes-requires--prune check: apply
// with both flags set together is exactly the case they must continue to
// allow.
func TestApplyAcceptsPruneWithPruneMailboxes(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)

	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-config", configPath, "-prune", "-prune-mailboxes", "-yes"},
		strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
}

func TestResolveVersion(t *testing.T) {
	tests := []struct {
		name           string
		ldflagsVersion string
		mainVersion    string
		revision       string
		modified       bool
		want           string
	}{
		{
			name:           "ldflags version wins over a real module version",
			ldflagsVersion: "v0.1.0-rc1",
			mainVersion:    "v0.1.0",
			revision:       "a1b2c3d4e5f6a7b8",
			modified:       true,
			want:           "v0.1.0-rc1",
		},
		{
			name:           "real module version is used",
			ldflagsVersion: "dev",
			mainVersion:    "v0.1.0",
			want:           "v0.1.0",
		},
		{
			name:           "(devel) falls back to dev wording",
			ldflagsVersion: "dev",
			mainVersion:    "(devel)",
			want:           "dev",
		},
		{
			name:           "empty module version falls back to dev wording",
			ldflagsVersion: "dev",
			mainVersion:    "",
			want:           "dev",
		},
		{
			name:           "revision is appended and truncated to 12 characters",
			ldflagsVersion: "dev",
			mainVersion:    "(devel)",
			revision:       "a1b2c3d4e5f6a7b8c9d0",
			want:           "dev (a1b2c3d4e5f6)",
		},
		{
			name:           "modified tree is marked",
			ldflagsVersion: "dev",
			mainVersion:    "(devel)",
			revision:       "a1b2c3d4e5f6a7b8c9d0",
			modified:       true,
			want:           "dev (a1b2c3d4e5f6, modified)",
		},
		{
			name:           "missing revision produces no empty parentheses",
			ldflagsVersion: "dev",
			mainVersion:    "(devel)",
			modified:       true,
			want:           "dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveVersion(tt.ldflagsVersion, tt.mainVersion, tt.revision, tt.modified)
			if got != tt.want {
				t.Errorf("resolveVersion(%q, %q, %q, %v) = %q, want %q",
					tt.ldflagsVersion, tt.mainVersion, tt.revision, tt.modified, got, tt.want)
			}
		})
	}
}

// TestUICommandIsRecognised is the acceptance test for the ui subcommand
// itself: -h on it must exit zero with usage, like every other command.
func TestUICommandIsRecognised(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"ui", "-h"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("ui -h returned %v, want nil — stderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ui") {
		t.Errorf("usage does not mention the ui command: %s", stdout.String())
	}
}

// TestUsageListsTheUICommand guards the operator-visible surface: an
// operator reading -h/help has no other way to discover the command.
func TestUsageListsTheUICommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"help"}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "mailctl ui") {
		t.Errorf("usage omits the ui command:\n%s", stdout.String())
	}
}

// TestUIFlagsAreRejectedOutsideUI mirrors
// TestScopedFlagsAreRejectedOutsidePlanAndApply for -addr and -no-browser:
// both only mean something to the server ui starts, so every other command,
// including plan and apply, must reject them — not silently ignore them.
func TestUIFlagsAreRejectedOutsideUI(t *testing.T) {
	tests := []struct {
		args  []string
		label string
	}{
		{[]string{"plan"}, "plan"},
		{[]string{"apply", "-yes"}, "apply"},
		{[]string{"audit"}, "audit"},
		{[]string{"import", "-domain", "test.com", "-provider", "cfrouting"}, "import"},
		{[]string{"mailbox", "add", "new@test.com"}, "mailbox add"},
		{[]string{"alias", "add", "info", "-alias-domain", "test.com", "-to", "box@test.com"}, "alias add"},
		{[]string{"apppass", "create", "box@test.com"}, "apppass create"},
	}
	flagsToReject := []struct{ set, name string }{
		{"-addr=127.0.0.1:0", "addr"},
		{"-insecure", "insecure"},
		{"-data=/tmp/x", "data"},
		{"-no-browser", "no-browser"},
	}

	for _, tt := range tests {
		for _, flag := range flagsToReject {
			t.Run(tt.label+" "+flag.name, func(t *testing.T) {
				var stdout, stderr strings.Builder
				args := append(append([]string{}, tt.args...), flag.set)
				err := run(args, strings.NewReader(""), &stdout, &stderr)

				wantSubstr := fmt.Sprintf("flag -%s is not valid for %s", flag.name, tt.label)
				if err == nil || !strings.Contains(err.Error(), wantSubstr) {
					t.Fatalf("err = %v, want it to contain %q", err, wantSubstr)
				}
			})
		}
	}
}

// TestUICommandContextIsCancelledByInterruptNotTimeout pins the requirement
// that ui, a foreground server an operator leaves open indefinitely, gets a
// context cancelled by interrupt rather than the 10-minute deadline every
// other command uses — a fixed timeout would kill the server out from under
// a working operator.
func TestUICommandContextIsCancelledByInterruptNotTimeout(t *testing.T) {
	ctx, cancel := commandContext("ui")
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Error("ui's context has a deadline; it must be cancelled by interrupt instead")
	}
}

// TestOtherCommandsKeepTheTenMinuteTimeout guards against commandContext
// overreaching: every command other than ui must keep exactly the deadline
// behaviour it always had.
func TestOtherCommandsKeepTheTenMinuteTimeout(t *testing.T) {
	for _, command := range []string{"plan", "apply", "audit", "import", "mailbox", "alias", "apppass"} {
		ctx, cancel := commandContext(command)
		defer cancel()
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Errorf("%s: context has no deadline, want the 10-minute timeout", command)
			continue
		}
		if remaining := time.Until(deadline); remaining <= 0 || remaining > 10*time.Minute {
			t.Errorf("%s: deadline %v from now, want within (0, 10m]", command, remaining)
		}
	}
}

// syncBuffer is a concurrency-safe io.Writer with a String method, so a test
// can poll a server's stdout from a goroutine other than the one writing to
// it without racing those writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitForHost polls out until serveUI's startup line appears and returns the
// host:port it printed.
func waitForHost(t *testing.T, out *syncBuffer) string {
	t.Helper()
	re := regexp.MustCompile(`http://([^/]+)/`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			return m[1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("serveUI did not print a listening URL in time; got:\n%s", out.String())
	return ""
}

// TestUIRejectsRawOptionsStar is the regression guard for a security-review
// finding: Go's net/http answers a raw "OPTIONS * HTTP/1.1" request 200 via
// an internal handler substituted in before the configured Handler ever
// runs (see net/http's serverHandler.ServeHTTP), bypassing every middleware
// including the login guard in internal/ui — with no session and regardless
// of Host. The fix is DisableGeneralOptionsHandler: true on the *http.Server
// serveUI builds, which stops that substitution so the request reaches the
// real, guarded handler chain instead and gets rejected. This test supplies
// no session at all: it only needs the raw request to stop being answered
// 200 by something the guard never saw.
func TestUIRejectsRawOptionsStar(t *testing.T) {
	runner := engine.New(config.Config{}, nil, nil, mail.Deps{}, engine.Options{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- serveUI(ctx, runner, uiOptions{addr: "127.0.0.1:0", dataDir: t.TempDir()}, out)
	}()

	host := waitForHost(t, out)

	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatalf("dial %s: %v", host, err)
	}
	fmt.Fprintf(conn, "OPTIONS * HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)

	statusLine, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	_ = conn.Close()

	if strings.Contains(statusLine, " 200 ") {
		t.Errorf("OPTIONS * was answered 200 with no session and no Origin: %q", statusLine)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveUI: %v", err)
	}
}

func TestUIStartsWithoutACloudflareToken(t *testing.T) {
	u := unconfiguredPlanner{cfg: config.Config{Domains: []config.Domain{{Name: "a.example"}, {Name: "b.example"}}}, domains: domainList{"b.example"}, err: fmt.Errorf("CLOUDFLARE_API_TOKEN is required")}
	ds, err := u.Domains()
	if err != nil || len(ds) != 1 || ds[0].Name != "b.example" {
		t.Fatalf("domains = %+v err = %v", ds, err)
	}
	if _, err := u.Plan(context.Background()); err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_API_TOKEN") {
		t.Fatalf("plan err = %v", err)
	}
	if _, err := u.Desired(context.Background(), ds[0]); err == nil {
		t.Fatal("desired should fail without a token")
	}
}
