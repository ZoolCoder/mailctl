package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomainsJSONNamesCredentialsWithoutValues(t *testing.T) {
	configPath := writeTestConfig(t, "http://127.0.0.1:1")

	var stdout bytes.Buffer
	if err := run([]string{"domains", "-json", "-config", configPath}, nil, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
	var doc struct {
		Domains []struct {
			Name      string `json:"name"`
			Mailboxes []struct {
				Address string `json:"address"`
			} `json:"mailboxes"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("not json: %v\n%s", err, stdout.String())
	}
	if len(doc.Domains) != 1 || doc.Domains[0].Name != "test.com" || doc.Domains[0].Mailboxes[0].Address != "box@test.com" {
		t.Errorf("domains = %+v", doc.Domains)
	}
}

func TestApplySavedPlanAppliesWhenNothingDrifted(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	planPath := savePlan(t, configPath)
	var stdout, stderr strings.Builder
	err := run([]string{"apply", "-plan", planPath, "-config", configPath}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}
}

func TestApplySavedPlanRefusesDrift(t *testing.T) {
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	planPath := savePlan(t, configPath)
	body := read(t, configPath) + "      - address: late@test.com\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	err := run([]string{"apply", "-plan", planPath, "-config", configPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "drifted") {
		t.Fatalf("err = %v, want a drift refusal", err)
	}
}

func TestMailboxAddEditOnlyDoesNotApply(t *testing.T) {
	configPath := writeTestConfig(t, "http://127.0.0.1:1")
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stderr strings.Builder
	err := run([]string{"mailbox", "add", "new@test.com", "-edit-only", "-config", configPath}, nil, &bytes.Buffer{}, &stderr)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(read(t, configPath), "new@test.com") {
		t.Errorf("mailbox missing from config after -edit-only add")
	}
	if !strings.Contains(stderr.String(), "nothing applied") {
		t.Errorf("stderr = %s", stderr.String())
	}
}

func savePlan(t *testing.T, configPath string) string {
	t.Helper()
	var stdout bytes.Buffer
	if err := run([]string{"plan", "-json", "-config", configPath}, nil, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("plan: %v", err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, stdout.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
