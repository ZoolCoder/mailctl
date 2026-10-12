package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
)

// TestMain keeps every test away from the real Keychain and network: lookups
// miss, stores are unavailable, and doctor's provider checks pass offline.
func TestMain(m *testing.M) {
	keychainGet = func(string) (string, bool) { return "", false }
	keychainSet = func(string, string) error { return errors.New("keychain stubbed out") }
	keychainAvailable = func() bool { return false }
	verifyCloudflare = func(context.Context, config.Config, string) error { return nil }
	verifyPurelymail = func(context.Context, config.Config, string) error { return nil }
	lookupNS = func(context.Context, string) error { return nil }
	os.Exit(m.Run())
}

// stubKeychain replaces the Keychain with an in-memory map for one test.
func stubKeychain(t *testing.T, items map[string]string) {
	t.Helper()
	get, set, available := keychainGet, keychainSet, keychainAvailable
	keychainGet = func(account string) (string, bool) {
		value, ok := items[account]
		return value, ok
	}
	keychainSet = func(account, value string) error {
		items[account] = value
		return nil
	}
	keychainAvailable = func() bool { return true }
	credentialCache.Clear()
	t.Cleanup(func() {
		keychainGet, keychainSet, keychainAvailable = get, set, available
		credentialCache.Clear()
	})
}

func TestCredentialComesFromTheEnvironmentBeforeTheKeychain(t *testing.T) {
	stubKeychain(t, map[string]string{"PURELYMAIL_API_TOKEN": "from-keychain"})

	t.Setenv("PURELYMAIL_API_TOKEN", "")
	if value, source := lookupCredential("PURELYMAIL_API_TOKEN"); value != "from-keychain" || source != "keychain" {
		t.Errorf("unset env: got %q from %q, want the Keychain value", value, source)
	}
	t.Setenv("PURELYMAIL_API_TOKEN", "from-env")
	if value, source := lookupCredential("PURELYMAIL_API_TOKEN"); value != "from-env" || source != "env" {
		t.Errorf("set env: got %q from %q, want the environment value", value, source)
	}
	if value, source := lookupCredential("NOT_SET_ANYWHERE"); value != "" || source != "" {
		t.Errorf("missing: got %q from %q, want nothing", value, source)
	}
}

func TestConfigLookupOrder(t *testing.T) {
	work, xdg := t.TempDir(), t.TempDir()
	t.Chdir(work)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("MAILCTL_CONFIG", "")

	if _, source := resolveConfigPath(""); source != "" {
		t.Errorf("nothing present: source = %q, want none", source)
	}

	user := filepath.Join(xdg, "mailctl", "mailctl.yaml")
	writeFile(t, user, "version: 1\n")
	if path, source := resolveConfigPath(""); path != user || source != "user config" {
		t.Errorf("user config: got %s from %q", path, source)
	}

	writeFile(t, filepath.Join(work, "mailctl.yaml"), "version: 1\n")
	if path, source := resolveConfigPath(""); path != "mailctl.yaml" || source != "working directory" {
		t.Errorf("working directory: got %s from %q", path, source)
	}

	t.Setenv("MAILCTL_CONFIG", "/from/env.yaml")
	if path, source := resolveConfigPath(""); path != "/from/env.yaml" || source != "MAILCTL_CONFIG" {
		t.Errorf("MAILCTL_CONFIG: got %s from %q", path, source)
	}

	if path, source := resolveConfigPath("/explicit.yaml"); path != "/explicit.yaml" || source != "-config" {
		t.Errorf("-config: got %s from %q", path, source)
	}
}

func TestMissingConfigExplainsTheLookupOrder(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("MAILCTL_CONFIG", "")

	err := run([]string{"plan"}, nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "no config found") {
		t.Fatalf("err = %v, want the lookup order", err)
	}
}

func TestGeneratedCredentialsGoToTheKeychain(t *testing.T) {
	items := map[string]string{}
	stubKeychain(t, items)
	server := fakeServer(t)
	configPath := writeTestConfig(t, server.URL)
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-tok")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout, stderr strings.Builder
	if err := run([]string{"apply", "-config", configPath, "-yes"}, strings.NewReader(""), &stdout, &stderr); err != nil {
		t.Fatalf("run: %v\nstderr:\n%s", err, stderr.String())
	}

	credential := items["box@test.com"]
	if credential == "" {
		t.Fatalf("Keychain did not get the credential; items = %v", items)
	}
	if strings.Contains(stdout.String()+stderr.String(), credential) {
		t.Errorf("credential printed although the Keychain holds it")
	}
	if !strings.Contains(stderr.String(), "Stored 1 generated credential(s) in the Keychain") {
		t.Errorf("stderr should name where the credential went; got:\n%s", stderr.String())
	}
}

func TestAppPasswordAccountKeepsNamedCredentialsApart(t *testing.T) {
	if a, b := appPasswordAccount("box@test.com", "phone"), appPasswordAccount("box@test.com", "laptop"); a == b {
		t.Errorf("two named app credentials share the account %q", a)
	}
	if got := appPasswordAccount("box@test.com", ""); got != "box@test.com (app)" {
		t.Errorf("unnamed account = %q", got)
	}
}

func TestDoctorReportsCredentialSourcesWithoutValues(t *testing.T) {
	stubKeychain(t, map[string]string{"PURELYMAIL_API_TOKEN": "pm-secret"})
	configPath := writeTestConfig(t, "http://127.0.0.1:1")
	t.Setenv("CLOUDFLARE_API_TOKEN", "cf-secret")
	t.Setenv("PURELYMAIL_API_TOKEN", "")

	var stdout bytes.Buffer
	if err := run([]string{"doctor", "-json", "-config", configPath}, nil, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v\n%s", err, stdout.String())
	}
	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("not json: %v\n%s", err, stdout.String())
	}
	got := map[string]doctorCheck{}
	for _, c := range report.Checks {
		got[c.Name] = c
	}
	if c := got["CLOUDFLARE_API_TOKEN"]; c.Status != checkOK || c.Detail != "from env" {
		t.Errorf("cloudflare credential = %+v", c)
	}
	if c := got["PURELYMAIL_API_TOKEN"]; c.Status != checkOK || c.Detail != "from keychain" {
		t.Errorf("purelymail credential = %+v", c)
	}
	if strings.Contains(stdout.String(), "secret") {
		t.Errorf("doctor printed a credential value:\n%s", stdout.String())
	}
}

func TestDoctorFailsWithoutAToken(t *testing.T) {
	configPath := writeTestConfig(t, "http://127.0.0.1:1")
	t.Setenv("CLOUDFLARE_API_TOKEN", "")
	t.Setenv("PURELYMAIL_API_TOKEN", "pm-tok")

	var stdout bytes.Buffer
	err := run([]string{"doctor", "-config", configPath}, nil, &stdout, &bytes.Buffer{})
	if err == nil || !strings.Contains(stdout.String(), "fail  CLOUDFLARE_API_TOKEN") {
		t.Errorf("err = %v, want a failed CLOUDFLARE_API_TOKEN check; got:\n%s", err, stdout.String())
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
