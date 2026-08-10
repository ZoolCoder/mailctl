package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func env(pairs map[string]string) func(string) string {
	return func(name string) string { return pairs[name] }
}

const minimalConfig = `
version: 1
cloudflare:
  accountId: ${CF_ACCOUNT}
domains:
  - name: Example.com
    mail:
      provider: purelymail
    mailboxes:
      - address: Contact@Example.com
        passwordEnv: CONTACT_PASSWORD
`

func TestLoadExpandsEnvAndAppliesDefaults(t *testing.T) {
	path := writeConfig(t, minimalConfig)

	cfg, err := Load(path, env(map[string]string{"CF_ACCOUNT": "acc-123"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Cloudflare.AccountID != "acc-123" {
		t.Errorf("accountId = %q, want acc-123", cfg.Cloudflare.AccountID)
	}
	if cfg.Cloudflare.TTL != 1 {
		t.Errorf("ttl = %d, want default 1", cfg.Cloudflare.TTL)
	}
	if cfg.Cloudflare.BaseURL != DefaultCloudflareBaseURL {
		t.Errorf("baseUrl = %q, want %q", cfg.Cloudflare.BaseURL, DefaultCloudflareBaseURL)
	}

	domain := cfg.Domains[0]
	if domain.Name != "example.com" {
		t.Errorf("domain name = %q, want lowercased", domain.Name)
	}
	if domain.ZoneName != "example.com" {
		t.Errorf("zoneName = %q, want defaulted to domain name", domain.ZoneName)
	}
	if got := domain.Mail.Providers; len(got) != 1 || got[0] != "purelymail" {
		t.Errorf("providers = %v, want [purelymail]", got)
	}
	if got := domain.Mailboxes[0].Address; got != "contact@example.com" {
		t.Errorf("mailbox address = %q, want lowercased", got)
	}
	if got := domain.Mailboxes[0].LocalPart(); got != "contact" {
		t.Errorf("local part = %q, want contact", got)
	}
}

func TestLoadAcceptsProviderList(t *testing.T) {
	path := writeConfig(t, `
version: 1
domains:
  - name: example.com
    mail:
      provider: [cfrouting, cfsending]
`)

	cfg, err := Load(path, env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Domains[0].Mail.Providers
	if len(got) != 2 || got[0] != "cfrouting" || got[1] != "cfsending" {
		t.Errorf("providers = %v, want [cfrouting cfsending]", got)
	}
}

func TestLoadRejectsUnsetEnvVar(t *testing.T) {
	path := writeConfig(t, minimalConfig)

	_, err := Load(path, env(nil))
	if err == nil {
		t.Fatal("expected an error for the unset CF_ACCOUNT variable")
	}
	if !strings.Contains(err.Error(), "CF_ACCOUNT") {
		t.Errorf("error %q should name the missing variable", err)
	}
}

func TestExpandEnvIgnoresVarInComment(t *testing.T) {
	data := []byte("value: ok\n# use ${SOME_VAR} here\n")

	out, err := expandEnv(data, env(nil))
	if err != nil {
		t.Fatalf("expandEnv: %v, want no error since ${SOME_VAR} is only in a comment", err)
	}
	if !strings.Contains(string(out), "${SOME_VAR}") {
		t.Errorf("comment content should stay literal; got %q", out)
	}
}

func TestExpandEnvExpandsBeforeComment(t *testing.T) {
	data := []byte("value: ${REAL} # uses ${SOME_VAR} here\n")

	out, err := expandEnv(data, env(map[string]string{"REAL": "acc-1"}))
	if err != nil {
		t.Fatalf("expandEnv: %v", err)
	}
	if !strings.Contains(string(out), "acc-1") {
		t.Errorf("REAL should expand before the comment starts; got %q", out)
	}
	if !strings.Contains(string(out), "${SOME_VAR}") {
		t.Errorf("comment content should stay literal; got %q", out)
	}
}

func TestExpandEnvHashInsideQuotesIsNotComment(t *testing.T) {
	data := []byte(`value: "a#b ${VAR}"` + "\n")

	_, err := expandEnv(data, env(nil))
	if err == nil || !strings.Contains(err.Error(), "VAR") {
		t.Fatalf("err = %v, want a missing-VAR error; the quoted # must not start a comment", err)
	}
}

func TestLoadDefaultsDMARCPctTo100(t *testing.T) {
	path := writeConfig(t, `
version: 1
domains:
  - name: example.com
    mail:
      provider: purelymail
    mailboxes:
      - address: a@example.com
        passwordEnv: A_PASSWORD
    deliverability:
      dmarc:
        policy: quarantine
        rua: mailto:dmarc@example.com
`)

	cfg, err := Load(path, env(nil))
	if err != nil {
		t.Fatalf("Load: %v, want pct to default rather than being required", err)
	}
	if got := cfg.Domains[0].Deliverability.DMARC.Pct; got != 100 {
		t.Errorf("dmarc.pct = %d, want default 100", got)
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := writeConfig(t, "version: 2\ndomains: []\n")

	_, err := Load(path, env(nil))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err = %v, want a version error", err)
	}
}

func TestLoadRejectsTypoInMailMapping(t *testing.T) {
	path := writeConfig(t, `
version: 1
domains:
  - name: example.com
    mail:
      provider: purelymail
      setings:
        allowAccountReset: true
`)

	_, err := Load(path, env(nil))
	if err == nil {
		t.Fatal("expected an error for the unknown key mail.setings")
	}
	if !strings.Contains(err.Error(), "setings") {
		t.Errorf("error should name the offending key; got %q", err)
	}
	if !strings.Contains(err.Error(), "line 7") {
		t.Errorf("error should name the offending line; got %q", err)
	}
}

func TestLoadRejectsTypoInMailSettingsMapping(t *testing.T) {
	path := writeConfig(t, `
version: 1
domains:
  - name: example.com
    mail:
      provider: purelymail
      settings:
        allowAcountReset: true
`)

	_, err := Load(path, env(nil))
	if err == nil {
		t.Fatal("expected an error for the unknown key mail.settings.allowAcountReset")
	}
	if !strings.Contains(err.Error(), "allowAcountReset") {
		t.Errorf("error should name the offending key; got %q", err)
	}
	if !strings.Contains(err.Error(), "line 8") {
		t.Errorf("error should name the offending line; got %q", err)
	}
}

func TestLoadMS365Block(t *testing.T) {
	path := writeConfig(t, `
version: 1
cloudflare:
  accountId: acc
domains:
  - name: example.com
    zoneName: example.com
    mail:
      provider: ms365
      ms365:
        license: BUSINESS_BASIC
        usageLocation: DE
        dkimCnames:
          - selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft
          - selector2-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft
    mailboxes:
      - address: someone@example.com
        displayName: Some One
      - address: other@example.com
        license: BUSINESS_STANDARD
`)
	cfg, err := Load(path, env(map[string]string{"CF_ACCOUNT": "acc-123"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.Domains[0]
	if got.Mail.MS365 == nil {
		t.Fatal("Mail.MS365 is nil")
	}
	if got.Mail.MS365.License != "BUSINESS_BASIC" {
		t.Errorf("License = %q", got.Mail.MS365.License)
	}
	if got.Mail.MS365.UsageLocation != "DE" {
		t.Errorf("UsageLocation = %q", got.Mail.MS365.UsageLocation)
	}
	if len(got.Mail.MS365.DKIMCnames) != 2 {
		t.Fatalf("DKIMCnames = %v", got.Mail.MS365.DKIMCnames)
	}
	if got.Mailboxes[0].DisplayName != "Some One" {
		t.Errorf("DisplayName = %q", got.Mailboxes[0].DisplayName)
	}
	if got.Mailboxes[1].License != "BUSINESS_STANDARD" {
		t.Errorf("mailbox License = %q", got.Mailboxes[1].License)
	}
}

func TestUnknownMS365KeyReportsFieldAndLine(t *testing.T) {
	path := writeConfig(t, `
version: 1
cloudflare:
  accountId: acc
domains:
  - name: example.com
    zoneName: example.com
    mail:
      provider: ms365
      ms365:
        license: BUSINESS_BASIC
        licence: BUSINESS_BASIC
`)
	_, err := Load(path, env(nil))
	if err == nil {
		t.Fatal("want an error for the misspelled key")
	}
	for _, want := range []string{"licence", "line 12", "license"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %s", err, want)
		}
	}
}

func TestMS365BlockAbsentIsNil(t *testing.T) {
	path := writeConfig(t, `
version: 1
cloudflare:
  accountId: acc
domains:
  - name: example.com
    zoneName: example.com
    mail:
      provider: purelymail
`)
	cfg, err := Load(path, env(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Domains[0].Mail.MS365 != nil {
		t.Fatal("Mail.MS365 should be nil when the block is absent")
	}
}

func TestLoadRejectsMappingProvider(t *testing.T) {
	path := writeConfig(t, `
version: 1
domains:
  - name: example.com
    mail:
      provider:
        name: purelymail
`)

	_, err := Load(path, env(nil))
	if err == nil {
		t.Fatal("expected an error for a mapping-valued provider")
	}
	if !strings.Contains(err.Error(), "line 7") {
		t.Errorf("error should name the offending line; got %q", err)
	}
}
