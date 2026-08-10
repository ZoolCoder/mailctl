# mailctl Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone `mailctl` Go CLI that reconciles multi-domain email configuration (Purelymail mailboxes/aliases + Cloudflare DNS) from a YAML file with a plan/apply model.

**Architecture:** A config package parses YAML into a desired-state tree. A DNS provider (Cloudflare) and a mail provider (Purelymail) each read actual state and emit ordered `plan.Action` values carrying a `Do` closure. An engine concatenates DNS actions before mail actions and either renders them (`plan`) or executes them (`apply`). Providers register themselves in an init-time registry so the engine never branches on a provider name.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` (only non-stdlib dependency), stdlib `net/http`, `crypto/rand`, `net/http/httptest` for tests.

**Spec:** `docs/superpowers/specs/2026-08-07-mailctl-design.md`

**Scope:** This plan delivers a working tool at feature parity with the old `example/internal/mailsetup` plus multi-domain support, full Purelymail endpoint coverage, aliases, catch-all, recovery methods, prune, and generated passwords. Deliverability records (SPF merge, DMARC, MTA-STS, TLS-RPT, BIMI) and the MTA-STS Worker are plan 2. Cloudflare Email Routing/Sending providers, `audit`, `import`, and the convenience subcommands are plan 3.

## Global Constraints

- Module path: `github.com/zoolcoder/mailctl`. Repo root: `the repository root` (git repo already initialised, one commit `e36b8a9`).
- Go directive: `go 1.26`.
- Dependencies: `gopkg.in/yaml.v3` only. Everything else is standard library. Do not add a Cloudflare SDK, a CLI framework, or an assertion library.
- `cmd/mailctl/main.go` contains CLI parsing and wiring only. No business logic.
- Never write a password, API token, or app password to stdout or to any log line, at any verbosity.
- Every error message names the provider, the domain, and the specific object.
- Config validation errors are accumulated and returned together via `errors.Join`, never one-at-a-time.
- The tool is additive by default. Nothing provider-side is deleted unless `-prune` (mail objects) or `-replace-dns` (conflicting DNS) is passed.
- Before every commit: `gofmt -l .` prints nothing, `go vet ./...` passes, `go test ./...` passes.
- Commit style: conventional commits, imperative, lowercase, `<60` chars.
- No live API calls in the test suite. All HTTP tests use `httptest.Server`.

## Deviations from the spec (deliberate, carried through every task)

1. **`plan.Action` carries a `Do func(context.Context) error` closure** instead of the spec's `Provider.Apply(ctx, actions)` method. Providers build the closure when they build the action, so the engine executes any action from any provider uniformly and there is no second dispatch. `mail.Provider` therefore has no `Apply` method.
2. **`internal/engine`** is added to the package layout. The spec described the execution flow but assigned it to no package, and `cmd/` is specified as wiring-only.
3. **`internal/dns.Provider`** exposes `Zone`/`Records`/`Create`/`Delete` rather than `Apply`, for the same reason as (1).

## File structure

```
go.mod                              module + yaml.v3
cmd/mailctl/main.go                 flag parsing, provider blank-imports, exit codes
internal/config/config.go           YAML types, Mail.UnmarshalYAML, accessors
internal/config/load.go             file read, ${VAR} expansion, defaults, version gate
internal/config/validate.go         cross-field validation, errors.Join
internal/plan/action.go             Op, Action, Plan, Render
internal/secret/secret.go           password resolution, crypto/rand generation, reporting
internal/cfapi/client.go            Cloudflare v4 envelope, auth, error mapping
internal/cfapi/list.go              generic paginated List[T]
internal/dns/record.go              Record, Existing, Zone, Provider interface, conflict kinds
internal/dns/diff.go                desired-vs-actual diff producing plan.Actions
internal/dns/cloudflare/provider.go zone lookup + record CRUD
internal/mail/provider.go           Provider interface, State types, Options
internal/mail/registry.go           name -> Factory registry, Deps
internal/mail/purelymail/client.go  /api/v0 transport + envelope
internal/mail/purelymail/api.go     one method per endpoint
internal/mail/purelymail/provider.go DesiredDNS / Actual / Plan
internal/engine/engine.go           per-domain orchestration, DNS-before-mail ordering
```

---

### Task 1: Module bootstrap and config types

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Create: `internal/config/load.go`
- Test: `internal/config/load_test.go`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: nothing.
- Produces: `config.Config`, `config.Domain`, `config.Mailbox`, `config.Alias`, `config.CatchAll`, `config.Deliverability`, `config.Load(path string, getenv func(string) string) (Config, error)`. Every later task reads these types.

- [ ] **Step 1: Initialise the module and pin the one dependency**

```bash
cd the repository root
go mod init github.com/zoolcoder/mailctl
go get gopkg.in/yaml.v3@v3.0.1
```

Then confirm `go.mod` reads:

```
module github.com/zoolcoder/mailctl

go 1.26

require gopkg.in/yaml.v3 v3.0.1
```

- [ ] **Step 2: Add build artefacts and local config to `.gitignore`**

Append to `.gitignore`:

```
mailctl
mailctl.yaml
*.secrets
.env
```

`mailctl.yaml` is ignored because the real config names live mailboxes. A redacted `mailctl.example.yaml` is committed in Task 12.

- [ ] **Step 3: Write the failing test for loading, expansion, and defaults**

Create `internal/config/load_test.go`:

```go
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

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := writeConfig(t, "version: 2\ndomains: []\n")

	_, err := Load(path, env(nil))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err = %v, want a version error", err)
	}
}
```

- [ ] **Step 4: Run the test and confirm it fails to build**

Run: `go test ./internal/config/ -run TestLoad -v`
Expected: FAIL — `undefined: Load`, `undefined: DefaultCloudflareBaseURL`.

- [ ] **Step 5: Write the config types**

Create `internal/config/config.go`:

```go
// Package config defines the mailctl YAML schema and loads it into a desired-state tree.
package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only config schema version this build understands.
const SchemaVersion = 1

const (
	DefaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"
	DefaultPurelymailBaseURL = "https://purelymail.com"
	DefaultTTL               = 1
)

type Config struct {
	Version    int              `yaml:"version"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	Purelymail PurelymailConfig `yaml:"purelymail"`
	Domains    []Domain         `yaml:"domains"`
}

type CloudflareConfig struct {
	AccountID string `yaml:"accountId"`
	BaseURL   string `yaml:"baseUrl"`
	TTL       int    `yaml:"ttl"`
}

type PurelymailConfig struct {
	BaseURL string `yaml:"baseUrl"`
}

type Domain struct {
	Name           string         `yaml:"name"`
	ZoneName       string         `yaml:"zoneName"`
	Mail           Mail           `yaml:"mail"`
	Mailboxes      []Mailbox      `yaml:"mailboxes"`
	Aliases        []Alias        `yaml:"aliases"`
	CatchAll       *CatchAll      `yaml:"catchAll"`
	Deliverability Deliverability `yaml:"deliverability"`
}

// Mail holds the provider selection and provider-level domain settings.
// provider accepts either a scalar name or a list of names.
type Mail struct {
	Providers []string
	Settings  DomainSettings
}

func (m *Mail) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Provider yaml.Node      `yaml:"provider"`
		Settings DomainSettings `yaml:"settings"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	m.Settings = raw.Settings

	switch raw.Provider.Kind {
	case 0: // key absent
		return nil
	case yaml.ScalarNode:
		var name string
		if err := raw.Provider.Decode(&name); err != nil {
			return err
		}
		m.Providers = []string{name}
	case yaml.SequenceNode:
		return raw.Provider.Decode(&m.Providers)
	default:
		return fmt.Errorf("mail.provider must be a string or a list of strings")
	}
	return nil
}

type DomainSettings struct {
	AllowAccountReset     *bool `yaml:"allowAccountReset"`
	SymbolicSubaddressing *bool `yaml:"symbolicSubaddressing"`
}

type Mailbox struct {
	Address                        string     `yaml:"address"`
	PasswordEnv                    string     `yaml:"passwordEnv"`
	EnablePasswordReset            *bool      `yaml:"enablePasswordReset"`
	EnableSearchIndexing           *bool      `yaml:"enableSearchIndexing"`
	RequireTwoFactorAuthentication *bool      `yaml:"requireTwoFactorAuthentication"`
	SendWelcomeEmail               *bool      `yaml:"sendWelcomeEmail"`
	Recovery                       []Recovery `yaml:"recovery"`
}

// Recovery is one password-reset method attached to a mailbox.
type Recovery struct {
	Type          string `yaml:"type"` // email | phone
	Target        string `yaml:"target"`
	Description   string `yaml:"description"`
	AllowMfaReset bool   `yaml:"allowMfaReset"`
}

type Alias struct {
	Match string   `yaml:"match"`
	To    []string `yaml:"to"`
}

type CatchAll struct {
	To []string `yaml:"to"`
}

// Deliverability is consumed by plan 2. It is parsed here so that a config
// carrying these keys loads cleanly against this build.
type Deliverability struct {
	SPFIncludes []string `yaml:"spfIncludes"`
	DMARC       *DMARC   `yaml:"dmarc"`
	MTASts      *MTASts  `yaml:"mtaSts"`
	TLSRpt      string   `yaml:"tlsRpt"`
	BIMI        *BIMI    `yaml:"bimi"`
}

type DMARC struct {
	Policy          string `yaml:"policy"`
	SubdomainPolicy string `yaml:"subdomainPolicy"`
	Pct             int    `yaml:"pct"`
	RUA             string `yaml:"rua"`
	RUF             string `yaml:"ruf"`
}

type MTASts struct {
	Mode   string `yaml:"mode"`
	MaxAge int    `yaml:"maxAge"`
	Deploy bool   `yaml:"deploy"`
}

type BIMI struct {
	Logo string `yaml:"logo"`
	VMC  string `yaml:"vmc"`
}

// LocalPart returns the portion of the address before the @.
func (m Mailbox) LocalPart() string {
	local, _, _ := strings.Cut(m.Address, "@")
	return local
}

// Prefix reports whether the alias match is a prefix match (trailing *).
func (a Alias) Prefix() bool { return strings.HasSuffix(a.Match, "*") }

// MatchUser returns the alias local part with any trailing * removed.
func (a Alias) MatchUser() string { return strings.TrimSuffix(a.Match, "*") }

// Domain returns the domain with the given name, and whether it was found.
func (c Config) Domain(name string) (Domain, bool) {
	for _, d := range c.Domains {
		if strings.EqualFold(d.Name, name) {
			return d, true
		}
	}
	return Domain{}, false
}

// BoolOr resolves an optional YAML bool against a default.
func BoolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
```

- [ ] **Step 6: Write the loader**

Create `internal/config/load.go`:

```go
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads path, expands ${VAR} references using getenv, applies defaults,
// and validates the result. getenv may be nil, in which case os.Getenv is used.
func Load(path string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	expanded, err := expandEnv(data, getenv)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(string(expanded)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.Version != SchemaVersion {
		return Config{}, fmt.Errorf(
			"config %s declares version %d; this build understands version %d only",
			path, cfg.Version, SchemaVersion)
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s:\n%w", path, err)
	}
	return cfg, nil
}

// expandEnv replaces every ${VAR} with its value. An unset or empty variable
// is an error, never a silent empty string.
func expandEnv(data []byte, getenv func(string) string) ([]byte, error) {
	var missing []error
	seen := map[string]bool{}

	out := envRef.ReplaceAllFunc(data, func(match []byte) []byte {
		name := string(envRef.FindSubmatch(match)[1])
		value := getenv(name)
		if value == "" {
			if !seen[name] {
				seen[name] = true
				missing = append(missing,
					fmt.Errorf("environment variable %s is referenced in the config but is not set", name))
			}
			return match
		}
		return []byte(value)
	})

	return out, errors.Join(missing...)
}

func (c *Config) applyDefaults() {
	if c.Cloudflare.BaseURL == "" {
		c.Cloudflare.BaseURL = DefaultCloudflareBaseURL
	}
	if c.Cloudflare.TTL == 0 {
		c.Cloudflare.TTL = DefaultTTL
	}
	if c.Purelymail.BaseURL == "" {
		c.Purelymail.BaseURL = DefaultPurelymailBaseURL
	}

	for i := range c.Domains {
		d := &c.Domains[i]
		d.Name = strings.ToLower(strings.TrimSpace(d.Name))
		d.ZoneName = strings.ToLower(strings.TrimSpace(d.ZoneName))
		if d.ZoneName == "" {
			d.ZoneName = d.Name
		}
		for j := range d.Mailboxes {
			m := &d.Mailboxes[j]
			m.Address = strings.ToLower(strings.TrimSpace(m.Address))
			m.PasswordEnv = strings.TrimSpace(m.PasswordEnv)
			for k := range m.Recovery {
				m.Recovery[k].Type = strings.ToLower(strings.TrimSpace(m.Recovery[k].Type))
				m.Recovery[k].Target = strings.TrimSpace(m.Recovery[k].Target)
			}
		}
		for j := range d.Aliases {
			d.Aliases[j].Match = strings.ToLower(strings.TrimSpace(d.Aliases[j].Match))
			for k := range d.Aliases[j].To {
				d.Aliases[j].To[k] = strings.ToLower(strings.TrimSpace(d.Aliases[j].To[k]))
			}
		}
		if d.CatchAll != nil {
			for k := range d.CatchAll.To {
				d.CatchAll.To[k] = strings.ToLower(strings.TrimSpace(d.CatchAll.To[k]))
			}
		}
	}
}
```

- [ ] **Step 7: Add a temporary no-op validator so the package compiles**

Create `internal/config/validate.go` with only this, to be filled in by Task 2:

```go
package config

// Validate reports every problem with the config at once.
func (c Config) Validate() error { return nil }
```

- [ ] **Step 8: Run the tests and verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS for all four `TestLoad*` tests.

- [ ] **Step 9: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add go.mod go.sum .gitignore internal/config/config.go internal/config/load.go internal/config/load_test.go
git commit -m "feat(config): add yaml schema, env expansion, defaults"
```

---

### Task 2: Config validation

**Files:**
- Modify: `internal/config/validate.go` (replace the Task 1 stub entirely)
- Test: `internal/config/validate_test.go`

**Interfaces:**
- Consumes: every type from Task 1.
- Produces: `func (c Config) Validate() error`, and the exported set `config.MailboxlessProviders` naming providers that reject a `mailboxes:` block. `internal/engine` relies on validation having already run.

- [ ] **Step 1: Write the failing validation test**

Create `internal/config/validate_test.go`:

```go
package config

import (
	"strings"
	"testing"
)

func TestValidateCollectsEveryError(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "user@other.com"}, {Address: "not-an-email"}},
			Aliases:   []Alias{{Match: "info", To: nil}},
		}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"user@other.com", "not-an-email", "info"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestValidateRejectsDuplicateMailbox(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "a@example.com"}, {Address: "a@example.com"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate-mailbox error", err)
	}
}

func TestValidateRejectsMailboxesOnRoutingOnlyProvider(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"cfrouting"}},
			Mailboxes: []Mailbox{{Address: "a@example.com"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cfrouting") {
		t.Fatalf("err = %v, want an error naming cfrouting", err)
	}
}

func TestValidateDMARC(t *testing.T) {
	tests := []struct {
		name    string
		dmarc   DMARC
		wantErr string
	}{
		{"bad policy", DMARC{Policy: "drop", Pct: 100}, "policy"},
		{"pct too high", DMARC{Policy: "reject", Pct: 101}, "pct"},
		{"pct too low", DMARC{Policy: "reject", Pct: -1}, "pct"},
		{"valid", DMARC{Policy: "quarantine", Pct: 100, SubdomainPolicy: "reject"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dmarc := tt.dmarc
			cfg := Config{
				Version: SchemaVersion,
				Domains: []Domain{{
					Name:           "example.com",
					ZoneName:       "example.com",
					Mail:           Mail{Providers: []string{"purelymail"}},
					Mailboxes:      []Mailbox{{Address: "a@example.com"}},
					Deliverability: Deliverability{DMARC: &dmarc},
				}},
			}
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want mention of %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsUnknownProvider(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{"gmail"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "gmail") {
		t.Fatalf("err = %v, want an error naming the unknown provider", err)
	}
}
```

- [ ] **Step 2: Run the tests and confirm they fail**

Run: `go test ./internal/config/ -run TestValidate -v`
Expected: FAIL — the stub returns nil, so every test reports "expected validation errors".

- [ ] **Step 3: Implement validation**

Replace `internal/config/validate.go` in full:

```go
package config

import (
	"errors"
	"fmt"
	"strings"
)

// KnownProviders is every mail provider name the config accepts. Providers are
// registered at init time in internal/mail, but config must be able to reject a
// typo without importing that package, so the list is duplicated here
// deliberately and kept in sync by TestKnownProvidersMatchRegistry.
var KnownProviders = []string{"purelymail", "cfrouting", "cfsending"}

// MailboxlessProviders route mail but do not host it. A domain using only these
// providers may not declare mailboxes.
var MailboxlessProviders = []string{"cfrouting", "cfsending"}

var dmarcPolicies = []string{"none", "quarantine", "reject"}

var mtaStsModes = []string{"none", "testing", "enforce"}

func (c Config) Validate() error {
	var errs []error

	if len(c.Domains) == 0 {
		errs = append(errs, errors.New("at least one domain is required"))
	}

	seenDomains := map[string]bool{}
	for _, d := range c.Domains {
		if d.Name == "" {
			errs = append(errs, errors.New("every domain needs a name"))
			continue
		}
		if seenDomains[d.Name] {
			errs = append(errs, fmt.Errorf("domain %s is declared twice", d.Name))
		}
		seenDomains[d.Name] = true
		errs = append(errs, d.validate()...)
	}

	return errors.Join(errs...)
}

func (d Domain) validate() []error {
	var errs []error

	if len(d.Mail.Providers) == 0 {
		errs = append(errs, fmt.Errorf("domain %s: mail.provider is required", d.Name))
	}
	for _, name := range d.Mail.Providers {
		if !contains(KnownProviders, name) {
			errs = append(errs, fmt.Errorf(
				"domain %s: unknown mail provider %q; known providers are %s",
				d.Name, name, strings.Join(KnownProviders, ", ")))
		}
	}

	if len(d.Mailboxes) > 0 && d.onlyMailboxless() {
		errs = append(errs, fmt.Errorf(
			"domain %s: provider %s routes mail but does not host mailboxes; remove the mailboxes block",
			d.Name, strings.Join(d.Mail.Providers, "+")))
	}

	seenMailbox := map[string]bool{}
	for _, m := range d.Mailboxes {
		if err := checkAddress(d.Name, "mailbox", m.Address); err != nil {
			errs = append(errs, err)
			continue
		}
		if seenMailbox[m.Address] {
			errs = append(errs, fmt.Errorf("domain %s: duplicate mailbox %s", d.Name, m.Address))
		}
		seenMailbox[m.Address] = true
		errs = append(errs, m.validate(d.Name)...)
	}

	seenAlias := map[string]bool{}
	for _, a := range d.Aliases {
		if a.Match == "" {
			errs = append(errs, fmt.Errorf("domain %s: alias match is required", d.Name))
			continue
		}
		if strings.Contains(a.Match, "@") {
			errs = append(errs, fmt.Errorf(
				"domain %s: alias %q must be a local part, not a full address", d.Name, a.Match))
		}
		if seenAlias[a.Match] {
			errs = append(errs, fmt.Errorf("domain %s: duplicate alias %s", d.Name, a.Match))
		}
		seenAlias[a.Match] = true
		if len(a.To) == 0 {
			errs = append(errs, fmt.Errorf("domain %s: alias %s needs at least one to: address", d.Name, a.Match))
		}
		for _, target := range a.To {
			if !strings.Contains(target, "@") {
				errs = append(errs, fmt.Errorf(
					"domain %s: alias %s target %q is not an email address", d.Name, a.Match, target))
			}
		}
	}

	if d.CatchAll != nil && len(d.CatchAll.To) == 0 {
		errs = append(errs, fmt.Errorf(
			"domain %s: catchAll needs at least one to: address; omit the key entirely to leave the catch-all unmanaged",
			d.Name))
	}

	errs = append(errs, d.Deliverability.validate(d)...)
	return errs
}

func (m Mailbox) validate(domain string) []error {
	var errs []error
	for _, r := range m.Recovery {
		switch r.Type {
		case "email":
			if !strings.Contains(r.Target, "@") {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s recovery email %q is not an email address", domain, m.Address, r.Target))
			}
		case "phone":
			if r.Target == "" {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s recovery phone needs a target", domain, m.Address))
			}
		default:
			errs = append(errs, fmt.Errorf(
				"domain %s: mailbox %s recovery type %q must be email or phone", domain, m.Address, r.Type))
		}
	}
	return errs
}

func (v Deliverability) validate(d Domain) []error {
	var errs []error

	if v.DMARC != nil {
		if !contains(dmarcPolicies, v.DMARC.Policy) {
			errs = append(errs, fmt.Errorf(
				"domain %s: dmarc.policy %q must be one of %s",
				d.Name, v.DMARC.Policy, strings.Join(dmarcPolicies, ", ")))
		}
		if v.DMARC.SubdomainPolicy != "" && !contains(dmarcPolicies, v.DMARC.SubdomainPolicy) {
			errs = append(errs, fmt.Errorf(
				"domain %s: dmarc.subdomainPolicy %q must be one of %s",
				d.Name, v.DMARC.SubdomainPolicy, strings.Join(dmarcPolicies, ", ")))
		}
		if v.DMARC.Pct < 1 || v.DMARC.Pct > 100 {
			errs = append(errs, fmt.Errorf("domain %s: dmarc.pct %d must be between 1 and 100", d.Name, v.DMARC.Pct))
		}
	}

	if v.MTASts != nil {
		if !contains(mtaStsModes, v.MTASts.Mode) {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.mode %q must be one of %s",
				d.Name, v.MTASts.Mode, strings.Join(mtaStsModes, ", ")))
		}
		if v.MTASts.Mode == "enforce" && !d.publishesMX() {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.mode enforce requires a mail provider that publishes MX records; %s does not",
				d.Name, strings.Join(d.Mail.Providers, "+")))
		}
	}

	if v.BIMI != nil && v.BIMI.Logo == "" {
		errs = append(errs, fmt.Errorf("domain %s: bimi.logo is required when bimi is configured", d.Name))
	}

	return errs
}

// publishesMX reports whether any configured provider publishes inbound MX records.
// cfsending is outbound only.
func (d Domain) publishesMX() bool {
	for _, name := range d.Mail.Providers {
		if name != "cfsending" {
			return true
		}
	}
	return false
}

func (d Domain) onlyMailboxless() bool {
	for _, name := range d.Mail.Providers {
		if !contains(MailboxlessProviders, name) {
			return false
		}
	}
	return len(d.Mail.Providers) > 0
}

func checkAddress(domain, kind, address string) error {
	if address == "" {
		return fmt.Errorf("domain %s: %s address is required", domain, kind)
	}
	local, host, ok := strings.Cut(address, "@")
	if !ok || local == "" || host == "" {
		return fmt.Errorf("domain %s: %q is not a valid email address", domain, address)
	}
	if !strings.EqualFold(host, domain) {
		return fmt.Errorf("domain %s: %s %s must use domain %s", domain, kind, address, domain)
	}
	return nil
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS, including the Task 1 tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/config/validate.go internal/config/validate_test.go
git commit -m "feat(config): validate domains, mailboxes, aliases, deliverability"
```

---

### Task 3: Plan actions and rendering

**Files:**
- Create: `internal/plan/action.go`
- Test: `internal/plan/action_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `plan.Op` constants (`OpCreate`, `OpUpdate`, `OpDelete`, `OpManual`), `plan.Action{Op, Resource, Domain, Provider, Detail, Do}`, `plan.Plan`, `(*Plan).Add`, `(Plan).Render(io.Writer)`, `(Plan).Executable() []Action`, `(Plan).Destructive() []Action`. Every provider and the engine build `Action` values.

- [ ] **Step 1: Write the failing test**

Create `internal/plan/action_test.go`:

```go
package plan

import (
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
```

Add the shared helper at the bottom of the same file:

```go
func noop(_ context.Context) error { return nil }
```

and add `"context"` to the import block.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/plan/ -v`
Expected: FAIL — `undefined: Plan`.

- [ ] **Step 3: Implement the plan package**

Create `internal/plan/action.go`:

```go
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
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/plan/ -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/plan/
git commit -m "feat(plan): add action type and plan renderer"
```

---

### Task 4: Shared Cloudflare API client

**Files:**
- Create: `internal/cfapi/client.go`
- Create: `internal/cfapi/list.go`
- Test: `internal/cfapi/client_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `cfapi.New(baseURL, token string) *Client`, `(*Client).Do(ctx, method, path string, body, result any) error`, `(*Client).Multipart(ctx, method, path string, parts []Part, result any) error`, `cfapi.List[T any](ctx, c *Client, path string) ([]T, error)`, `cfapi.Part{Name, Filename, ContentType string, Data []byte}`. Used by `dns/cloudflare` (Task 6), and by `cfrouting`, `cfsending`, and `worker` in later plans.

- [ ] **Step 1: Write the failing transport test**

Create `internal/cfapi/client_test.go`:

```go
package cfapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestDoSendsBearerTokenAndDecodesResult(t *testing.T) {
	var gotAuth, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"z1","name":"a.com"}}`)
	}))
	defer server.Close()

	var got zone
	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones",
		map[string]any{"name": "a.com"}, &got)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if !strings.Contains(gotBody, `"name":"a.com"`) {
		t.Errorf("body = %q, want the marshalled payload", gotBody)
	}
	if got.ID != "z1" {
		t.Errorf("result id = %q, want z1", got.ID)
	}
}

func TestDoSurfacesCloudflareErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":81057,"message":"Record already exists."}]}`)
	}))
	defer server.Close()

	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones/z1/dns_records", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Record already exists.") || !strings.Contains(err.Error(), "81057") {
		t.Errorf("error should carry Cloudflare's own text and code; got %q", err)
	}
}

func TestListFollowsPagination(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		body := map[string]any{
			"success":     true,
			"errors":      []any{},
			"result":      []zone{{ID: "z" + page, Name: page + ".com"}},
			"result_info": map[string]int{"page": len(pages), "total_pages": 3},
		}
		json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	got, err := List[zone](context.Background(), New(server.URL, "tok"), "/zones")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d zones across pages, want 3", len(got))
	}
	if len(pages) != 3 || pages[0] != "1" || pages[2] != "3" {
		t.Errorf("requested pages = %v, want 1,2,3", pages)
	}
}

func TestListPreservesExistingQueryString(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	if _, err := List[zone](context.Background(), New(server.URL, "tok"), "/zones?name=a.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !strings.Contains(gotQuery, "name=a.com") || !strings.Contains(gotQuery, "page=1") {
		t.Errorf("query = %q, want both the caller filter and the page parameter", gotQuery)
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/cfapi/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 3: Implement the client**

Create `internal/cfapi/client.go`:

```go
// Package cfapi is the shared transport for every Cloudflare v4 API call
// mailctl makes: DNS, Email Routing, Email Sending, and Workers.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Messages   []apiMessage    `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo resultInfo      `json:"result_info"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

// Do performs one request. body is JSON-marshalled when non-nil; result is
// JSON-unmarshalled from the envelope's result field when non-nil.
func (c *Client) Do(ctx context.Context, method, path string, body, result any) error {
	var reader io.Reader
	var contentType string
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal Cloudflare %s %s request: %w", method, path, err)
		}
		reader = bytes.NewReader(payload)
		contentType = "application/json"
	}
	_, err := c.send(ctx, method, path, reader, contentType, result)
	return err
}

// Part is one section of a multipart upload, used for Worker script uploads.
type Part struct {
	Name        string
	Filename    string
	ContentType string
	Data        []byte
}

// Multipart performs a multipart/form-data request.
func (c *Client) Multipart(ctx context.Context, method, path string, parts []Part, result any) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for _, part := range parts {
		header := make(textproto.MIMEHeader)
		if part.Filename != "" {
			header.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name=%q; filename=%q`, part.Name, part.Filename))
		} else {
			header.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q`, part.Name))
		}
		if part.ContentType != "" {
			header.Set("Content-Type", part.ContentType)
		}
		field, err := writer.CreatePart(header)
		if err != nil {
			return fmt.Errorf("build Cloudflare multipart part %s: %w", part.Name, err)
		}
		if _, err := field.Write(part.Data); err != nil {
			return fmt.Errorf("write Cloudflare multipart part %s: %w", part.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close Cloudflare multipart body: %w", err)
	}

	_, err := c.send(ctx, method, path, &buf, writer.FormDataContentType(), result)
	return err
}

func (c *Client) send(ctx context.Context, method, path string, body io.Reader, contentType string, result any) (resultInfo, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return resultInfo{}, fmt.Errorf("build Cloudflare %s %s request: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return resultInfo{}, fmt.Errorf("Cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resultInfo{}, fmt.Errorf("read Cloudflare %s %s response: %w", method, path, err)
	}

	var env envelope
	decodeErr := json.Unmarshal(data, &env)

	// A non-2xx status with a parseable envelope still yields Cloudflare's own
	// message, which is more useful than the status line.
	if decodeErr != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resultInfo{}, fmt.Errorf("Cloudflare %s %s returned %s: %s",
				method, path, resp.Status, strings.TrimSpace(string(data)))
		}
		return resultInfo{}, fmt.Errorf("parse Cloudflare %s %s response: %w", method, path, decodeErr)
	}

	if !env.Success {
		return env.ResultInfo, fmt.Errorf("Cloudflare %s %s failed: %w", method, path, messagesError(env.Errors))
	}

	if result != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, result); err != nil {
			return env.ResultInfo, fmt.Errorf("parse Cloudflare %s %s result: %w", method, path, err)
		}
	}
	return env.ResultInfo, nil
}

func messagesError(messages []apiMessage) error {
	if len(messages) == 0 {
		return errors.New("no error detail returned")
	}
	parts := make([]string, 0, len(messages))
	for _, m := range messages {
		parts = append(parts, fmt.Sprintf("%d: %s", m.Code, m.Message))
	}
	return errors.New(strings.Join(parts, "; "))
}
```

- [ ] **Step 4: Implement paginated listing**

Create `internal/cfapi/list.go`:

```go
package cfapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const listPageSize = 100

// List fetches every page of a paginated collection endpoint. path may already
// carry a query string; page and per_page are appended to it.
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	for page := 1; ; page++ {
		var chunk []T
		paged := fmt.Sprintf("%s%spage=%d&per_page=%d", path, separator, page, listPageSize)
		info, err := c.send(ctx, http.MethodGet, paged, nil, "", &chunk)
		if err != nil {
			return nil, err
		}
		all = append(all, chunk...)
		if info.TotalPages <= 1 || page >= info.TotalPages {
			return all, nil
		}
	}
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/cfapi/ -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/cfapi/
git commit -m "feat(cfapi): add shared cloudflare v4 client with pagination"
```

---

### Task 5: Secret resolution and generation

**Files:**
- Create: `internal/secret/secret.go`
- Test: `internal/secret/secret_test.go`

**Interfaces:**
- Consumes: `config.Mailbox`.
- Produces: `secret.NewResolver(getenv func(string) string) *Resolver`, `(*Resolver).Password(domain string, m config.Mailbox) (string, error)`, `(*Resolver).Generated() map[string]string`, `secret.Generate(length int) (string, error)`, `secret.ReportTo(w io.Writer, generated map[string]string) error`, `secret.WriteFile(path string, generated map[string]string) error`. The Purelymail provider (Task 9) calls `Password`; `cmd` (Task 12) calls the reporting functions.

- [ ] **Step 1: Write the failing test**

Create `internal/secret/secret_test.go`:

```go
package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
)

func TestPasswordPrefersEnvVar(t *testing.T) {
	r := NewResolver(func(name string) string {
		if name == "BOX_PW" {
			return "from-env"
		}
		return ""
	})

	got, err := r.Password("a.com", config.Mailbox{Address: "box@a.com", PasswordEnv: "BOX_PW"})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if got != "from-env" {
		t.Errorf("secret = %q, want from-env", got)
	}
	if len(r.Generated()) != 0 {
		t.Errorf("nothing should be reported as generated; got %v", r.Generated())
	}
}

func TestPasswordFailsWhenNamedEnvVarIsEmpty(t *testing.T) {
	r := NewResolver(func(string) string { return "" })

	_, err := r.Password("a.com", config.Mailbox{Address: "box@a.com", PasswordEnv: "BOX_PW"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "BOX_PW") || !strings.Contains(err.Error(), "box@a.com") {
		t.Errorf("error should name the variable and the mailbox; got %q", err)
	}
}

func TestPasswordGeneratesWhenNoEnvVarConfigured(t *testing.T) {
	r := NewResolver(func(string) string { return "" })

	got, err := r.Password("a.com", config.Mailbox{Address: "box@a.com"})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if len(got) != GeneratedLength {
		t.Errorf("generated length = %d, want %d", len(got), GeneratedLength)
	}
	if r.Generated()["box@a.com"] != got {
		t.Errorf("generated value should be recorded for later reporting")
	}
}

func TestPasswordIsStableAcrossCallsForOneMailbox(t *testing.T) {
	r := NewResolver(func(string) string { return "" })
	m := config.Mailbox{Address: "box@a.com"}

	first, _ := r.Password("a.com", m)
	second, _ := r.Password("a.com", m)
	if first != second {
		t.Error("plan and apply must resolve the same mailbox to the same value")
	}
}

func TestGenerateProducesDistinctValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		value, err := Generate(GeneratedLength)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[value] {
			t.Fatalf("Generate returned a duplicate: %q", value)
		}
		seen[value] = true
	}
}

func TestWriteFileIsOwnerReadableOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.secrets")

	if err := WriteFile(path, map[string]string{"box@a.com": "value-1"}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "box@a.com") || !strings.Contains(string(body), "value-1") {
		t.Errorf("file should contain the address and its value; got %q", body)
	}
}

func TestReportToWritesNothingWhenNothingGenerated(t *testing.T) {
	var out strings.Builder
	if err := ReportTo(&out, nil); err != nil {
		t.Fatalf("ReportTo: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output; got %q", out.String())
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/secret/ -v`
Expected: FAIL — `undefined: NewResolver`.

- [ ] **Step 3: Implement the secret package**

Create `internal/secret/secret.go`:

```go
// Package secret resolves mailbox credentials and reports generated ones
// exactly once. Nothing in this package writes to stdout.
package secret

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
)

// GeneratedLength is the length of a generated credential.
const GeneratedLength = 24

// alphabet is 74 characters with no quote, backslash, or backtick, so a
// generated value pastes into a shell or a mail client without escaping.
const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%()*+,-.:;=?@[]^_"

// Resolver resolves one credential per mailbox and remembers what it generated.
type Resolver struct {
	getenv    func(string) string
	generated map[string]string
	cache     map[string]string
}

func NewResolver(getenv func(string) string) *Resolver {
	if getenv == nil {
		getenv = os.Getenv
	}
	return &Resolver{
		getenv:    getenv,
		generated: map[string]string{},
		cache:     map[string]string{},
	}
}

// Password returns the credential for a mailbox. A configured passwordEnv must
// be set and non-empty; with no passwordEnv a value is generated once and
// cached, so plan and apply agree within a single run.
func (r *Resolver) Password(domain string, m config.Mailbox) (string, error) {
	if cached, ok := r.cache[m.Address]; ok {
		return cached, nil
	}

	if m.PasswordEnv != "" {
		value := r.getenv(m.PasswordEnv)
		if value == "" {
			return "", fmt.Errorf(
				"domain %s: mailbox %s needs environment variable %s to be set",
				domain, m.Address, m.PasswordEnv)
		}
		r.cache[m.Address] = value
		return value, nil
	}

	value, err := Generate(GeneratedLength)
	if err != nil {
		return "", fmt.Errorf("domain %s: generate credential for %s: %w", domain, m.Address, err)
	}
	r.cache[m.Address] = value
	r.generated[m.Address] = value
	return value, nil
}

// Generated returns the credentials this resolver created, keyed by address.
func (r *Resolver) Generated() map[string]string {
	out := make(map[string]string, len(r.generated))
	for k, v := range r.generated {
		out[k] = v
	}
	return out
}

// Generate returns a cryptographically random string of the given length.
func Generate(length int) (string, error) {
	limit := big.NewInt(int64(len(alphabet)))
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

// ReportTo writes generated credentials under a delimited banner. Callers pass
// os.Stderr; stdout may be piped and must stay free of these values.
func ReportTo(w io.Writer, generated map[string]string) error {
	if len(generated) == 0 {
		return nil
	}

	const rule = "======================================================================"
	if _, err := fmt.Fprintf(w, "\n%s\nGENERATED CREDENTIALS - shown once, not stored anywhere\n%s\n", rule, rule); err != nil {
		return err
	}
	for _, address := range sortedKeys(generated) {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", address, generated[address]); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s\n\n", rule)
	return err
}

// WriteFile writes generated credentials to a new 0600 file, one
// address<TAB>value pair per line.
func WriteFile(path string, generated map[string]string) error {
	if len(generated) == 0 {
		return nil
	}
	var body strings.Builder
	for _, address := range sortedKeys(generated) {
		fmt.Fprintf(&body, "%s\t%s\n", address, generated[address])
	}
	if err := os.WriteFile(path, []byte(body.String()), 0o600); err != nil {
		return fmt.Errorf("write secrets file %s: %w", path, err)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/secret/ -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/secret/
git commit -m "feat(secret): resolve and generate mailbox credentials"
```

---

### Task 6: DNS records, the Cloudflare DNS provider, and the diff

**Files:**
- Create: `internal/dns/record.go`
- Create: `internal/dns/diff.go`
- Create: `internal/dns/cloudflare/provider.go`
- Test: `internal/dns/diff_test.go`
- Test: `internal/dns/cloudflare/provider_test.go`

**Interfaces:**
- Consumes: `cfapi.Client`, `cfapi.List`, `plan.Action`.
- Produces: `dns.Record{Type, Name, Content, TTL, Priority, Proxied, Kind}`, `dns.Existing{Record; ID string}`, `dns.Zone{ID, Name}`, the `dns.Provider` interface, kind constants (`dns.KindMX`, `KindSPF`, `KindDKIM`, `KindDMARC`, `KindOwnership`, `KindMTASts`, `KindTLSRpt`, `KindBIMI`, `KindOther`), `dns.Diff(p Provider, zoneID, domain string, actual []Existing, desired []Record, opts DiffOptions) ([]plan.Action, error)`, `dns.DiffOptions{ReplaceConflicts bool}`, `cloudflare.New(api *cfapi.Client, ttl int) *Provider`. Mail providers (Task 8) return `[]dns.Record` from `DesiredDNS`; the engine (Task 10) calls `Diff`.

- [ ] **Step 1: Write the failing diff test**

Create `internal/dns/diff_test.go`:

```go
package dns

import (
	"context"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/plan"
)

// fakeProvider records the calls Diff's action closures make.
type fakeProvider struct {
	created []Record
	deleted []string
}

func (f *fakeProvider) Zone(context.Context, string) (Zone, error) { return Zone{}, nil }
func (f *fakeProvider) Records(context.Context, string) ([]Existing, error) {
	return nil, nil
}
func (f *fakeProvider) Create(_ context.Context, _ string, r Record) error {
	f.created = append(f.created, r)
	return nil
}
func (f *fakeProvider) Delete(_ context.Context, _, id string) error {
	f.deleted = append(f.deleted, id)
	return nil
}

func mx(content string, priority int) Record {
	return Record{Type: "MX", Name: "a.com", Content: content, Priority: priority, TTL: 1, Kind: KindMX}
}

func TestDiffCreatesMissingRecord(t *testing.T) {
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", nil, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want one create", actions)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(provider.created) != 1 || provider.created[0].Content != "mailserver.purelymail.com" {
		t.Errorf("created = %+v, want the desired record", provider.created)
	}
}

func TestDiffIsSilentWhenConverged(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: mx("mailserver.purelymail.com", 50)}}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none", actions)
	}
}

func TestDiffIgnoresTrailingDotAndCase(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: Record{
		Type: "CNAME", Name: "PurelyMail1._domainkey.A.com", Content: "key1.dkimroot.purelymail.com.", TTL: 1,
	}}}
	desired := []Record{{
		Type: "CNAME", Name: "purelymail1._domainkey.a.com", Content: "key1.dkimroot.purelymail.com", TTL: 1, Kind: KindDKIM,
	}}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; comparison must ignore case and a trailing dot", actions)
	}
}

func TestDiffRefusesConflictWithoutReplaceFlag(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: mx("mail.oldhost.com", 10)}}

	_, err := Diff(&fakeProvider{}, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err == nil {
		t.Fatal("expected a conflict error")
	}
	if !strings.Contains(err.Error(), "-replace-dns") || !strings.Contains(err.Error(), "mail.oldhost.com") {
		t.Errorf("error should name the conflict and the flag; got %q", err)
	}
}

func TestDiffReplacesConflictWhenAllowed(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: mx("mail.oldhost.com", 10)}}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)},
		DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete then create", actions)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if len(provider.deleted) != 1 || provider.deleted[0] != "r1" {
		t.Errorf("deleted = %v, want [r1]", provider.deleted)
	}
	if len(provider.created) != 1 {
		t.Errorf("created = %+v, want the replacement", provider.created)
	}
}

func TestConflictRules(t *testing.T) {
	tests := []struct {
		name     string
		existing Record
		desired  Record
		conflict bool
	}{
		{"mx conflicts with any mx",
			Record{Type: "MX", Name: "a.com", Content: "other"},
			Record{Type: "MX", Name: "a.com", Kind: KindMX}, true},
		{"spf conflicts with another spf txt",
			Record{Type: "TXT", Name: "a.com", Content: "v=spf1 include:other ~all"},
			Record{Type: "TXT", Name: "a.com", Kind: KindSPF}, true},
		{"spf does not conflict with an unrelated txt",
			Record{Type: "TXT", Name: "a.com", Content: "google-site-verification=xyz"},
			Record{Type: "TXT", Name: "a.com", Kind: KindSPF}, false},
		{"ownership conflicts with nothing",
			Record{Type: "TXT", Name: "a.com", Content: "anything"},
			Record{Type: "TXT", Name: "a.com", Kind: KindOwnership}, false},
		{"dkim conflicts with anything on its own name",
			Record{Type: "A", Name: "purelymail1._domainkey.a.com", Content: "1.2.3.4"},
			Record{Type: "CNAME", Name: "purelymail1._domainkey.a.com", Kind: KindDKIM}, true},
		{"mta-sts txt conflicts with another sts policy id",
			Record{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=old"},
			Record{Type: "TXT", Name: "_mta-sts.a.com", Kind: KindMTASts}, true},
		{"tls-rpt conflicts with another tls-rpt",
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Content: "v=TLSRPTv1; rua=mailto:x@a.com"},
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Kind: KindTLSRpt}, true},
		{"bimi conflicts with another bimi",
			Record{Type: "TXT", Name: "default._bimi.a.com", Content: "v=BIMI1; l=https://old"},
			Record{Type: "TXT", Name: "default._bimi.a.com", Kind: KindBIMI}, true},
		{"unrelated name never conflicts",
			Record{Type: "MX", Name: "other.com", Content: "x"},
			Record{Type: "MX", Name: "a.com", Kind: KindMX}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conflicts(tt.existing, tt.desired); got != tt.conflict {
				t.Errorf("conflicts() = %v, want %v", got, tt.conflict)
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/dns/ -v`
Expected: FAIL — `undefined: Diff`, `undefined: Record`.

- [ ] **Step 3: Implement the record types and the provider interface**

Create `internal/dns/record.go`:

```go
// Package dns models the DNS records mailctl publishes and diffs them against
// what a zone already contains.
package dns

import (
	"context"
	"fmt"
	"strings"
)

// Kind identifies what role a record plays, which decides what already-present
// record counts as a conflict.
type Kind string

const (
	KindMX        Kind = "mx"
	KindSPF       Kind = "spf"
	KindDKIM      Kind = "dkim"
	KindDMARC     Kind = "dmarc"
	KindOwnership Kind = "ownership"
	KindMTASts    Kind = "mtasts"
	KindTLSRpt    Kind = "tlsrpt"
	KindBIMI      Kind = "bimi"
	KindOther     Kind = "other"
)

type Record struct {
	Type     string
	Name     string
	Content  string
	TTL      int
	Priority int
	Proxied  *bool
	Kind     Kind
}

// Existing is a record already published in a zone.
type Existing struct {
	Record
	ID string
}

type Zone struct {
	ID   string
	Name string
}

// Provider is a DNS zone mailctl can read and change.
type Provider interface {
	Zone(ctx context.Context, name string) (Zone, error)
	Records(ctx context.Context, zoneID string) ([]Existing, error)
	Create(ctx context.Context, zoneID string, r Record) error
	Delete(ctx context.Context, zoneID, recordID string) error
}

func (r Record) String() string {
	out := fmt.Sprintf("%s %s -> %s", r.Type, r.Name, r.Content)
	if r.Priority > 0 {
		out += fmt.Sprintf(" priority=%d", r.Priority)
	}
	return out
}

// same reports whether an existing record already satisfies a desired one.
// Comparison is case-insensitive and ignores the trailing dot Cloudflare adds
// to CNAME and MX targets.
func same(existing, desired Record) bool {
	if !strings.EqualFold(existing.Type, desired.Type) {
		return false
	}
	if !equalHost(existing.Name, desired.Name) {
		return false
	}
	if !equalHost(existing.Content, desired.Content) {
		return false
	}
	if desired.Priority > 0 && existing.Priority != desired.Priority {
		return false
	}
	return true
}

func equalHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// conflicts reports whether an existing record blocks a desired one. Only
// records on the same name can conflict.
func conflicts(existing, desired Record) bool {
	if !equalHost(existing.Name, desired.Name) {
		return false
	}
	content := strings.ToLower(strings.TrimSpace(existing.Content))
	isTXT := strings.EqualFold(existing.Type, "TXT")

	switch desired.Kind {
	case KindMX:
		return strings.EqualFold(existing.Type, "MX")
	case KindSPF:
		return isTXT && strings.HasPrefix(content, "v=spf1")
	case KindMTASts:
		return isTXT && strings.HasPrefix(content, "v=stsv1")
	case KindTLSRpt:
		return isTXT && strings.HasPrefix(content, "v=tlsrptv1")
	case KindBIMI:
		return isTXT && strings.HasPrefix(content, "v=bimi1")
	case KindOwnership:
		// Ownership TXT records sit alongside anything else on the apex.
		return false
	case KindDKIM, KindDMARC:
		// These live on names mailctl owns outright, so anything there is stale.
		return true
	default:
		return strings.EqualFold(existing.Type, desired.Type)
	}
}
```

- [ ] **Step 4: Implement the diff**

Create `internal/dns/diff.go`:

```go
package dns

import (
	"context"
	"fmt"

	"github.com/zoolcoder/mailctl/internal/plan"
)

type DiffOptions struct {
	// ReplaceConflicts deletes conflicting records instead of failing.
	ReplaceConflicts bool
}

// Diff returns the actions that bring a zone from actual to desired. It is
// additive: a record already in the zone that no desired record conflicts with
// is left untouched.
func Diff(p Provider, zoneID, domain string, actual []Existing, desired []Record, opts DiffOptions) ([]plan.Action, error) {
	var actions []plan.Action
	// A deletion planned for one desired record must not be planned again by a
	// later one, so track what is already scheduled to go.
	deleted := map[string]bool{}

	for _, want := range desired {
		if want.Content == "" {
			return nil, fmt.Errorf("domain %s: refusing to publish an empty %s record for %s",
				domain, want.Type, want.Name)
		}

		satisfied := false
		var blocking []Existing
		for _, have := range actual {
			if deleted[have.ID] {
				continue
			}
			if same(have.Record, want) {
				satisfied = true
				continue
			}
			if conflicts(have.Record, want) {
				blocking = append(blocking, have)
			}
		}
		if satisfied {
			continue
		}

		if len(blocking) > 0 && !opts.ReplaceConflicts {
			return nil, fmt.Errorf(
				"domain %s: %s already exists and does not match the desired %s record; rerun with -replace-dns to replace it",
				domain, blocking[0].Record.String(), want.Type)
		}

		for _, block := range blocking {
			block := block
			deleted[block.ID] = true
			actions = append(actions, plan.Action{
				Op:       plan.OpDelete,
				Resource: "dns",
				Domain:   domain,
				Provider: "cloudflare",
				Detail:   "conflicting " + block.Record.String(),
				Do: func(ctx context.Context) error {
					return p.Delete(ctx, zoneID, block.ID)
				},
			})
		}

		want := want
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "dns",
			Domain:   domain,
			Provider: "cloudflare",
			Detail:   want.String(),
			Do: func(ctx context.Context) error {
				return p.Create(ctx, zoneID, want)
			},
		})
	}

	return actions, nil
}
```

- [ ] **Step 5: Run the diff tests and verify they pass**

Run: `go test ./internal/dns/ -v`
Expected: PASS — 6 tests, including all nine `TestConflictRules` subtests.

- [ ] **Step 6: Write the failing Cloudflare provider test**

Create `internal/dns/cloudflare/provider_test.go`:

```go
package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestZoneLooksUpByName(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("name")
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1","name":"a.com"}],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	zone, err := New(cfapi.New(server.URL, "tok"), 1).Zone(context.Background(), "a.com")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}
	if gotQuery != "a.com" {
		t.Errorf("name filter = %q, want a.com", gotQuery)
	}
	if zone.ID != "z1" {
		t.Errorf("zone id = %q, want z1", zone.ID)
	}
}

func TestZoneNotFoundNamesTheZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	_, err := New(cfapi.New(server.URL, "tok"), 1).Zone(context.Background(), "missing.com")
	if err == nil || !strings.Contains(err.Error(), "missing.com") {
		t.Fatalf("err = %v, want an error naming the zone", err)
	}
}

func TestCreateSendsTTLAndPriority(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"r1"}}`)
	}))
	defer server.Close()

	record := dns.Record{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX}
	if err := New(cfapi.New(server.URL, "tok"), 1).Create(context.Background(), "z1", record); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if payload["type"] != "MX" || payload["content"] != "mailserver.purelymail.com" {
		t.Errorf("payload = %v, want the record fields", payload)
	}
	if payload["priority"].(float64) != 50 {
		t.Errorf("priority = %v, want 50", payload["priority"])
	}
	if payload["ttl"].(float64) != 1 {
		t.Errorf("ttl = %v, want the provider default 1", payload["ttl"])
	}
	if _, present := payload["proxied"]; present {
		t.Error("proxied must be omitted unless the record sets it")
	}
}

func TestCreateSendsProxiedWhenSet(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &payload)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"r1"}}`)
	}))
	defer server.Close()

	off := false
	record := dns.Record{Type: "CNAME", Name: "x.a.com", Content: "y.com", TTL: 300, Proxied: &off, Kind: dns.KindDKIM}
	if err := New(cfapi.New(server.URL, "tok"), 1).Create(context.Background(), "z1", record); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if payload["proxied"] != false {
		t.Errorf("proxied = %v, want false", payload["proxied"])
	}
	if payload["ttl"].(float64) != 300 {
		t.Errorf("ttl = %v, want the record's own 300", payload["ttl"])
	}
}

func TestRecordsMapsPriorityAndID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"r1","type":"MX","name":"a.com","content":"mx.a.com","ttl":1,"priority":10,"proxied":false}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	got, err := New(cfapi.New(server.URL, "tok"), 1).Records(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].ID != "r1" || got[0].Priority != 10 || got[0].Type != "MX" {
		t.Errorf("record = %+v, want the mapped fields", got[0])
	}
}
```

- [ ] **Step 7: Run it and confirm it fails**

Run: `go test ./internal/dns/cloudflare/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 8: Implement the Cloudflare DNS provider**

Create `internal/dns/cloudflare/provider.go`:

```go
// Package cloudflare implements dns.Provider against the Cloudflare v4 API.
package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/dns"
)

type Provider struct {
	api *cfapi.Client
	ttl int
}

// New returns a provider. ttl is the fallback for records that do not set their
// own; 1 means "automatic" to Cloudflare.
func New(api *cfapi.Client, ttl int) *Provider {
	if ttl == 0 {
		ttl = 1
	}
	return &Provider{api: api, ttl: ttl}
}

var _ dns.Provider = (*Provider)(nil)

type apiZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type apiRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Proxied  bool   `json:"proxied"`
}

func (p *Provider) Zone(ctx context.Context, name string) (dns.Zone, error) {
	query := url.Values{}
	query.Set("name", name)

	zones, err := cfapi.List[apiZone](ctx, p.api, "/zones?"+query.Encode())
	if err != nil {
		return dns.Zone{}, fmt.Errorf("look up Cloudflare zone %s: %w", name, err)
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, name) {
			return dns.Zone{ID: z.ID, Name: z.Name}, nil
		}
	}
	return dns.Zone{}, fmt.Errorf(
		"Cloudflare zone %s was not found; check the zone name and that the API token can read it", name)
}

func (p *Provider) Records(ctx context.Context, zoneID string) ([]dns.Existing, error) {
	records, err := cfapi.List[apiRecord](ctx, p.api, "/zones/"+zoneID+"/dns_records")
	if err != nil {
		return nil, fmt.Errorf("list Cloudflare DNS records for zone %s: %w", zoneID, err)
	}

	out := make([]dns.Existing, 0, len(records))
	for _, r := range records {
		proxied := r.Proxied
		out = append(out, dns.Existing{
			ID: r.ID,
			Record: dns.Record{
				Type:     r.Type,
				Name:     r.Name,
				Content:  r.Content,
				TTL:      r.TTL,
				Priority: r.Priority,
				Proxied:  &proxied,
				Kind:     dns.KindOther,
			},
		})
	}
	return out, nil
}

func (p *Provider) Create(ctx context.Context, zoneID string, r dns.Record) error {
	ttl := r.TTL
	if ttl == 0 {
		ttl = p.ttl
	}
	payload := map[string]any{
		"type":    r.Type,
		"name":    r.Name,
		"content": r.Content,
		"ttl":     ttl,
	}
	if r.Priority > 0 {
		payload["priority"] = r.Priority
	}
	if r.Proxied != nil {
		payload["proxied"] = *r.Proxied
	}

	if err := p.api.Do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", payload, nil); err != nil {
		return fmt.Errorf("create DNS record %s: %w", r.String(), err)
	}
	return nil
}

func (p *Provider) Delete(ctx context.Context, zoneID, recordID string) error {
	if err := p.api.Do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil); err != nil {
		return fmt.Errorf("delete DNS record %s: %w", recordID, err)
	}
	return nil
}
```

- [ ] **Step 9: Run all DNS tests and verify they pass**

Run: `go test ./internal/dns/... -v`
Expected: PASS for both packages.

- [ ] **Step 10: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/dns/
git commit -m "feat(dns): add record diff and cloudflare dns provider"
```

---

### Task 7: Mail provider interface and registry

**Files:**
- Create: `internal/mail/provider.go`
- Create: `internal/mail/registry.go`
- Test: `internal/mail/registry_test.go`

**Interfaces:**
- Consumes: `config.Domain`, `dns.Record`, `plan.Action`, `secret.Resolver`.
- Produces: `mail.Provider` interface, `mail.State`, `mail.Mailbox`, `mail.Alias`, `mail.CatchAll`, `mail.Recovery`, `mail.Options{Prune bool, Secrets *secret.Resolver}`, `mail.Deps{Cloudflare *cfapi.Client, AccountID string, PurelymailBaseURL string, Getenv func(string) string}`, `mail.Register(name string, f Factory)`, `mail.Open(name string, deps Deps) (Provider, error)`, `mail.Registered() []string`. Task 9's provider registers itself here; Task 10's engine calls `Open`.

- [ ] **Step 1: Write the failing registry test**

Create `internal/mail/registry_test.go`:

```go
package mail

import (
	"context"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) DesiredDNS(context.Context, config.Domain) ([]dns.Record, error) {
	return nil, nil
}
func (s stubProvider) Actual(context.Context, config.Domain) (State, error) { return State{}, nil }
func (s stubProvider) Plan(config.Domain, State, Options) ([]plan.Action, error) {
	return nil, nil
}

func TestOpenReturnsRegisteredProvider(t *testing.T) {
	Register("stub", func(Deps) (Provider, error) { return stubProvider{name: "stub"}, nil })
	t.Cleanup(func() { unregister("stub") })

	got, err := Open("stub", Deps{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Name() != "stub" {
		t.Errorf("Name() = %q, want stub", got.Name())
	}
}

func TestOpenUnknownProviderListsWhatIsAvailable(t *testing.T) {
	Register("stub", func(Deps) (Provider, error) { return stubProvider{name: "stub"}, nil })
	t.Cleanup(func() { unregister("stub") })

	_, err := Open("nope", Deps{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "nope") || !strings.Contains(err.Error(), "stub") {
		t.Errorf("error should name the unknown provider and the known ones; got %q", err)
	}
}

func TestKnownProvidersMatchRegistry(t *testing.T) {
	// config.KnownProviders is a hand-maintained copy of the registry so that
	// config validation does not import this package. This test keeps them
	// honest. Every registered provider must appear in config.KnownProviders.
	for _, name := range Registered() {
		found := false
		for _, known := range config.KnownProviders {
			if known == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %q is registered but missing from config.KnownProviders", name)
		}
	}
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/mail/ -v`
Expected: FAIL — `undefined: Register`.

- [ ] **Step 3: Define the provider interface and state types**

Create `internal/mail/provider.go`:

```go
// Package mail defines the interface every mail provider implements and the
// vocabulary the engine uses to talk about provider-side state.
package mail

import (
	"context"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

// Provider is one mail service managing one or more domains.
type Provider interface {
	Name() string

	// DesiredDNS returns the records this provider needs published for the
	// domain. Providers that expose a DNS endpoint fetch them; providers that
	// do not construct them.
	DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error)

	// Actual reads current provider-side state for the domain.
	Actual(ctx context.Context, d config.Domain) (State, error)

	// Plan diffs the config against actual and returns ordered actions. Plan
	// performs no I/O; the returned actions carry closures that do.
	Plan(d config.Domain, actual State, opts Options) ([]plan.Action, error)
}

// State is provider-side reality for one domain.
type State struct {
	DomainExists bool
	Settings     Settings
	Mailboxes    []Mailbox
	Aliases      []Alias
	CatchAll     *CatchAll
	// Notes are provider observations worth showing in plan output, such as
	// "DNS check: mx=true spf=false".
	Notes []string
}

type Settings struct {
	AllowAccountReset     bool
	SymbolicSubaddressing bool
}

type Mailbox struct {
	Address  string
	Recovery []Recovery
}

type Recovery struct {
	ID          string
	Type        string // email | phone
	Target      string
	Description string
}

type Alias struct {
	ID     string
	Match  string // local part, without any trailing *
	Prefix bool
	To     []string
}

type CatchAll struct {
	ID string
	To []string
}

// Options are the flags that change what Plan produces.
type Options struct {
	// Prune plans deletion of provider-side objects absent from the config.
	Prune bool
	// Secrets resolves mailbox credentials.
	Secrets *secret.Resolver
}

// Mailbox returns the state entry for an address, and whether it exists.
func (s State) Mailbox(address string) (Mailbox, bool) {
	for _, m := range s.Mailboxes {
		if equalFold(m.Address, address) {
			return m, true
		}
	}
	return Mailbox{}, false
}

// Alias returns the state entry matching a local part and prefix flag.
func (s State) Alias(match string, prefix bool) (Alias, bool) {
	for _, a := range s.Aliases {
		if equalFold(a.Match, match) && a.Prefix == prefix {
			return a, true
		}
	}
	return Alias{}, false
}
```

Add the small helper at the bottom of the same file and import `"strings"`:

```go
func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
```

- [ ] **Step 4: Implement the registry**

Create `internal/mail/registry.go`:

```go
package mail

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

// Deps is everything a provider factory may need. A factory takes only what it
// uses; adding a field here does not change existing providers.
type Deps struct {
	Cloudflare        *cfapi.Client
	AccountID         string
	PurelymailBaseURL string
	Getenv            func(string) string
}

type Factory func(Deps) (Provider, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a provider factory. Providers call this from an init function
// and are pulled in by a blank import in cmd/mailctl, so the engine never
// imports a provider package directly.
func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("mail: provider " + name + " registered twice")
	}
	registry[name] = f
}

// unregister exists for tests.
func unregister(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, name)
}

// Open builds the named provider.
func Open(name string, deps Deps) (Provider, error) {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown mail provider %q; available providers are %s",
			name, strings.Join(Registered(), ", "))
	}
	provider, err := factory(deps)
	if err != nil {
		return nil, fmt.Errorf("open mail provider %s: %w", name, err)
	}
	return provider, nil
}

// Registered returns every registered provider name, sorted.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/mail/ -v`
Expected: PASS (3 tests). `TestKnownProvidersMatchRegistry` passes trivially here because no real provider is imported by this package's tests; it becomes meaningful once Task 8 registers `purelymail` and a test in that package exercises it.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/provider.go internal/mail/registry.go internal/mail/registry_test.go
git commit -m "feat(mail): add provider interface and registry"
```

---

### Task 8: Purelymail API client

**Files:**
- Create: `internal/mail/purelymail/client.go`
- Create: `internal/mail/purelymail/api.go`
- Test: `internal/mail/purelymail/client_test.go`

**Interfaces:**
- Consumes: nothing outside stdlib.
- Produces: `purelymail.NewClient(baseURL, token string) *Client` plus one method per endpoint: `GetOwnershipCode`, `ListDomains`, `AddDomain`, `DeleteDomain`, `UpdateDomainSettings`, `ListUsers`, `GetUser`, `CreateUser`, `ModifyUser`, `DeleteUser`, `ListPasswordReset`, `UpsertPasswordReset`, `DeletePasswordReset`, `ListRoutingRules`, `CreateRoutingRule`, `DeleteRoutingRule`, `CreateAppPassword`, `DeleteAppPassword`, `CheckAccountCredit`. Types `purelymail.Domain`, `DNSSummary`, `User`, `ResetMethod`, `RoutingRule`, `NewUser`, `UserChanges`. Task 9 consumes all of it.

**Critical API behaviour:** Purelymail returns HTTP 200 with `{"type":"error","code":...,"message":...}` in the body on failure. Status code alone is not a success signal. Every call is a POST to `/api/v0/<endpoint>` with the token in the `Purelymail-Api-Token` header.

- [ ] **Step 1: Write the failing transport test**

Create `internal/mail/purelymail/client_test.go`:

```go
package purelymail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recorder captures the last request and replies with a canned body.
type recorder struct {
	path    string
	body    map[string]any
	headers http.Header
}

func serve(t *testing.T, rec *recorder, response string) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rec.path = r.URL.Path
		rec.headers = r.Header.Clone()
		rec.body = map[string]any{}
		json.Unmarshal(raw, &rec.body)
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "tok")
}

func TestPostSendsTokenHeaderAndPath(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`)

	got, err := client.GetOwnershipCode(context.Background())
	if err != nil {
		t.Fatalf("GetOwnershipCode: %v", err)
	}

	if rec.path != "/api/v0/getOwnershipCode" {
		t.Errorf("path = %q, want /api/v0/getOwnershipCode", rec.path)
	}
	if rec.headers.Get("Purelymail-Api-Token") != "tok" {
		t.Errorf("token header = %q, want tok", rec.headers.Get("Purelymail-Api-Token"))
	}
	if got != "purelymail_ownership_proof=abc" {
		t.Errorf("code = %q, want the ownership proof", got)
	}
}

func TestErrorBodyWithHTTP200IsAnError(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"error","code":"INVALID_DOMAIN","message":"Domain not found."}`)

	err := client.AddDomain(context.Background(), "a.com")
	if err == nil {
		t.Fatal("a 200 response carrying an error body must be an error")
	}
	if !strings.Contains(err.Error(), "INVALID_DOMAIN") || !strings.Contains(err.Error(), "Domain not found.") {
		t.Errorf("error should carry Purelymail's own code and message; got %q", err)
	}
}

func TestListDomainsDecodesDNSSummary(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"domains":[
		{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,"isShared":false,
		 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":false,"passesDmarc":false}}
	]}}`)

	domains, err := client.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(domains) != 1 {
		t.Fatalf("got %d domains, want 1", len(domains))
	}
	if !domains[0].DNSSummary.PassesMX || domains[0].DNSSummary.PassesDKIM {
		t.Errorf("dnsSummary = %+v, want mx true and dkim false", domains[0].DNSSummary)
	}
	if rec.body["includeShared"] != false {
		t.Errorf("includeShared = %v, want false", rec.body["includeShared"])
	}
}

func TestCreateUserSendsEveryField(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.CreateUser(context.Background(), NewUser{
		UserName:             "contact",
		DomainName:           "a.com",
		Password:             "value-1",
		EnablePasswordReset:  true,
		EnableSearchIndexing: true,
		SendWelcomeEmail:     false,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if rec.path != "/api/v0/createUser" {
		t.Errorf("path = %q, want /api/v0/createUser", rec.path)
	}
	for key, want := range map[string]any{
		"userName":             "contact",
		"domainName":           "a.com",
		"enablePasswordReset":  true,
		"enableSearchIndexing": true,
		"sendWelcomeEmail":     false,
	} {
		if rec.body[key] != want {
			t.Errorf("body[%q] = %v, want %v", key, rec.body[key], want)
		}
	}
	if _, present := rec.body["password"]; !present {
		t.Error("createUser must send the credential field")
	}
}

func TestCreateRoutingRuleMapsPrefixAndCatchAll(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.CreateRoutingRule(context.Background(), RoutingRule{
		DomainName:      "a.com",
		MatchUser:       "info",
		Prefix:          true,
		TargetAddresses: []string{"contact@a.com"},
		Catchall:        false,
	})
	if err != nil {
		t.Fatalf("CreateRoutingRule: %v", err)
	}

	if rec.body["matchUser"] != "info" || rec.body["prefix"] != true || rec.body["catchall"] != false {
		t.Errorf("body = %v, want the mapped rule fields", rec.body)
	}
	targets, _ := rec.body["targetAddresses"].([]any)
	if len(targets) != 1 || targets[0] != "contact@a.com" {
		t.Errorf("targetAddresses = %v, want [contact@a.com]", rec.body["targetAddresses"])
	}
}

func TestListRoutingRulesDecodesIDs(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":{"rules":[
		{"id":7,"domainName":"a.com","matchUser":"info","prefix":false,"targetAddresses":["contact@a.com"],"catchall":false},
		{"id":8,"domainName":"a.com","matchUser":"","prefix":false,"targetAddresses":["contact@a.com"],"catchall":true}
	]}}`)

	rules, err := client.ListRoutingRules(context.Background())
	if err != nil {
		t.Fatalf("ListRoutingRules: %v", err)
	}
	if len(rules) != 2 || rules[0].ID != 7 || !rules[1].Catchall {
		t.Errorf("rules = %+v, want the two decoded rules", rules)
	}
}

func TestDeleteRoutingRuleSendsID(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	if err := client.DeleteRoutingRule(context.Background(), 7); err != nil {
		t.Fatalf("DeleteRoutingRule: %v", err)
	}
	if rec.body["routingRuleId"].(float64) != 7 {
		t.Errorf("routingRuleId = %v, want 7", rec.body["routingRuleId"])
	}
}

func TestUpsertPasswordResetSendsMethod(t *testing.T) {
	rec := &recorder{}
	client := serve(t, rec, `{"type":"success","result":null}`)

	err := client.UpsertPasswordReset(context.Background(), "box@a.com", ResetMethod{
		Type:        "email",
		Target:      "fallback@example.com",
		Description: "personal",
	})
	if err != nil {
		t.Fatalf("UpsertPasswordReset: %v", err)
	}
	if rec.path != "/api/v0/upsertPasswordReset" {
		t.Errorf("path = %q, want /api/v0/upsertPasswordReset", rec.path)
	}
	if rec.body["userName"] != "box@a.com" || rec.body["type"] != "email" ||
		rec.body["target"] != "fallback@example.com" {
		t.Errorf("body = %v, want the method fields", rec.body)
	}
}

func TestNetworkFailureNamesTheEndpoint(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "tok")

	err := client.AddDomain(context.Background(), "a.com")
	if err == nil || !strings.Contains(err.Error(), "addDomain") {
		t.Fatalf("err = %v, want an error naming the endpoint", err)
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/mail/purelymail/ -v`
Expected: FAIL — `undefined: NewClient`.

- [ ] **Step 3: Implement the transport**

Create `internal/mail/purelymail/client.go`:

```go
// Package purelymail talks to the Purelymail /api/v0 JSON API and implements
// mail.Provider on top of it.
package purelymail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public API host.
const DefaultBaseURL = "https://purelymail.com"

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

type envelope struct {
	Type    string          `json:"type"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// post calls one endpoint. Purelymail answers HTTP 200 even for failures, with
// type "error" in the body, so the body is always what decides success.
func (c *Client) post(ctx context.Context, endpoint string, body, result any) error {
	if body == nil {
		body = map[string]any{}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal Purelymail %s request: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v0/"+endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build Purelymail %s request: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Purelymail-Api-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Purelymail %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read Purelymail %s response: %w", endpoint, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("Purelymail %s returned %s with an unparseable body: %s",
			endpoint, resp.Status, strings.TrimSpace(string(data)))
	}

	if env.Type == "error" || env.Code != "" {
		return fmt.Errorf("Purelymail %s failed: %s %s", endpoint, env.Code, env.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Purelymail %s returned %s: %s",
			endpoint, resp.Status, strings.TrimSpace(string(data)))
	}

	if result == nil {
		return nil
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return fmt.Errorf("Purelymail %s returned no result", endpoint)
	}
	if err := json.Unmarshal(env.Result, result); err != nil {
		return fmt.Errorf("parse Purelymail %s result: %w", endpoint, err)
	}
	return nil
}
```

- [ ] **Step 4: Implement one method per endpoint**

Create `internal/mail/purelymail/api.go`:

```go
package purelymail

import "context"

type Domain struct {
	Name                  string     `json:"name"`
	AllowAccountReset     bool       `json:"allowAccountReset"`
	SymbolicSubaddressing bool       `json:"symbolicSubaddressing"`
	IsShared              bool       `json:"isShared"`
	DNSSummary            DNSSummary `json:"dnsSummary"`
}

type DNSSummary struct {
	PassesMX    bool `json:"passesMx"`
	PassesSPF   bool `json:"passesSpf"`
	PassesDKIM  bool `json:"passesDkim"`
	PassesDMARC bool `json:"passesDmarc"`
}

// NewUser is the createUser request. Every field is sent, matching the field
// set the previous mailsetup tool used successfully against the live API; the
// published OpenAPI description of this endpoint is incomplete.
type NewUser struct {
	UserName                 string `json:"userName"`
	DomainName               string `json:"domainName"`
	Password                 string `json:"password"`
	EnablePasswordReset      bool   `json:"enablePasswordReset"`
	EnableSearchIndexing     bool   `json:"enableSearchIndexing"`
	SendWelcomeEmail         bool   `json:"sendWelcomeEmail"`
	RecoveryEmail            string `json:"recoveryEmail,omitempty"`
	RecoveryEmailDescription string `json:"recoveryEmailDescription,omitempty"`
	RecoveryPhone            string `json:"recoveryPhone,omitempty"`
	RecoveryPhoneDescription string `json:"recoveryPhoneDescription,omitempty"`
}

// UserChanges is the modifyUser request. Pointer fields are omitted when nil so
// a change to one setting never resets another.
type UserChanges struct {
	UserName                       string  `json:"userName"`
	NewPassword                    *string `json:"newPassword,omitempty"`
	EnablePasswordReset            *bool   `json:"enablePasswordReset,omitempty"`
	EnableSearchIndexing           *bool   `json:"enableSearchIndexing,omitempty"`
	RequireTwoFactorAuthentication *bool   `json:"requireTwoFactorAuthentication,omitempty"`
}

type ResetMethod struct {
	ID          string `json:"id,omitempty"`
	Type        string `json:"type"`
	Target      string `json:"target"`
	Description string `json:"description,omitempty"`
}

type RoutingRule struct {
	ID              int      `json:"id,omitempty"`
	DomainName      string   `json:"domainName"`
	MatchUser       string   `json:"matchUser"`
	Prefix          bool     `json:"prefix"`
	TargetAddresses []string `json:"targetAddresses"`
	Catchall        bool     `json:"catchall"`
}

// GetOwnershipCode returns the TXT value proving domain ownership.
func (c *Client) GetOwnershipCode(ctx context.Context) (string, error) {
	var out struct {
		Code string `json:"code"`
	}
	if err := c.post(ctx, "getOwnershipCode", nil, &out); err != nil {
		return "", err
	}
	return out.Code, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var out struct {
		Domains []Domain `json:"domains"`
	}
	if err := c.post(ctx, "listDomains", map[string]any{"includeShared": false}, &out); err != nil {
		return nil, err
	}
	return out.Domains, nil
}

func (c *Client) AddDomain(ctx context.Context, domain string) error {
	return c.post(ctx, "addDomain", map[string]any{"domainName": domain}, nil)
}

func (c *Client) DeleteDomain(ctx context.Context, domain string) error {
	return c.post(ctx, "deleteDomain", map[string]any{"name": domain}, nil)
}

// UpdateDomainSettings changes domain-level settings. Pass recheckDNS to make
// Purelymail re-read the zone after records have been published.
func (c *Client) UpdateDomainSettings(ctx context.Context, domain string, allowReset, symbolic *bool, recheckDNS bool) error {
	body := map[string]any{"name": domain}
	if allowReset != nil {
		body["allowAccountReset"] = *allowReset
	}
	if symbolic != nil {
		body["symbolicSubaddressing"] = *symbolic
	}
	if recheckDNS {
		body["recheckDns"] = true
	}
	return c.post(ctx, "updateDomainSettings", body, nil)
}

// ListUsers returns every mailbox address on the account.
func (c *Client) ListUsers(ctx context.Context) ([]string, error) {
	var out struct {
		Users []string `json:"users"`
	}
	if err := c.post(ctx, "listUser", nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

func (c *Client) CreateUser(ctx context.Context, u NewUser) error {
	return c.post(ctx, "createUser", u, nil)
}

func (c *Client) ModifyUser(ctx context.Context, changes UserChanges) error {
	return c.post(ctx, "modifyUser", changes, nil)
}

func (c *Client) DeleteUser(ctx context.Context, address string) error {
	return c.post(ctx, "deleteUser", map[string]any{"userName": address}, nil)
}

func (c *Client) ListPasswordReset(ctx context.Context, address string) ([]ResetMethod, error) {
	var out struct {
		Methods []ResetMethod `json:"methods"`
	}
	if err := c.post(ctx, "listPasswordReset", map[string]any{"userName": address}, &out); err != nil {
		return nil, err
	}
	return out.Methods, nil
}

func (c *Client) UpsertPasswordReset(ctx context.Context, address string, m ResetMethod) error {
	body := map[string]any{
		"userName":    address,
		"type":        m.Type,
		"target":      m.Target,
		"description": m.Description,
	}
	if m.ID != "" {
		body["id"] = m.ID
	}
	return c.post(ctx, "upsertPasswordReset", body, nil)
}

func (c *Client) DeletePasswordReset(ctx context.Context, address, id string) error {
	return c.post(ctx, "deletePasswordReset", map[string]any{"userName": address, "id": id}, nil)
}

func (c *Client) ListRoutingRules(ctx context.Context) ([]RoutingRule, error) {
	var out struct {
		Rules []RoutingRule `json:"rules"`
	}
	if err := c.post(ctx, "listRoutingRules", nil, &out); err != nil {
		return nil, err
	}
	return out.Rules, nil
}

func (c *Client) CreateRoutingRule(ctx context.Context, rule RoutingRule) error {
	return c.post(ctx, "createRoutingRule", map[string]any{
		"domainName":      rule.DomainName,
		"matchUser":       rule.MatchUser,
		"prefix":          rule.Prefix,
		"targetAddresses": rule.TargetAddresses,
		"catchall":        rule.Catchall,
	}, nil)
}

func (c *Client) DeleteRoutingRule(ctx context.Context, id int) error {
	return c.post(ctx, "deleteRoutingRule", map[string]any{"routingRuleId": id}, nil)
}

// CreateAppPassword returns a credential that is shown exactly once. There is
// no endpoint to list or re-read it, which is why app credentials are an
// imperative subcommand rather than part of the reconciled config.
func (c *Client) CreateAppPassword(ctx context.Context, address, name string) (string, error) {
	var out struct {
		AppPassword string `json:"appPassword"`
	}
	body := map[string]any{"userName": address}
	if name != "" {
		body["name"] = name
	}
	if err := c.post(ctx, "createAppPassword", body, &out); err != nil {
		return "", err
	}
	return out.AppPassword, nil
}

func (c *Client) DeleteAppPassword(ctx context.Context, address, name string) error {
	return c.post(ctx, "deleteAppPassword", map[string]any{"userName": address, "name": name}, nil)
}

// CheckAccountCredit returns the account's remaining credit as Purelymail
// reports it. The audit command surfaces this.
func (c *Client) CheckAccountCredit(ctx context.Context) (string, error) {
	var out struct {
		Credit string `json:"credit"`
	}
	if err := c.post(ctx, "checkAccountCredit", nil, &out); err != nil {
		return "", err
	}
	return out.Credit, nil
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/mail/purelymail/ -v`
Expected: PASS (9 tests).

- [ ] **Step 6: Confirm the three uncertain response shapes against the live API**

Three response bodies were not observed directly and their decoding is a guess:
`listPasswordReset` (the `methods` key and each method's `id`/`type`/`target` names),
`createAppPassword` (the `appPassword` key), and `checkAccountCredit` (the `credit` key).
Verify with read-only calls before trusting them. `listPasswordReset` is safe to call
against a real mailbox; run it with your own token:

```bash
curl -s https://purelymail.com/api/v0/listPasswordReset \
  -H "Content-Type: application/json" \
  -H "Purelymail-Api-Token: $PURELYMAIL_API_TOKEN" \
  -d '{"userName":"contact@example.com"}' | python3 -m json.tool

curl -s https://purelymail.com/api/v0/checkAccountCredit \
  -H "Content-Type: application/json" \
  -H "Purelymail-Api-Token: $PURELYMAIL_API_TOKEN" \
  -d '{}' | python3 -m json.tool
```

If a key differs, change the struct tag in `api.go` and the corresponding literal in
`client_test.go` to the observed name, then rerun the tests. `createAppPassword` is a
write, so leave it until you actually need an app credential; if its shape turns out to
differ, only `CreateAppPassword` changes.

- [ ] **Step 7: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/purelymail/client.go internal/mail/purelymail/api.go internal/mail/purelymail/client_test.go
git commit -m "feat(purelymail): add full api/v0 client"
```

---

### Task 9: Purelymail as a mail provider

**Files:**
- Create: `internal/mail/purelymail/provider.go`
- Test: `internal/mail/purelymail/provider_test.go`

**Interfaces:**
- Consumes: everything from Task 8, plus `mail.Provider`, `mail.State`, `mail.Options`, `dns.Record`, `plan.Action`, `secret.Resolver`.
- Produces: `purelymail.Provider` implementing `mail.Provider`, registered as `"purelymail"` in an `init` function. Nothing imports it by name except the blank import in `cmd/mailctl`.

**Behaviour notes that drive the code:**
- The ownership dance lives here: `DesiredDNS` calls `getOwnershipCode` and returns the value as a TXT record on the apex. The engine publishes DNS before mail, so by the time `addDomain` runs the proof is live.
- There is no update endpoint for a routing rule. A rule whose targets drift is deleted and recreated, in that order.
- Purelymail publishes DMARC as a CNAME to `dmarcroot.purelymail.com`. When the config declares `deliverability.dmarc`, plan 2 publishes a TXT record instead, so the provider omits its CNAME in that case to avoid two managers of one name.

- [ ] **Step 1: Write the failing DesiredDNS test**

Create `internal/mail/purelymail/provider_test.go`:

```go
package purelymail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

// routes serves canned responses keyed by endpoint name and records every
// request body it received, keyed the same way.
type routes struct {
	responses map[string]string
	calls     []string
	bodies    map[string][]map[string]any
}

func newRoutes(responses map[string]string) *routes {
	return &routes{responses: responses, bodies: map[string][]map[string]any{}}
}

func (r *routes) client(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		endpoint := strings.TrimPrefix(req.URL.Path, "/api/v0/")
		raw, _ := io.ReadAll(req.Body)
		body := map[string]any{}
		json.Unmarshal(raw, &body)

		r.calls = append(r.calls, endpoint)
		r.bodies[endpoint] = append(r.bodies[endpoint], body)

		response, ok := r.responses[endpoint]
		if !ok {
			response = `{"type":"success","result":null}`
		}
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)
	return NewClient(server.URL, "tok")
}

func domainConfig() config.Domain {
	return config.Domain{
		Name:     "a.com",
		ZoneName: "a.com",
		Mail:     config.Mail{Providers: []string{"purelymail"}},
		Mailboxes: []config.Mailbox{
			{Address: "contact@a.com", PasswordEnv: "PW"},
		},
		Aliases:  []config.Alias{{Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &config.CatchAll{To: []string{"contact@a.com"}},
	}
}

func TestDesiredDNSCoversMXSPFOwnershipDKIMDMARC(t *testing.T) {
	r := newRoutes(map[string]string{
		"getOwnershipCode": `{"type":"success","result":{"code":"purelymail_ownership_proof=abc"}}`,
	})
	provider := &Provider{client: r.client(t)}

	records, err := provider.DesiredDNS(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}

	byKind := map[dns.Kind][]dns.Record{}
	for _, rec := range records {
		byKind[rec.Kind] = append(byKind[rec.Kind], rec)
	}

	if got := byKind[dns.KindMX]; len(got) != 1 || got[0].Content != "mailserver.purelymail.com" || got[0].Priority != 50 {
		t.Errorf("MX = %+v, want one record to mailserver.purelymail.com priority 50", got)
	}
	if got := byKind[dns.KindSPF]; len(got) != 1 || !strings.Contains(got[0].Content, "include:_spf.purelymail.com") {
		t.Errorf("SPF = %+v, want the purelymail include", got)
	}
	if got := byKind[dns.KindOwnership]; len(got) != 1 || got[0].Content != "purelymail_ownership_proof=abc" {
		t.Errorf("ownership = %+v, want the code from the API", got)
	}
	if got := byKind[dns.KindDKIM]; len(got) != 3 {
		t.Errorf("DKIM = %+v, want three CNAMEs", got)
	}
	if got := byKind[dns.KindDMARC]; len(got) != 1 || got[0].Type != "CNAME" {
		t.Errorf("DMARC = %+v, want the dmarcroot CNAME", got)
	}
	for _, rec := range byKind[dns.KindDKIM] {
		if rec.Proxied == nil || *rec.Proxied {
			t.Errorf("DKIM record %s must be DNS-only, not proxied", rec.Name)
		}
	}
}

func TestDesiredDNSOmitsDMARCCNAMEWhenConfigManagesDMARC(t *testing.T) {
	r := newRoutes(map[string]string{
		"getOwnershipCode": `{"type":"success","result":{"code":"code"}}`,
	})
	provider := &Provider{client: r.client(t)}

	d := domainConfig()
	d.Deliverability.DMARC = &config.DMARC{Policy: "reject", Pct: 100}

	records, err := provider.DesiredDNS(context.Background(), d)
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	for _, rec := range records {
		if rec.Kind == dns.KindDMARC {
			t.Fatalf("provider must not publish a DMARC record when the config declares one; got %+v", rec)
		}
	}
}

func TestActualReadsDomainMailboxesAndRules(t *testing.T) {
	r := newRoutes(map[string]string{
		"listDomains": `{"type":"success","result":{"domains":[
			{"name":"a.com","allowAccountReset":true,"symbolicSubaddressing":false,
			 "dnsSummary":{"passesMx":true,"passesSpf":true,"passesDkim":true,"passesDmarc":false}}]}}`,
		"listUser":          `{"type":"success","result":{"users":["contact@a.com","other@b.com"]}}`,
		"listPasswordReset": `{"type":"success","result":{"methods":[{"id":"m1","type":"email","target":"fallback@example.com","description":"personal"}]}}`,
		"listRoutingRules": `{"type":"success","result":{"rules":[
			{"id":7,"domainName":"a.com","matchUser":"info","prefix":false,"targetAddresses":["contact@a.com"],"catchall":false},
			{"id":8,"domainName":"a.com","matchUser":"","prefix":false,"targetAddresses":["contact@a.com"],"catchall":true},
			{"id":9,"domainName":"b.com","matchUser":"x","prefix":false,"targetAddresses":["y@b.com"],"catchall":false}]}}`,
	})
	provider := &Provider{client: r.client(t)}

	state, err := provider.Actual(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}

	if !state.DomainExists {
		t.Error("DomainExists = false, want true")
	}
	if len(state.Mailboxes) != 1 || state.Mailboxes[0].Address != "contact@a.com" {
		t.Errorf("mailboxes = %+v, want only the a.com mailbox", state.Mailboxes)
	}
	if len(state.Mailboxes[0].Recovery) != 1 || state.Mailboxes[0].Recovery[0].Target != "fallback@example.com" {
		t.Errorf("recovery = %+v, want the one listed method", state.Mailboxes[0].Recovery)
	}
	if len(state.Aliases) != 1 || state.Aliases[0].Match != "info" {
		t.Errorf("aliases = %+v, want only the a.com alias", state.Aliases)
	}
	if state.CatchAll == nil || state.CatchAll.ID != "8" {
		t.Errorf("catchAll = %+v, want rule 8", state.CatchAll)
	}
	if len(state.Notes) == 0 || !strings.Contains(state.Notes[0], "dmarc=false") {
		t.Errorf("notes = %v, want the DNS summary", state.Notes)
	}
}

func TestPlanOnEmptyProviderCreatesEverything(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "value-1" })}

	actions, err := provider.Plan(domainConfig(), mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	want := []struct {
		op       plan.Op
		resource string
	}{
		{plan.OpCreate, "domain"},
		{plan.OpCreate, "mailbox"},
		{plan.OpCreate, "alias"},
		{plan.OpCreate, "catchall"},
	}
	if len(actions) != len(want) {
		t.Fatalf("got %d actions, want %d: %+v", len(actions), len(want), actions)
	}
	for i, w := range want {
		if actions[i].Op != w.op || actions[i].Resource != w.resource {
			t.Errorf("action %d = %s %s, want %s %s", i, actions[i].Op, actions[i].Resource, w.op, w.resource)
		}
	}
	for _, a := range actions {
		if strings.Contains(a.Detail, "value-1") {
			t.Fatalf("action detail leaked a credential: %q", a.Detail)
		}
	}
}

func TestPlanIsEmptyWhenConverged(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none", actions)
	}
}

func TestPlanReplacesAliasWhenTargetsDrift(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "contact@a.com"}},
		Aliases:      []mail.Alias{{ID: "7", Match: "info", To: []string{"stale@a.com"}}},
		CatchAll:     &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete then create for the drifted alias", actions)
	}
}

func TestPlanLeavesUnmanagedObjectsAloneWithoutPrune(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com"},
			{Address: "legacy@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; legacy@a.com is unmanaged, not deletable", actions)
	}
}

func TestPlanPruneDeletesUnmanagedMailbox(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com"},
			{Address: "legacy@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(domainConfig(), actual,
		mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpDelete || !strings.Contains(actions[0].Detail, "legacy@a.com") {
		t.Fatalf("actions = %+v, want one delete naming legacy@a.com", actions)
	}
}

func TestPlanReconcilesRecoveryMethods(t *testing.T) {
	provider := &Provider{client: newRoutes(nil).client(t)}

	d := domainConfig()
	d.Mailboxes[0].Recovery = []config.Recovery{
		{Type: "email", Target: "new@example.com", Description: "personal"},
	}
	actual := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{{
			Address:  "contact@a.com",
			Recovery: []mail.Recovery{{ID: "m1", Type: "email", Target: "old@example.com"}},
		}},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}

	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(actions) != 1 || actions[0].Resource != "recovery" || actions[0].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want one recovery upsert", actions)
	}
	if !strings.Contains(actions[0].Detail, "new@example.com") {
		t.Errorf("detail = %q, want the new target named", actions[0].Detail)
	}
}

func TestApplyingPlanCallsTheRightEndpoints(t *testing.T) {
	r := newRoutes(nil)
	provider := &Provider{client: r.client(t)}
	opts := mail.Options{Secrets: secret.NewResolver(func(string) string { return "value-1" })}

	actions, err := provider.Plan(domainConfig(), mail.State{}, opts)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do %s %s: %v", a.Op, a.Resource, err)
		}
	}

	wantCalls := []string{"addDomain", "createUser", "createRoutingRule", "createRoutingRule"}
	if len(r.calls) != len(wantCalls) {
		t.Fatalf("calls = %v, want %v", r.calls, wantCalls)
	}
	for i, want := range wantCalls {
		if r.calls[i] != want {
			t.Errorf("call %d = %s, want %s", i, r.calls[i], want)
		}
	}
	if got := r.bodies["createRoutingRule"][1]["catchall"]; got != true {
		t.Errorf("second routing rule catchall = %v, want true", got)
	}
}

func TestProviderIsRegistered(t *testing.T) {
	for _, name := range mail.Registered() {
		if name == "purelymail" {
			return
		}
	}
	t.Fatal("purelymail should register itself in an init function")
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/mail/purelymail/ -run TestDesired -v`
Expected: FAIL — `undefined: Provider`.

- [ ] **Step 3: Implement the provider**

Create `internal/mail/purelymail/provider.go`:

```go
package purelymail

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// Name is the value used in the config's mail.provider field.
const Name = "purelymail"

// SPFInclude is the mechanism Purelymail requires in the domain's SPF record.
// The deliverability package merges it with any additional includes.
const SPFInclude = "include:_spf.purelymail.com"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		getenv := deps.Getenv
		if getenv == nil {
			return nil, fmt.Errorf("purelymail: no environment accessor supplied")
		}
		token := getenv("PURELYMAIL_API_TOKEN")
		if token == "" {
			return nil, fmt.Errorf("PURELYMAIL_API_TOKEN is required for the purelymail provider")
		}
		return &Provider{client: NewClient(deps.PurelymailBaseURL, token)}, nil
	})
}

type Provider struct {
	client *Client
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	code, err := p.client.GetOwnershipCode(ctx)
	if err != nil {
		return nil, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if code == "" {
		return nil, fmt.Errorf("domain %s: Purelymail returned an empty ownership code", d.Name)
	}

	dnsOnly := false
	records := []dns.Record{
		{Type: "MX", Name: d.Name, Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX},
		{Type: "TXT", Name: d.Name, Content: "v=spf1 " + SPFInclude + " ~all", Kind: dns.KindSPF},
		{Type: "TXT", Name: d.Name, Content: code, Kind: dns.KindOwnership},
	}
	for i := 1; i <= 3; i++ {
		records = append(records, dns.Record{
			Type:    "CNAME",
			Name:    fmt.Sprintf("purelymail%d._domainkey.%s", i, d.Name),
			Content: fmt.Sprintf("key%d.dkimroot.purelymail.com", i),
			Proxied: &dnsOnly,
			Kind:    dns.KindDKIM,
		})
	}

	// When the config declares a DMARC policy, the deliverability package owns
	// _dmarc as a TXT record; two managers of one name would fight.
	if d.Deliverability.DMARC == nil {
		records = append(records, dns.Record{
			Type:    "CNAME",
			Name:    "_dmarc." + d.Name,
			Content: "dmarcroot.purelymail.com",
			Proxied: &dnsOnly,
			Kind:    dns.KindDMARC,
		})
	}
	return records, nil
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State

	domains, err := p.client.ListDomains(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	for _, remote := range domains {
		if !strings.EqualFold(remote.Name, d.Name) {
			continue
		}
		state.DomainExists = true
		state.Settings = mail.Settings{
			AllowAccountReset:     remote.AllowAccountReset,
			SymbolicSubaddressing: remote.SymbolicSubaddressing,
		}
		state.Notes = append(state.Notes, fmt.Sprintf(
			"purelymail DNS check: mx=%t spf=%t dkim=%t dmarc=%t",
			remote.DNSSummary.PassesMX, remote.DNSSummary.PassesSPF,
			remote.DNSSummary.PassesDKIM, remote.DNSSummary.PassesDMARC))
		break
	}

	if !state.DomainExists {
		// Nothing else can exist for a domain Purelymail does not know about.
		return state, nil
	}

	users, err := p.client.ListUsers(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	suffix := "@" + d.Name
	for _, address := range users {
		address = strings.ToLower(address)
		if !strings.HasSuffix(address, suffix) {
			continue
		}
		methods, err := p.client.ListPasswordReset(ctx, address)
		if err != nil {
			return state, fmt.Errorf("domain %s: mailbox %s: %w", d.Name, address, err)
		}
		box := mail.Mailbox{Address: address}
		for _, m := range methods {
			box.Recovery = append(box.Recovery, mail.Recovery{
				ID: m.ID, Type: m.Type, Target: m.Target, Description: m.Description,
			})
		}
		state.Mailboxes = append(state.Mailboxes, box)
	}

	rules, err := p.client.ListRoutingRules(ctx)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	for _, rule := range rules {
		if !strings.EqualFold(rule.DomainName, d.Name) {
			continue
		}
		if rule.Catchall {
			state.CatchAll = &mail.CatchAll{ID: strconv.Itoa(rule.ID), To: rule.TargetAddresses}
			continue
		}
		state.Aliases = append(state.Aliases, mail.Alias{
			ID:     strconv.Itoa(rule.ID),
			Match:  rule.MatchUser,
			Prefix: rule.Prefix,
			To:     rule.TargetAddresses,
		})
	}
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	var actions []plan.Action

	actions = append(actions, p.planDomain(d, actual)...)

	mailboxActions, err := p.planMailboxes(d, actual, opts)
	if err != nil {
		return nil, err
	}
	actions = append(actions, mailboxActions...)

	actions = append(actions, p.planAliases(d, actual, opts)...)
	actions = append(actions, p.planCatchAll(d, actual)...)
	return actions, nil
}

func (p *Provider) planDomain(d config.Domain, actual mail.State) []plan.Action {
	if !actual.DomainExists {
		name := d.Name
		return []plan.Action{{
			Op:       plan.OpCreate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "add domain " + name,
			Do: func(ctx context.Context) error {
				if err := p.client.AddDomain(ctx, name); err != nil {
					return fmt.Errorf(
						"add Purelymail domain %s failed; the ownership TXT record may not have propagated yet, wait a minute and rerun: %w",
						name, err)
				}
				return nil
			},
		}}
	}

	want := d.Mail.Settings
	allowReset := want.AllowAccountReset
	symbolic := want.SymbolicSubaddressing
	resetDrift := allowReset != nil && *allowReset != actual.Settings.AllowAccountReset
	symbolicDrift := symbolic != nil && *symbolic != actual.Settings.SymbolicSubaddressing
	if !resetDrift && !symbolicDrift {
		return nil
	}

	name := d.Name
	return []plan.Action{{
		Op:       plan.OpUpdate,
		Resource: "domain",
		Domain:   d.Name,
		Provider: Name,
		Detail: fmt.Sprintf("update settings (allowAccountReset=%s symbolicSubaddressing=%s)",
			boolText(allowReset), boolText(symbolic)),
		Do: func(ctx context.Context) error {
			return p.client.UpdateDomainSettings(ctx, name, allowReset, symbolic, false)
		},
	}}
}

func (p *Provider) planMailboxes(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	var actions []plan.Action
	managed := map[string]bool{}

	for _, want := range d.Mailboxes {
		managed[want.Address] = true
		_, exists := actual.Mailbox(want.Address)
		if !exists {
			credential, err := opts.Secrets.Password(d.Name, want)
			if err != nil {
				return nil, err
			}
			newUser := NewUser{
				UserName:             want.LocalPart(),
				DomainName:           d.Name,
				Password:             credential,
				EnablePasswordReset:  config.BoolOr(want.EnablePasswordReset, true),
				EnableSearchIndexing: config.BoolOr(want.EnableSearchIndexing, true),
				SendWelcomeEmail:     config.BoolOr(want.SendWelcomeEmail, false),
			}
			address := want.Address
			actions = append(actions, plan.Action{
				Op:       plan.OpCreate,
				Resource: "mailbox",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "create " + address,
				Do: func(ctx context.Context) error {
					return p.client.CreateUser(ctx, newUser)
				},
			})
		}
		actions = append(actions, p.planRecovery(d, want, actual)...)
	}

	if !opts.Prune {
		return actions, nil
	}
	for _, have := range actual.Mailboxes {
		if managed[strings.ToLower(have.Address)] {
			continue
		}
		address := have.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "mailbox",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "delete " + address + " and all mail it holds",
			Do: func(ctx context.Context) error {
				return p.client.DeleteUser(ctx, address)
			},
		})
	}
	return actions, nil
}

// planRecovery reconciles password-reset methods for one mailbox. A mailbox
// that does not exist yet has no methods, so everything in config is created.
func (p *Provider) planRecovery(d config.Domain, want config.Mailbox, actual mail.State) []plan.Action {
	var actions []plan.Action
	have, _ := actual.Mailbox(want.Address)

	keep := map[string]bool{}
	for _, method := range want.Recovery {
		existing, found := findRecovery(have.Recovery, method.Type, method.Target)
		if found {
			keep[existing.ID] = true
			continue
		}
		method := method
		address := want.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "recovery",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("add %s recovery %s to %s", method.Type, method.Target, address),
			Do: func(ctx context.Context) error {
				return p.client.UpsertPasswordReset(ctx, address, ResetMethod{
					Type:        method.Type,
					Target:      method.Target,
					Description: method.Description,
				})
			},
		})
	}

	// Recovery methods are fully managed once a mailbox declares any, because a
	// stale reset path is a standing account-takeover route. A mailbox with no
	// recovery block in config is left alone.
	if len(want.Recovery) == 0 {
		return actions
	}
	for _, method := range have.Recovery {
		if keep[method.ID] {
			continue
		}
		method := method
		address := want.Address
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "recovery",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("remove %s recovery %s from %s", method.Type, method.Target, address),
			Do: func(ctx context.Context) error {
				return p.client.DeletePasswordReset(ctx, address, method.ID)
			},
		})
	}
	return actions
}

func (p *Provider) planAliases(d config.Domain, actual mail.State, opts mail.Options) []plan.Action {
	var actions []plan.Action
	managed := map[string]bool{}

	for _, want := range d.Aliases {
		key := aliasKey(want.MatchUser(), want.Prefix())
		managed[key] = true

		existing, found := actual.Alias(want.MatchUser(), want.Prefix())
		if found && sameTargets(existing.To, want.To) {
			continue
		}
		if found {
			// Purelymail has no update endpoint for a routing rule.
			id := existing.ID
			actions = append(actions, plan.Action{
				Op:       plan.OpDelete,
				Resource: "alias",
				Domain:   d.Name,
				Provider: Name,
				Detail:   fmt.Sprintf("replace alias %s (targets changed)", want.Match),
				Do:       p.deleteRule(id),
			})
		}
		rule := RoutingRule{
			DomainName:      d.Name,
			MatchUser:       want.MatchUser(),
			Prefix:          want.Prefix(),
			TargetAddresses: want.To,
		}
		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   fmt.Sprintf("alias %s -> %s", want.Match, strings.Join(want.To, ", ")),
			Do: func(ctx context.Context) error {
				return p.client.CreateRoutingRule(ctx, rule)
			},
		})
	}

	if !opts.Prune {
		return actions
	}
	for _, have := range actual.Aliases {
		if managed[aliasKey(have.Match, have.Prefix)] {
			continue
		}
		id, match := have.ID, have.Match
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "alias",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "delete unmanaged alias " + match,
			Do:       p.deleteRule(id),
		})
	}
	return actions
}

func (p *Provider) planCatchAll(d config.Domain, actual mail.State) []plan.Action {
	// Omitting the key leaves whatever exists untouched.
	if d.CatchAll == nil {
		return nil
	}
	if actual.CatchAll != nil && sameTargets(actual.CatchAll.To, d.CatchAll.To) {
		return nil
	}

	var actions []plan.Action
	if actual.CatchAll != nil {
		id := actual.CatchAll.ID
		actions = append(actions, plan.Action{
			Op:       plan.OpDelete,
			Resource: "catchall",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "replace catch-all (targets changed)",
			Do:       p.deleteRule(id),
		})
	}
	rule := RoutingRule{
		DomainName:      d.Name,
		TargetAddresses: d.CatchAll.To,
		Catchall:        true,
	}
	return append(actions, plan.Action{
		Op:       plan.OpCreate,
		Resource: "catchall",
		Domain:   d.Name,
		Provider: Name,
		Detail:   "catch-all -> " + strings.Join(d.CatchAll.To, ", "),
		Do: func(ctx context.Context) error {
			return p.client.CreateRoutingRule(ctx, rule)
		},
	})
}

func (p *Provider) deleteRule(id string) func(context.Context) error {
	return func(ctx context.Context) error {
		numeric, err := strconv.Atoi(id)
		if err != nil {
			return fmt.Errorf("Purelymail routing rule id %q is not a number: %w", id, err)
		}
		return p.client.DeleteRoutingRule(ctx, numeric)
	}
}

func findRecovery(methods []mail.Recovery, kind, target string) (mail.Recovery, bool) {
	for _, m := range methods {
		if strings.EqualFold(m.Type, kind) && strings.EqualFold(m.Target, target) {
			return m, true
		}
	}
	return mail.Recovery{}, false
}

func aliasKey(match string, prefix bool) string {
	return fmt.Sprintf("%s|%t", strings.ToLower(match), prefix)
}

// sameTargets compares target lists ignoring order and case.
func sameTargets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[strings.ToLower(v)]++
	}
	for _, v := range b {
		key := strings.ToLower(v)
		seen[key]--
		if seen[key] < 0 {
			return false
		}
	}
	return true
}

func boolText(v *bool) string {
	if v == nil {
		return "unchanged"
	}
	return strconv.FormatBool(*v)
}
```

- [ ] **Step 4: Run the provider tests and verify they pass**

Run: `go test ./internal/mail/purelymail/ -v`
Expected: PASS — the 9 client tests from Task 8 and the 11 provider tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/mail/purelymail/provider.go internal/mail/purelymail/provider_test.go
git commit -m "feat(purelymail): reconcile domain, mailboxes, aliases, recovery"
```

---

### Task 10: Engine

**Files:**
- Create: `internal/engine/engine.go`
- Test: `internal/engine/engine_test.go`

**Interfaces:**
- Consumes: `config.Config`, `dns.Provider`, `dns.Diff`, `mail.Open`, `mail.Deps`, `plan.Plan`, `secret.Resolver`.
- Produces: `engine.New(cfg config.Config, dnsProvider dns.Provider, deps mail.Deps, opts Options) *Engine`, `engine.Options{Domains []string, Prune bool, ReplaceDNS bool, Secrets *secret.Resolver}`, `(*Engine).Plan(ctx) (plan.Plan, error)`, `(*Engine).Apply(ctx, p plan.Plan, out io.Writer) error`. `cmd/mailctl` (Task 11) is the only consumer.

- [ ] **Step 1: Write the failing engine test**

Create `internal/engine/engine_test.go`:

```go
package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

type fakeDNS struct {
	records []dns.Existing
	created []dns.Record
}

func (f *fakeDNS) Zone(_ context.Context, name string) (dns.Zone, error) {
	return dns.Zone{ID: "zone-" + name, Name: name}, nil
}
func (f *fakeDNS) Records(context.Context, string) ([]dns.Existing, error) { return f.records, nil }
func (f *fakeDNS) Create(_ context.Context, _ string, r dns.Record) error {
	f.created = append(f.created, r)
	return nil
}
func (f *fakeDNS) Delete(context.Context, string, string) error { return nil }

type fakeMail struct {
	name    string
	desired []dns.Record
	actions []plan.Action
}

func (f *fakeMail) Name() string { return f.name }
func (f *fakeMail) DesiredDNS(context.Context, config.Domain) ([]dns.Record, error) {
	return f.desired, nil
}
func (f *fakeMail) Actual(context.Context, config.Domain) (mail.State, error) {
	return mail.State{Notes: []string{f.name + " note"}}, nil
}
func (f *fakeMail) Plan(config.Domain, mail.State, mail.Options) ([]plan.Action, error) {
	return f.actions, nil
}

func registerFake(t *testing.T, name string, provider *fakeMail) {
	t.Helper()
	mail.Register(name, func(mail.Deps) (mail.Provider, error) { return provider, nil })
	t.Cleanup(func() { mail.Unregister(name) })
}

func cfg(providers ...string) config.Config {
	return config.Config{
		Version: config.SchemaVersion,
		Domains: []config.Domain{{
			Name:     "a.com",
			ZoneName: "a.com",
			Mail:     config.Mail{Providers: providers},
		}},
	}
}

func TestPlanOrdersDNSBeforeMail(t *testing.T) {
	registerFake(t, "fake", &fakeMail{
		name:    "fake",
		desired: []dns.Record{{Type: "MX", Name: "a.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake",
			Detail: "add domain", Do: func(context.Context) error { return nil }}},
	})

	e := New(cfg("fake"), &fakeDNS{}, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(got.Actions) != 2 {
		t.Fatalf("actions = %+v, want two", got.Actions)
	}
	if got.Actions[0].Resource != "dns" {
		t.Errorf("first action is %s; DNS must be applied before mail so the ownership proof resolves",
			got.Actions[0].Resource)
	}
	if got.Actions[1].Resource != "domain" {
		t.Errorf("second action = %s, want domain", got.Actions[1].Resource)
	}
}

func TestPlanUnionsDNSFromSeveralProviders(t *testing.T) {
	registerFake(t, "inbound", &fakeMail{name: "inbound",
		desired: []dns.Record{{Type: "MX", Name: "a.com", Content: "mx.in.com", Priority: 10, Kind: dns.KindMX}}})
	registerFake(t, "outbound", &fakeMail{name: "outbound",
		desired: []dns.Record{{Type: "TXT", Name: "x._domainkey.a.com", Content: "k=rsa", Kind: dns.KindDKIM}}})

	e := New(cfg("inbound", "outbound"), &fakeDNS{}, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(got.Actions) != 2 {
		t.Fatalf("actions = %+v, want one per provider record", got.Actions)
	}
}

func TestPlanRejectsProvidersDemandingDifferentContentForOneRecord(t *testing.T) {
	registerFake(t, "one", &fakeMail{name: "one",
		desired: []dns.Record{{Type: "TXT", Name: "a.com", Content: "v=spf1 include:one ~all", Kind: dns.KindSPF}}})
	registerFake(t, "two", &fakeMail{name: "two",
		desired: []dns.Record{{Type: "TXT", Name: "a.com", Content: "v=spf1 include:two ~all", Kind: dns.KindSPF}}})

	e := New(cfg("one", "two"), &fakeDNS{}, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil {
		t.Fatal("expected an error when two providers demand different content for one record")
	}
	if !strings.Contains(err.Error(), "one") || !strings.Contains(err.Error(), "two") {
		t.Errorf("error should name both providers; got %q", err)
	}
}

func TestPlanFiltersToSelectedDomains(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake"})

	c := cfg("fake")
	c.Domains = append(c.Domains, config.Domain{
		Name: "b.com", ZoneName: "b.com", Mail: config.Mail{Providers: []string{"fake"}}})

	e := New(c, &fakeDNS{}, mail.Deps{}, Options{Domains: []string{"b.com"}, Secrets: secret.NewResolver(nil)})
	if _, err := e.Plan(context.Background()); err != nil {
		t.Fatalf("Plan: %v", err)
	}
}

func TestPlanRejectsUnknownSelectedDomain(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake"})

	e := New(cfg("fake"), &fakeDNS{}, mail.Deps{}, Options{Domains: []string{"nope.com"}, Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nope.com") {
		t.Fatalf("err = %v, want an error naming the unknown domain", err)
	}
}

func TestApplyRunsActionsInOrder(t *testing.T) {
	var order []string
	registerFake(t, "fake", &fakeMail{name: "fake", actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake", Detail: "one",
			Do: func(context.Context) error { order = append(order, "one"); return nil }},
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "fake", Detail: "two",
			Do: func(context.Context) error { order = append(order, "two"); return nil }},
	}})

	e := New(cfg("fake"), &fakeDNS{}, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	p, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var out strings.Builder
	if err := e.Apply(context.Background(), p, &out); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(order) != 2 || order[0] != "one" || order[1] != "two" {
		t.Errorf("order = %v, want [one two]", order)
	}
}

func TestApplyReportsProgressBeforeFailing(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake", actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake", Detail: "ok",
			Do: func(context.Context) error { return nil }},
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "fake", Detail: "boom",
			Do: func(context.Context) error { return errors.New("api said no") }},
		{Op: plan.OpCreate, Resource: "alias", Domain: "a.com", Provider: "fake", Detail: "never",
			Do: func(context.Context) error { t.Fatal("must not run after a failure"); return nil }},
	}})

	e := New(cfg("fake"), &fakeDNS{}, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	p, _ := e.Plan(context.Background())

	var out strings.Builder
	err := e.Apply(context.Background(), p, &out)
	if err == nil {
		t.Fatal("expected the failure to surface")
	}
	if !strings.Contains(err.Error(), "api said no") {
		t.Errorf("error should carry the provider message; got %q", err)
	}
	if !strings.Contains(err.Error(), "1 of 3") {
		t.Errorf("error should say how much succeeded; got %q", err)
	}
	if !strings.Contains(err.Error(), "rerun") {
		t.Errorf("error should tell the user to rerun; got %q", err)
	}
}
```

- [ ] **Step 2: Export `Unregister` from the mail registry, which the test needs**

In `internal/mail/registry.go`, rename the unexported helper to an exported one so
tests in other packages can clean up after registering a fake:

```go
// Unregister removes a provider. It exists so tests can register fakes without
// leaking them into other tests.
func Unregister(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, name)
}
```

Update the two `unregister("stub")` calls in `internal/mail/registry_test.go` to
`Unregister("stub")`.

- [ ] **Step 3: Run the engine test and confirm it fails**

Run: `go test ./internal/engine/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 4: Implement the engine**

Create `internal/engine/engine.go`:

```go
// Package engine turns a config plus live provider state into an ordered plan,
// and executes it.
package engine

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

type Options struct {
	// Domains limits the run to these domain names. Empty means every domain.
	Domains []string
	// Prune plans deletion of provider-side objects absent from the config.
	Prune bool
	// ReplaceDNS deletes conflicting DNS records instead of failing.
	ReplaceDNS bool
	// Secrets resolves mailbox credentials.
	Secrets *secret.Resolver
}

type Engine struct {
	cfg  config.Config
	zone dns.Provider
	deps mail.Deps
	opts Options
}

func New(cfg config.Config, zone dns.Provider, deps mail.Deps, opts Options) *Engine {
	if opts.Secrets == nil {
		opts.Secrets = secret.NewResolver(nil)
	}
	return &Engine{cfg: cfg, zone: zone, deps: deps, opts: opts}
}

// Plan reads live state and returns everything that would change. It performs
// no writes.
func (e *Engine) Plan(ctx context.Context) (plan.Plan, error) {
	domains, err := e.selectedDomains()
	if err != nil {
		return plan.Plan{}, err
	}

	var out plan.Plan
	for _, d := range domains {
		domainPlan, err := e.planDomain(ctx, d)
		if err != nil {
			return plan.Plan{}, err
		}
		out.Extend(domainPlan)
	}
	return out, nil
}

func (e *Engine) planDomain(ctx context.Context, d config.Domain) (plan.Plan, error) {
	var out plan.Plan

	providers := make([]mail.Provider, 0, len(d.Mail.Providers))
	for _, name := range d.Mail.Providers {
		provider, err := mail.Open(name, e.deps)
		if err != nil {
			return out, fmt.Errorf("domain %s: %w", d.Name, err)
		}
		providers = append(providers, provider)
	}

	// Desired DNS is the union across providers. Deliverability records are
	// added here by plan 2.
	var desired []dns.Record
	owner := map[string]string{}
	for _, provider := range providers {
		records, err := provider.DesiredDNS(ctx, d)
		if err != nil {
			return out, err
		}
		for _, record := range records {
			key := strings.ToLower(record.Type + " " + strings.TrimSuffix(record.Name, "."))
			if previous, claimed := owner[key]; claimed {
				if !sameContent(desired, key, record) {
					return out, fmt.Errorf(
						"domain %s: providers %s and %s both want %s %s with different content; they cannot share this record",
						d.Name, previous, provider.Name(), record.Type, record.Name)
				}
				continue
			}
			owner[key] = provider.Name()
			desired = append(desired, record)
		}
	}

	zone, err := e.zone.Zone(ctx, d.ZoneName)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	actualRecords, err := e.zone.Records(ctx, zone.ID)
	if err != nil {
		return out, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	dnsActions, err := dns.Diff(e.zone, zone.ID, d.Name, actualRecords, desired,
		dns.DiffOptions{ReplaceConflicts: e.opts.ReplaceDNS})
	if err != nil {
		return out, err
	}
	out.Add(dnsActions...)

	// Mail actions run after DNS because Purelymail's addDomain fails until the
	// ownership TXT record resolves.
	for _, provider := range providers {
		state, err := provider.Actual(ctx, d)
		if err != nil {
			return out, err
		}
		for _, note := range state.Notes {
			out.Add(plan.Action{
				Op:       plan.OpManual,
				Resource: "note",
				Domain:   d.Name,
				Provider: provider.Name(),
				Detail:   note,
			})
		}
		actions, err := provider.Plan(d, state, mail.Options{Prune: e.opts.Prune, Secrets: e.opts.Secrets})
		if err != nil {
			return out, err
		}
		out.Add(actions...)
	}
	return out, nil
}

// Apply runs every executable action in order, writing one line per action.
func (e *Engine) Apply(ctx context.Context, p plan.Plan, out io.Writer) error {
	actions := p.Executable()
	for i, action := range actions {
		fmt.Fprintf(out, "[%d/%d] %s %s %s: %s\n",
			i+1, len(actions), action.Op, action.Domain, action.Resource, action.Detail)

		if err := action.Do(ctx); err != nil {
			return fmt.Errorf(
				"%s %s %s failed after %d of %d actions succeeded; every action is idempotent, so fix the cause and rerun: %w",
				action.Op, action.Domain, action.Resource, i, len(actions), err)
		}
	}
	fmt.Fprintf(out, "Applied %d actions.\n", len(actions))
	return nil
}

func (e *Engine) selectedDomains() ([]config.Domain, error) {
	if len(e.opts.Domains) == 0 {
		return e.cfg.Domains, nil
	}
	var out []config.Domain
	for _, name := range e.opts.Domains {
		d, ok := e.cfg.Domain(name)
		if !ok {
			return nil, fmt.Errorf("domain %s is not in the config", name)
		}
		out = append(out, d)
	}
	return out, nil
}

// sameContent reports whether the already-collected record for a key has the
// same content as a newly proposed one.
func sameContent(collected []dns.Record, key string, candidate dns.Record) bool {
	for _, record := range collected {
		existing := strings.ToLower(record.Type + " " + strings.TrimSuffix(record.Name, "."))
		if existing == key {
			return strings.EqualFold(record.Content, candidate.Content)
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `go test ./internal/engine/ -v`
Expected: PASS (7 tests).

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/engine/ internal/mail/registry.go internal/mail/registry_test.go
git commit -m "feat(engine): plan and apply across domains and providers"
```

---

### Task 11: Destructive-change confirmation

**Files:**
- Create: `internal/engine/confirm.go`
- Test: `internal/engine/confirm_test.go`

**Interfaces:**
- Consumes: `plan.Plan`, `plan.Action`.
- Produces: `engine.Confirm(in io.Reader, out io.Writer, p plan.Plan) error`. `cmd/mailctl` (Task 12) calls it before `Apply` unless `-yes` is passed.

- [ ] **Step 1: Write the failing test**

Create `internal/engine/confirm_test.go`:

```go
package engine

import (
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
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `go test ./internal/engine/ -run TestConfirm -v`
Expected: FAIL — `undefined: Confirm`.

- [ ] **Step 3: Implement the confirmation prompt**

Create `internal/engine/confirm.go`:

```go
package engine

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/plan"
)

// Confirm blocks until the operator retypes the affected domain names. It
// returns immediately when the plan deletes nothing. Mailbox deletion destroys
// stored mail irreversibly, so every object is named individually rather than
// summarised as a count.
func Confirm(in io.Reader, out io.Writer, p plan.Plan) error {
	deletions := p.Destructive()
	if len(deletions) == 0 {
		return nil
	}

	domains := map[string]bool{}
	fmt.Fprintf(out, "\nThe following %d changes delete data:\n", len(deletions))
	for _, action := range deletions {
		fmt.Fprintf(out, "  %s %s: %s\n", action.Domain, action.Resource, action.Detail)
		domains[strings.ToLower(action.Domain)] = true
	}

	expected := sortedSet(domains)
	fmt.Fprintf(out, "\nType %s to continue, anything else to abort: ", expected)

	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	if err != nil && answer == "" {
		return fmt.Errorf("aborted: could not read a confirmation (%w)", err)
	}

	if normaliseDomainList(answer) != expected {
		return fmt.Errorf("aborted: expected %q", expected)
	}
	return nil
}

func sortedSet(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// normaliseDomainList lowercases, trims, and re-joins a comma-separated answer
// so spacing and case do not decide the outcome. Order still matters, and the
// prompt shows the expected order.
func normaliseDomainList(answer string) string {
	parts := strings.Split(strings.TrimSpace(answer), ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, ",")
}
```

- [ ] **Step 4: Run the tests and verify they pass**

Run: `go test ./internal/engine/ -v`
Expected: PASS — the 7 engine tests and the 4 confirmation tests.

- [ ] **Step 5: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add internal/engine/confirm.go internal/engine/confirm_test.go
git commit -m "feat(engine): require typed confirmation for deletions"
```

---

### Task 12: The CLI

**Files:**
- Create: `cmd/mailctl/main.go`
- Create: `mailctl.example.yaml`

**Interfaces:**
- Consumes: `config.Load`, `cfapi.New`, `cloudflare.New`, `mail.Deps`, `engine.New`, `engine.Confirm`, `secret.NewResolver`, `secret.ReportTo`, `secret.WriteFile`, and the blank import of `internal/mail/purelymail`.
- Produces: the `mailctl` binary with subcommands `plan`, `apply`, `version`.

**Command surface delivered here.** `audit`, `import`, `mailbox`, `alias`, and `apppass` come in plan 3; this task prints a "not built yet, see plan 3" error for those names rather than "unknown subcommand", so an operator who read the spec is not left guessing.

- [ ] **Step 1: Write the CLI**

Create `cmd/mailctl/main.go`:

```go
// Command mailctl reconciles email configuration across domains.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	cfdns "github.com/zoolcoder/mailctl/internal/dns/cloudflare"
	"github.com/zoolcoder/mailctl/internal/engine"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/secret"

	// Providers register themselves at init time. This is the only place that
	// names a provider package.
	_ "github.com/zoolcoder/mailctl/internal/mail/purelymail"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `mailctl reconciles email configuration from a YAML file.

Usage:
  mailctl plan  [flags]     show what would change (default)
  mailctl apply [flags]     make the changes
  mailctl version

Flags:
  -config string        config file (default "mailctl.yaml")
  -domain value         limit to this domain; repeat for several
  -prune                delete provider-side objects absent from the config
  -replace-dns          replace conflicting MX, SPF, DKIM, DMARC records
  -yes                  skip the deletion confirmation prompt
  -secrets-out string   write generated credentials to this file (mode 0600)

Environment:
  CLOUDFLARE_API_TOKEN   required
  PURELYMAIL_API_TOKEN   required when a domain uses the purelymail provider
`

// domainList collects a repeatable -domain flag.
type domainList []string

func (d *domainList) String() string { return strings.Join(*d, ",") }

func (d *domainList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			*d = append(*d, part)
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "plan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}

	switch command {
	case "version":
		fmt.Println("mailctl", version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "plan", "apply":
	case "audit", "import", "mailbox", "alias", "apppass":
		return fmt.Errorf("%s is specified but not built yet; see docs/superpowers/plans for the plan that adds it", command)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown subcommand %q", command)
	}

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	var domains domainList
	configPath := flags.String("config", "mailctl.yaml", "path to the YAML configuration")
	prune := flags.Bool("prune", false, "delete provider-side objects absent from the config")
	replaceDNS := flags.Bool("replace-dns", false, "replace conflicting MX, SPF, DKIM, DMARC records")
	assumeYes := flags.Bool("yes", false, "skip the deletion confirmation prompt")
	secretsOut := flags.String("secrets-out", "", "write generated credentials to this file")
	flags.Var(&domains, "domain", "limit to this domain; repeat for several")

	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	cfg, err := config.Load(*configPath, os.Getenv)
	if err != nil {
		return err
	}

	cloudflareToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if cloudflareToken == "" {
		return errors.New("CLOUDFLARE_API_TOKEN is required")
	}

	api := cfapi.New(cfg.Cloudflare.BaseURL, cloudflareToken)
	secrets := secret.NewResolver(os.Getenv)

	runner := engine.New(cfg, cfdns.New(api, cfg.Cloudflare.TTL), mail.Deps{
		Cloudflare:        api,
		AccountID:         cfg.Cloudflare.AccountID,
		PurelymailBaseURL: cfg.Purelymail.BaseURL,
		Getenv:            os.Getenv,
	}, engine.Options{
		Domains:    domains,
		Prune:      *prune,
		ReplaceDNS: *replaceDNS,
		Secrets:    secrets,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	built, err := runner.Plan(ctx)
	if err != nil {
		return err
	}

	if command == "plan" {
		built.Render(os.Stdout)
		if !built.Empty() {
			fmt.Println("\nRun `mailctl apply` to make these changes.")
		}
		return nil
	}

	built.Render(os.Stdout)
	if built.Empty() {
		return nil
	}
	if !*assumeYes {
		if err := engine.Confirm(os.Stdin, os.Stdout, built); err != nil {
			return err
		}
	}

	applyErr := runner.Apply(ctx, built, os.Stdout)

	// Report generated credentials even when apply failed part-way: some
	// mailboxes may already exist with them.
	if generated := secrets.Generated(); len(generated) > 0 {
		if *secretsOut != "" {
			if err := secret.WriteFile(*secretsOut, generated); err != nil {
				return errors.Join(applyErr, err)
			}
			fmt.Fprintf(os.Stderr, "Wrote %d generated credentials to %s\n", len(generated), *secretsOut)
		} else if err := secret.ReportTo(os.Stderr, generated); err != nil {
			return errors.Join(applyErr, err)
		}
	}
	return applyErr
}
```

- [ ] **Step 2: Build the binary and check the help text**

```bash
go build -o mailctl ./cmd/mailctl
./mailctl help
./mailctl version
```

Expected: the usage block, then `mailctl dev`.

- [ ] **Step 3: Verify the missing-config path fails cleanly**

```bash
./mailctl plan -config does-not-exist.yaml
```

Expected: exit status 1 and `error: read config does-not-exist.yaml: ...`, with no stack trace.

- [ ] **Step 4: Write the example config**

Create `mailctl.example.yaml`:

```yaml
# mailctl configuration. Copy to mailctl.yaml and edit.
# ${VAR} is expanded from the environment; an unset variable is an error.
version: 1

cloudflare:
  accountId: ${CLOUDFLARE_ACCOUNT_ID}
  ttl: 1 # 1 means automatic

domains:
  - name: example.com
    # zoneName defaults to name; set it when the Cloudflare zone differs.
    zoneName: example.com

    mail:
      provider: purelymail
      settings:
        allowAccountReset: true
        symbolicSubaddressing: false

    mailboxes:
      # Omit passwordEnv to have mailctl generate a credential and print it once.
      - address: contact@example.com
        passwordEnv: CONTACT_PASSWORD
        enableSearchIndexing: true
        recovery:
          - type: email
            target: fallback@example.com
            description: personal

      - address: a.person@example.com
        passwordEnv: A_PERSON_PASSWORD
      - address: b.person@example.com
        passwordEnv: B_PERSON_PASSWORD
      - address: c.person@example.com
        passwordEnv: C_PERSON_PASSWORD

    aliases:
      - match: info # "info*" matches any local part starting with info
        to: [contact@example.com]

    # Omit catchAll entirely to leave whatever exists untouched.
    catchAll:
      to: [contact@example.com]

    # Deliverability is read by this build but only acted on once the
    # deliverability plan is implemented.
    deliverability:
      dmarc:
        policy: quarantine
        subdomainPolicy: reject
        pct: 100
        rua: mailto:dmarc@example.com
```

- [ ] **Step 5: Verify the example config loads**

```bash
CLOUDFLARE_ACCOUNT_ID=placeholder \
CLOUDFLARE_API_TOKEN=placeholder \
PURELYMAIL_API_TOKEN=placeholder \
CONTACT_PASSWORD=x A_PERSON_PASSWORD=x B_PERSON_PASSWORD=x C_PERSON_PASSWORD=x \
./mailctl plan -config mailctl.example.yaml
```

Expected: the config parses and validates, then the run fails at the first live API
call with a Cloudflare authentication error naming the endpoint. A parse or validation
error here is a bug in the config or the loader; an authentication error is success for
this step.

- [ ] **Step 6: Commit**

```bash
gofmt -l . && go vet ./... && go test ./...
git add cmd/mailctl/main.go mailctl.example.yaml
git commit -m "feat(cli): add plan and apply commands"
```

---

### Task 13: Migrate example and verify idempotence

**Files:**
- Create: `mailctl.yaml` (git-ignored, local only)
- Read: `../legacy-mailsetup/mailsetup.example.json`

**Interfaces:**
- Consumes: the finished binary.
- Produces: a verified converged live state. Nothing in the old repo is deleted here; that is a step in plan 3, after the Cloudflare providers land.

**Why this is a task and not a footnote:** `example.com` is already provisioned by the
old tool. A non-empty plan against it means the new tool disagrees with reality, and that
has to be understood before any `apply` runs.

- [ ] **Step 1: Write the real config**

Copy `mailctl.example.yaml` to `mailctl.yaml` and reconcile it against the old JSON at
`../legacy-mailsetup/mailsetup.example.json`. The four mailboxes
and their `passwordEnv` names carry over unchanged. The old config had no aliases and no
catch-all, so delete both blocks from the copy for the first run — adding them is a
separate, visible change.

```bash
cd the repository root
cp mailctl.example.yaml mailctl.yaml
$EDITOR mailctl.yaml
```

- [ ] **Step 2: Export the tokens and mailbox credentials**

The mailbox credentials must be the ones already in use, otherwise a future `modifyUser`
would change them. For this run they are only read if a mailbox is missing, but a missing
variable fails validation, so all four must be set.

```bash
export CLOUDFLARE_API_TOKEN=...
export CLOUDFLARE_ACCOUNT_ID=...
export PURELYMAIL_API_TOKEN=...
export CONTACT_PASSWORD=... A_PERSON_PASSWORD=... \
       B_PERSON_PASSWORD=... C_PERSON_PASSWORD=...
```

- [ ] **Step 3: Plan against the live domain**

```bash
./mailctl plan -domain example.com
```

Expected: `No changes. The live configuration already matches the config file.`, preceded
by the MANUAL note line carrying Purelymail's DNS summary.

If the plan is not empty, do not apply. Read each action and decide which of these it is:

- **A DKIM or DMARC CNAME the diff wants to recreate** — the old tool published the same
  records, so this means `same()` is not matching. Compare the live record content in the
  Cloudflare dashboard against `DesiredDNS`; the usual cause is a trailing dot or a
  proxied flag.
- **An ownership TXT record** — `getOwnershipCode` returns a fresh code per call only if
  the domain is not yet verified. For a verified domain it returns the same code, so a
  create action here means the old code is still published under a different value.
  Confirm in the dashboard before replacing anything.
- **A mailbox create** — the address in the config does not match the live one. Fix the
  config.

Fix the cause in code or config and rerun until the plan is empty.

- [ ] **Step 4: Prove idempotence through apply**

```bash
./mailctl apply -domain example.com
```

Expected: the same empty plan, and no prompt, since an empty plan short-circuits before
`Confirm`.

- [ ] **Step 5: Prove the tool actually does something, on a change you want anyway**

Add the `aliases` block back to `mailctl.yaml` with `info -> contact@example.com`, then:

```bash
./mailctl plan -domain example.com   # expect exactly one CREATE alias
./mailctl apply -domain example.com  # expect [1/1] and "Applied 1 actions."
./mailctl plan -domain example.com   # expect no changes
```

The third command is the real test: an apply that does not converge is the failure mode
this whole design exists to prevent.

- [ ] **Step 6: Commit**

`mailctl.yaml` is git-ignored and must not be committed. Commit only whatever code
changes step 3 required.

```bash
git status --short   # mailctl.yaml must NOT appear
gofmt -l . && go vet ./... && go test ./...
git commit -am "fix: reconcile diff against live example state"   # only if step 3 needed changes
```

---

## Self-review

**Spec coverage.** Every core-scope requirement maps to a task: repository and module
(1), YAML config with `${VAR}` and the `version` gate (1), validation collected with
`errors.Join` (2), plan/apply model and MANUAL entries (3), shared Cloudflare envelope
and pagination (4), credential resolution and generation with one-time reporting and
`-secrets-out` (5), DNS diff with the carried-over per-kind conflict rules and
`-replace-dns` (6), the provider registry that keeps the engine free of provider names
(7), full Purelymail `/api/v0` coverage including routing rules and reconcilable recovery
methods (8, 9), DNS-before-mail ordering and the multi-provider DNS union (10),
`-prune` with individually named objects and a typed confirmation (11), the CLI and the
example config (12), migration and idempotence proof (13).

Deferred by design, with the plan that carries them: SPF merge, DMARC/TLS-RPT/BIMI
builders, MTA-STS and its Worker (plan 2); `cfrouting`, `cfsending`, `audit`, `import`,
`mailbox`/`alias`/`apppass` subcommands, and deleting the old `example/internal/mailsetup`
(plan 3). `mailctl` names these subcommands explicitly in Task 12 so they fail with a
pointer rather than "unknown subcommand". `checkAccountCredit` and the app-credential
endpoints are implemented in Task 8 but not wired to a command until plan 3.

**Type consistency.** `mail.Provider` is `Name`/`DesiredDNS`/`Actual`/`Plan` in Tasks 7,
9, and 10. `plan.Action` fields are `Op`/`Resource`/`Domain`/`Provider`/`Detail`/`Do`
throughout. `dns.Provider` is `Zone`/`Records`/`Create`/`Delete` in Tasks 6 and 10.
`secret.Resolver.Password` takes `(domain string, m config.Mailbox)` in Tasks 5 and 9.
`mail.Unregister` is exported in Task 10 Step 2 and its two call sites in
`internal/mail/registry_test.go` are updated in the same step.

**Known soft spot.** Three Purelymail response shapes — `listPasswordReset`,
`createAppPassword`, `checkAccountCredit` — are decoded from field names that were not
observed on a live response. Task 8 Step 6 verifies the two read-only ones with a curl
before anything depends on them. `listPasswordReset` is the one that matters here:
`Actual` calls it for every mailbox, so a wrong key silently yields zero recovery methods
and Task 9's reconciliation would re-upsert them on every run. If Task 13 Step 3 shows a
recurring recovery upsert, this is the cause.
