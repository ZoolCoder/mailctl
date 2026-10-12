package importer

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/mail"
	"gopkg.in/yaml.v3"
)

func liveState() mail.State {
	return mail.State{
		DomainExists: true,
		Settings:     mail.Settings{AllowAccountReset: true},
		Mailboxes: []mail.Mailbox{
			{Address: "contact@a.com", Recovery: []mail.Recovery{
				{Type: "email", Target: "fallback@example.com", Description: "personal"},
			}},
			{Address: "sales@a.com"},
		},
		Aliases:  []mail.Alias{{ID: "7", Match: "info", To: []string{"contact@a.com"}}},
		CatchAll: &mail.CatchAll{ID: "8", To: []string{"contact@a.com"}},
	}
}

func TestRenderProducesParseableConfig(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// The rendered block is a domains entry, so wrap it to parse it whole.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Fatalf("rendered config does not parse:\n%s\nerror: %v", full, err)
	}

	if len(cfg.Domains) != 1 {
		t.Fatalf("parsed %d domains, want 1", len(cfg.Domains))
	}
	d := cfg.Domains[0]
	if d.Name != "a.com" || len(d.Mail.Providers) != 1 || d.Mail.Providers[0] != "purelymail" {
		t.Errorf("domain = %+v", d)
	}
	if len(d.Mailboxes) != 2 {
		t.Errorf("mailboxes = %+v, want both", d.Mailboxes)
	}
	if len(d.Aliases) != 1 || d.Aliases[0].Match != "info" {
		t.Errorf("aliases = %+v", d.Aliases)
	}
	if d.CatchAll == nil || len(d.CatchAll.To) != 1 {
		t.Errorf("catchAll = %+v", d.CatchAll)
	}

	// Validate the parsed config to ensure it can actually load.
	if err := cfg.Validate(); err != nil {
		t.Errorf("rendered config fails validation: %v", err)
	}
}

func TestRenderGivesEveryMailboxAPasswordEnvPlaceholder(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if !strings.Contains(got, "MAILCTL_CONTACT_A_COM_PASSWORD") {
		t.Errorf("expected a derived placeholder variable name:\n%s", got)
	}
	if !strings.Contains(got, "cannot be read back") {
		t.Errorf("the block should say why the placeholder is there:\n%s", got)
	}
}

func TestRenderCarriesRecoveryMethods(t *testing.T) {
	got, err := Render("a.com", "a.com", "purelymail", liveState())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Parse and validate the rendered config to check recovery structure.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Fatalf("rendered config does not parse: %v", err)
	}

	if len(cfg.Domains) != 1 {
		t.Fatalf("parsed %d domains, want 1", len(cfg.Domains))
	}

	// Find the contact@a.com mailbox and check its recovery methods.
	var contactBox *config.Mailbox
	for i := range cfg.Domains[0].Mailboxes {
		if cfg.Domains[0].Mailboxes[i].Address == "contact@a.com" {
			contactBox = &cfg.Domains[0].Mailboxes[i]
			break
		}
	}
	if contactBox == nil {
		t.Fatalf("contact@a.com mailbox not found")
	}
	if len(contactBox.Recovery) != 1 {
		t.Errorf("contact@a.com has %d recovery methods, want 1", len(contactBox.Recovery))
	}
	if contactBox.Recovery[0].Type != "email" || contactBox.Recovery[0].Target != "fallback@example.com" {
		t.Errorf("recovery method = %+v, want type=email target=fallback@example.com", contactBox.Recovery[0])
	}
}

func TestRenderOmitsEmptySections(t *testing.T) {
	got, err := Render("a.com", "a.com", "cfrouting", mail.State{DomainExists: true})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, absent := range []string{"mailboxes:", "aliases:", "catchAll:"} {
		if strings.Contains(got, absent) {
			t.Errorf("empty section %q should be omitted:\n%s", absent, got)
		}
	}

	// Verify the minimal block still parses and validates.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Errorf("minimal rendered config does not parse: %v\n%s", err, full)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("minimal rendered config fails validation: %v", err)
	}
}

func TestRenderDisambiguatesCollidingMailboxes(t *testing.T) {
	// Two addresses that collide under the basic placeholder scheme:
	// a-b@c.com and a_b@c.com both map to MAILCTL_A_B_C_COM_PASSWORD
	state := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "a-b@c.com"},
			{Address: "a_b@c.com"},
		},
	}

	got, err := Render("c.com", "c.com", "purelymail", state)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Extract the two passwordEnv values and verify they differ.
	lines := strings.Split(got, "\n")
	var passwords []string
	for i, line := range lines {
		if strings.Contains(line, "passwordEnv:") && i > 0 {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				passwords = append(passwords, parts[len(parts)-1])
			}
		}
	}

	if len(passwords) != 2 {
		t.Fatalf("expected 2 passwordEnv lines, got %d:\n%s", len(passwords), got)
	}
	if passwords[0] == passwords[1] {
		t.Errorf("colliding addresses produced identical passwordEnv: %s", passwords[0])
	}

	// Verify both are still valid env var names.
	for _, pwd := range passwords {
		if !strings.HasPrefix(pwd, "MAILCTL_") || !strings.HasSuffix(pwd, "_PASSWORD") {
			t.Errorf("invalid password env name: %s", pwd)
		}
	}
}

func TestRenderProducesDeterministicOutput(t *testing.T) {
	// Render the same state twice and verify byte-identical output.
	state := mail.State{
		DomainExists: true,
		Mailboxes: []mail.Mailbox{
			{Address: "a-b@c.com"},
			{Address: "a_b@c.com"},
		},
	}

	got1, err1 := Render("c.com", "c.com", "purelymail", state)
	if err1 != nil {
		t.Fatalf("first Render: %v", err1)
	}

	got2, err2 := Render("c.com", "c.com", "purelymail", state)
	if err2 != nil {
		t.Fatalf("second Render: %v", err2)
	}

	if got1 != got2 {
		t.Errorf("Render produced different output on identical input:\nFirst:\n%s\nSecond:\n%s", got1, got2)
	}
}

func TestRenderWithPrefixAlias(t *testing.T) {
	state := mail.State{
		DomainExists: true,
		Aliases: []mail.Alias{
			{ID: "1", Match: "support", Prefix: true, To: []string{"contact@a.com"}},
		},
	}

	got, err := Render("a.com", "a.com", "purelymail", state)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	// Parse and verify the prefix alias roundtrips correctly.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Fatalf("rendered config does not parse: %v", err)
	}

	if len(cfg.Domains) != 1 || len(cfg.Domains[0].Aliases) != 1 {
		t.Fatalf("expected 1 domain with 1 alias, got %d domains", len(cfg.Domains))
	}

	alias := cfg.Domains[0].Aliases[0]
	// The match field will include the * since it was rendered that way.
	if alias.Match != "support*" {
		t.Errorf("alias match = %q, want support*", alias.Match)
	}

	// Check that Prefix() correctly identifies this as a prefix match.
	if !alias.Prefix() {
		t.Errorf("alias.Prefix() = false, want true (should be prefix match)")
	}

	// Verify the MatchUser() method returns the local part without the asterisk.
	if alias.MatchUser() != "support" {
		t.Errorf("alias.MatchUser() = %q, want support", alias.MatchUser())
	}
}

// TestRenderMS365EmitsACommentedLicenseStub is the Finding 4 regression test.
// license and usageLocation cannot be read back from Microsoft Graph in a
// form config wants (Graph reports a skuId GUID, not the skuPartNumber, and
// never returns the domain-level default at all), so the block must be
// commented rather than either omitted (today's silent validation failure)
// or filled with a guessed value that would parse as a plausible-looking
// wrong one.
func TestRenderMS365EmitsACommentedLicenseStub(t *testing.T) {
	got, err := Render("a.com", "a.com", "ms365", mail.State{
		DomainExists: true,
		Mailboxes:    []mail.Mailbox{{Address: "sales@a.com"}},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	for _, want := range []string{"# ms365:", "license", "usageLocation"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected the commented stub to mention %q:\n%s", want, got)
		}
	}
	// The stub must be commented out, not live config: an active but
	// placeholder license would silently pass this decode and only fail
	// later, less clearly, against the tenant's real subscribedSkus.
	for _, line := range strings.Split(got, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "license:") || strings.HasPrefix(trimmed, "usageLocation:") {
			t.Errorf("license/usageLocation line is not commented out: %q", line)
		}
	}

	// The rendered block still parses as YAML (comments are inert), but
	// config.Validate must still refuse it: the operator has not filled in
	// the commented block yet, and this stub deliberately does not guess.
	full := "version: 1\ndomains:\n" + indent(got, "  ")
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(full), &cfg); err != nil {
		t.Fatalf("rendered config does not parse:\n%s\nerror: %v", full, err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("want Validate to still reject the config until the operator fills in the ms365 block")
	} else if !strings.Contains(err.Error(), "ms365") {
		t.Errorf("Validate error = %q, want it to name the missing ms365 block", err)
	}
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
