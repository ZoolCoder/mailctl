// Command mailctl reconciles email configuration across domains.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/configedit"
	cfdns "github.com/zoolcoder/mailctl/internal/dns/cloudflare"
	"github.com/zoolcoder/mailctl/internal/engine"
	"github.com/zoolcoder/mailctl/internal/importer"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/mail/ms365"
	"github.com/zoolcoder/mailctl/internal/mail/purelymail"
	"github.com/zoolcoder/mailctl/internal/secret"
	"github.com/zoolcoder/mailctl/internal/worker"

	// Providers register themselves at init time. This is the only place that
	// names a provider package other than purelymail and ms365, which mailbox
	// passwd and apppass also call directly.
	_ "github.com/zoolcoder/mailctl/internal/mail/cfrouting"
	_ "github.com/zoolcoder/mailctl/internal/mail/cfsending"
)

// version is overridden at build time with -ldflags "-X main.version=...".
// When it isn't, resolveVersion falls back to the module version Go itself
// embeds, so a "go install ...@v0.1.0" binary still reports something useful.
var version = "dev"

// resolveVersion picks what "mailctl version" prints. ldflagsVersion, if set
// to anything other than the "dev" default, wins outright: a release
// pipeline may want to stamp an exact string. Otherwise mainVersion is used
// when it's a real version; "(devel)" and "" (a working-tree build, or a Go
// version too old to embed build info) keep the existing "dev" wording
// rather than surfacing "(devel)" to a user. For a working-tree build, a
// truncated revision is appended, since that's what someone can actually
// hand back in a bug report; "modified" marks an unclean tree.
func resolveVersion(ldflagsVersion, mainVersion, revision string, modified bool) string {
	if ldflagsVersion != "dev" {
		return ldflagsVersion
	}

	v := mainVersion
	if v == "" || v == "(devel)" {
		v = "dev"
	}

	if v != "dev" {
		return v
	}

	if len(revision) > 12 {
		revision = revision[:12]
	}
	switch {
	case revision != "" && modified:
		return fmt.Sprintf("%s (%s, modified)", v, revision)
	case revision != "":
		return fmt.Sprintf("%s (%s)", v, revision)
	default:
		return v
	}
}

// buildVersion reads the module version Go embeds via runtime/debug and
// resolves it against version, the possibly ldflags-overridden default.
// ReadBuildInfo returns (info, ok) and can't be faked in a test, so this is
// the single untestable line; resolveVersion carries the actual logic.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return resolveVersion(version, "", "", false)
	}

	var revision string
	var modified bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}

	return resolveVersion(version, info.Main.Version, revision, modified)
}

const usage = `mailctl reconciles email configuration from a YAML file.

Usage:
  mailctl plan                       [flags]   show what would change (default)
  mailctl apply                      [flags]   make the changes
  mailctl audit                      [flags]   check DNS and deliverability status
  mailctl import                     [flags]   print a config block from live provider state
  mailctl mailbox add <address>      [flags]   add a mailbox to the config, then apply
  mailctl mailbox rm  <address>                remove a mailbox from the config only
  mailctl mailbox passwd <address>   [flags]   change a mailbox's credential at the provider
  mailctl alias add <local-part>     [flags]   add an alias to the config, then apply
  mailctl alias rm  <local-part>     [flags]   remove an alias from the config only
  mailctl apppass create <address>   [flags]   create an application credential
  mailctl apppass rm     <address>   [flags]   delete an application credential
  mailctl version

Flags:
  -config string        config file (default "mailctl.yaml")
  -domain value         limit to this domain; repeat for several
  -prune                delete provider-side objects absent from the config
  -prune-mailboxes      allow -prune to delete mailboxes; deleting a mailbox destroys its mail
  -replace-dns          replace conflicting MX, SPF, DKIM, DMARC records
  -yes                  skip the deletion confirmation prompt
  -secrets-out string   write generated credentials to this file (mode 0600)
  -provider string      provider to import from (import only)
  -zone string          Cloudflare zone name (import only, defaults to the domain)
  -password-env string  environment variable holding the credential (mailbox add|passwd)
  -alias-domain string  domain the alias belongs to (alias add|rm)
  -to value             alias target address; repeat for several (alias add)
  -name string          app credential label (apppass)

Environment:
  CLOUDFLARE_API_TOKEN   required
  PURELYMAIL_API_TOKEN   required when a domain uses the purelymail provider
  MS365_TENANT_ID        required when a domain uses the ms365 provider
  MS365_CLIENT_ID        required when a domain uses the ms365 provider
  MS365_CLIENT_SECRET    required when a domain uses the ms365 provider
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
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run is the only seam a generated credential could reach a writer through,
// so stdin/stdout/stderr are parameters rather than direct os.* references:
// tests can assert a credential lands on stderr and never on stdout.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// -h and --help must be handled before the prefix guard below: that guard
	// only promotes a non-dash token to command, so with either of these as
	// args[0] command would stay "plan" and args would keep "-h"/"--help" as
	// an unrecognized flag, which flag.Parse rejects with exit 1 instead of
	// the zero-exit, stdout usage every other help spelling gets.
	if len(args) > 0 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Fprint(stdout, usage)
		return nil
	}

	command := "plan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}

	// mailbox, alias, and apppass take a verb and a target address/match as
	// bare positional arguments before any flags (e.g. "mailbox add
	// sales@a.com -password-env SALES_PW"). flag.Parse stops at the first
	// non-flag token, so these two tokens must be shifted off here, the same
	// way command was, or -password-env/-alias-domain/-to/-name would never
	// be recognized as flags at all. Each shift is guarded the same way the
	// command shift above is: a token starting with "-" is left for
	// flags.Parse rather than consumed as the verb or target, so "mailbox add
	// -password-env X" reports the usage error instead of treating
	// "-password-env" as the address and "X" as a stray argument.
	var verb, target string
	switch command {
	case "mailbox", "alias", "apppass":
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			verb, args = shift(args)
		}
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			target, args = shift(args)
		}
		target = strings.ToLower(target)
	}

	switch command {
	case "version":
		fmt.Fprintln(stdout, "mailctl", buildVersion())
		return nil
	case "help":
		fmt.Fprint(stdout, usage)
		return nil
	case "plan", "apply", "audit", "import", "mailbox", "alias", "apppass":
	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown subcommand %q", command)
	}

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	// Output is suppressed here and written explicitly below: flag.Parse
	// calls Usage synchronously, before it returns, so a subcommand-scoped
	// -h/--help/help would otherwise land its usage text on stderr before
	// this function ever sees flag.ErrHelp and gets a chance to redirect it
	// to stdout.
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}

	var domains, aliasTargets domainList
	configPath := flags.String("config", "mailctl.yaml", "path to the YAML configuration")
	prune := flags.Bool("prune", false, "delete provider-side objects absent from the config")
	pruneMailboxes := flags.Bool("prune-mailboxes", false,
		"allow -prune to delete mailboxes; deleting a mailbox destroys its mail")
	replaceDNS := flags.Bool("replace-dns", false, "replace conflicting MX, SPF, DKIM, DMARC records")
	assumeYes := flags.Bool("yes", false, "skip the deletion confirmation prompt")
	secretsOut := flags.String("secrets-out", "", "write generated credentials to this file")
	importProvider := flags.String("provider", "", "provider to import from (import only)")
	importZone := flags.String("zone", "", "Cloudflare zone name (import only, defaults to the domain)")
	passwordEnv := flags.String("password-env", "", "environment variable holding the credential (mailbox add|passwd)")
	aliasDomain := flags.String("alias-domain", "", "domain the alias belongs to (alias add|rm)")
	appPassName := flags.String("name", "", "app credential label (apppass)")
	flags.Var(&domains, "domain", "limit to this domain; repeat for several")
	flags.Var(&aliasTargets, "to", "alias target address; repeat for several")

	if err := flags.Parse(args); err != nil {
		// A subcommand-scoped -h/--help/help (e.g. "mailctl plan -h") returns
		// flag.ErrHelp, which is success, not failure: it must exit zero with
		// usage on stdout, the same as the bare-command spellings handled
		// above, rather than propagating as "error: flag: help requested".
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return nil
		}
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usage)
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := rejectScopedFlags(flags, command, verb); err != nil {
		return err
	}
	// PruneMailboxes only changes what Prune plans; without Prune it would
	// silently do nothing, leaving an operator to conclude their tenant had
	// no unmanaged mailboxes when the flag never took effect.
	if *pruneMailboxes && !*prune {
		return fmt.Errorf(
			"-prune-mailboxes has no effect without -prune; add -prune to delete unmanaged mailboxes, or drop -prune-mailboxes")
	}

	cfg, err := config.Load(*configPath, os.Getenv)
	if err != nil {
		return err
	}

	// "At least one domain" is a precondition of the commands that reconcile
	// against a provider, not a property of a config document: import's whole
	// purpose is to bootstrap the first domain, so it alone is exempt.
	if command != "import" && len(cfg.Domains) == 0 {
		return fmt.Errorf("config %s declares no domains", *configPath)
	}

	secrets := secret.NewResolver(os.Getenv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// mailbox and alias dispatch here, ahead of the CLOUDFLARE_API_TOKEN check
	// below: rm (either) and mailbox passwd only touch the config file or
	// Purelymail, so they return before that check would ever apply to them.
	// add falls through past this block by setting command = "apply" without
	// returning, since only its reconciling apply needs Cloudflare.
	if command == "mailbox" || command == "alias" || command == "apppass" {
		switch command {
		case "mailbox":
			address := target
			if address == "" {
				return errors.New("usage: mailctl mailbox add|rm|passwd <address>")
			}
			if !strings.Contains(address, "@") {
				return fmt.Errorf("mailbox address %q has no @; expected local@domain", address)
			}
			domainName := domainOf(address)

			switch verb {
			case "add":
				if err := requireDomainInScope(domainName, domains); err != nil {
					return err
				}
				if err := configedit.AddMailbox(*configPath, domainName, address, *passwordEnv); err != nil {
					return err
				}
				noteConfigRewritten(stderr, *configPath)
			case "rm":
				if err := configedit.RemoveMailbox(*configPath, domainName, address); err != nil {
					return err
				}
				noteConfigRewritten(stderr, *configPath)
				fmt.Fprintln(stderr,
					"Removed from the config. The mailbox still exists at the provider; run apply -prune -prune-mailboxes to delete it and its mail.")
				return nil
			case "passwd":
				return changePassword(ctx, cfg, address, *passwordEnv, secrets, *secretsOut, stderr)
			default:
				return fmt.Errorf("unknown mailbox verb %q; want add, rm, or passwd", verb)
			}

		case "alias":
			match := target
			if match == "" || *aliasDomain == "" {
				return errors.New("usage: mailctl alias add|rm <local-part> -alias-domain <domain> [-to a@b.com]")
			}
			switch verb {
			case "add":
				if len(aliasTargets) == 0 {
					return errors.New("alias add needs at least one -to address")
				}
				if err := requireDomainInScope(*aliasDomain, domains); err != nil {
					return err
				}
				if err := configedit.AddAlias(*configPath, *aliasDomain, match, aliasTargets); err != nil {
					return err
				}
				noteConfigRewritten(stderr, *configPath)
			case "rm":
				if err := configedit.RemoveAlias(*configPath, *aliasDomain, match); err != nil {
					return err
				}
				noteConfigRewritten(stderr, *configPath)
				fmt.Fprintln(stderr,
					"Removed from the config. The rule still exists at the provider; run apply -prune to delete it.")
				return nil
			default:
				return fmt.Errorf("unknown alias verb %q; want add or rm", verb)
			}

		case "apppass":
			return appPassword(ctx, cfg, verb, target, *appPassName, *secretsOut, stderr)
		}

		// mailbox add and alias add fall through here: reload the edited
		// config and apply it, so the change reaches the provider in the
		// same command. The reload must happen before runner is built below,
		// which captures cfg by value; reloading afterward would leave the
		// runner working from the pre-edit config.
		cfg, err = config.Load(*configPath, os.Getenv)
		if err != nil {
			return err
		}
		command = "apply"
	}

	// Every command still reachable here (plan, apply, audit, import, and the
	// mailbox/alias add fallthrough above) reconciles against Cloudflare.
	cloudflareToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if cloudflareToken == "" {
		return errors.New("CLOUDFLARE_API_TOKEN is required")
	}

	api := cfapi.New(cfg.Cloudflare.BaseURL, cloudflareToken)

	var deployer *worker.Deployer
	if cfg.Cloudflare.AccountID != "" {
		deployer = worker.New(api, cfg.Cloudflare.AccountID)
	}

	zones := cfdns.New(api, cfg.Cloudflare.TTL)

	deps := mail.Deps{
		Cloudflare:        api,
		AccountID:         cfg.Cloudflare.AccountID,
		PurelymailBaseURL: cfg.Purelymail.BaseURL,
		Zones:             zones,
		Getenv:            os.Getenv,
	}

	if command == "import" {
		if len(domains) != 1 {
			return errors.New("import needs exactly one -domain")
		}
		name := domains[0]

		providerName := *importProvider
		if providerName == "" {
			return errors.New("import needs -provider (purelymail, cfrouting, cfsending, or ms365)")
		}
		zoneName := *importZone
		if zoneName == "" {
			zoneName = name
		}

		provider, err := mail.Open(providerName, deps)
		if err != nil {
			return err
		}
		stub := config.Domain{Name: name, ZoneName: zoneName,
			Mail: config.Mail{Providers: []string{providerName}}}

		state, err := provider.Actual(ctx, stub)
		if err != nil {
			return err
		}
		block, err := importer.Render(name, zoneName, providerName, state)
		if err != nil {
			return err
		}
		fmt.Fprint(stdout, block)
		return nil
	}

	runner := engine.New(cfg, zones, deployer, deps, engine.Options{
		Domains:        domains,
		Prune:          *prune,
		PruneMailboxes: *pruneMailboxes,
		ReplaceDNS:     *replaceDNS,
		Secrets:        secrets,
	})

	if command == "audit" {
		domains, err := runner.Domains()
		if err != nil {
			return err
		}
		failed := false
		for _, d := range domains {
			desired, err := runner.Desired(ctx, d)
			if err != nil {
				return err
			}
			report := audit.Run(ctx, d, desired, audit.NetResolver(), audit.HTTPFetcher())
			report.Render(stdout)
			if !report.OK() {
				failed = true
			}
		}
		if failed {
			return errors.New("audit found problems")
		}
		return nil
	}

	built, err := runner.Plan(ctx)
	if err != nil {
		return err
	}

	if command == "plan" {
		built.Render(stdout)
		if len(built.Executable()) != 0 {
			fmt.Fprintln(stdout, "\nRun `mailctl apply` to make these changes.")
		}
		return nil
	}

	built.Render(stdout)
	if built.Empty() {
		return nil
	}
	if !*assumeYes {
		// The prompt goes to stderr, not stdout: stdout is the pipeable
		// channel (e.g. `mailctl apply | tee log`), and a prompt hidden in a
		// pipe looks like a hang.
		if err := engine.Confirm(stdin, stderr, built); err != nil {
			return err
		}
	}

	applyErr := runner.Apply(ctx, built, stdout)

	// Report only credentials that were actually applied: a value generated
	// during planning but never set on the provider (because apply failed
	// part-way) would send the operator chasing a mailbox that does not
	// exist, and a rerun would generate a different value anyway.
	if applied := secrets.Applied(); len(applied) > 0 {
		if err := writeOrReport(stderr, *secretsOut, applied); err != nil {
			return errors.Join(applyErr, err)
		}
	}
	return applyErr
}

// shift returns the first element of args and the rest, or two empty/nil
// values if args is empty.
func shift(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

// domainOf returns the domain portion of an email address.
func domainOf(address string) string {
	_, domain, _ := strings.Cut(address, "@")
	return strings.ToLower(domain)
}

// requireDomainInScope rejects a mailbox/alias add whose edited domain would
// not actually be reconciled: add edits the config for editedDomain, then
// falls through to an apply limited to -domain (scope). With scope set to
// some other domain, that apply would create the mailbox or alias nowhere,
// write it to the config anyway, and exit 0 as if it had reached the
// provider. An empty scope means every domain, so it always passes.
func requireDomainInScope(editedDomain string, scope domainList) error {
	if len(scope) == 0 {
		return nil
	}
	for _, name := range scope {
		if strings.EqualFold(name, editedDomain) {
			return nil
		}
	}
	return fmt.Errorf("-domain %s does not include %s, the domain being edited", strings.Join(scope, ","), editedDomain)
}

// scopedFlags are meaningless or dangerous outside plan and apply. mailbox,
// alias, and apppass each name one target address on the command line, not a
// domain-wide reconciliation, so -prune (delete everything provider-side
// absent from the config), -prune-mailboxes (extend that to mailboxes), and
// -replace-dns apply to every domain in scope, not the one thing the operator
// named, and -yes would skip the prompt that is the only guard against that.
// import and audit never delete or write provider state at all. mailbox add
// and alias add do fall through to an internal apply, but engine.Options is
// built from these same flag values, so rejecting them here also keeps that
// internal apply from ever running with Prune, PruneMailboxes, or ReplaceDNS
// set, or its confirmation prompt skipped.
var scopedFlags = map[string]bool{"prune": true, "prune-mailboxes": true, "replace-dns": true, "yes": true}

// rejectScopedFlags errors on a flag from scopedFlags the operator actually
// set (via flags.Visit, not flags.VisitAll, so an unset default never
// triggers this) for a command it is not valid on.
func rejectScopedFlags(flags *flag.FlagSet, command, verb string) error {
	if command == "plan" || command == "apply" {
		return nil
	}
	label := command
	if verb != "" {
		label = command + " " + verb
	}
	var offense error
	flags.Visit(func(f *flag.Flag) {
		if offense == nil && scopedFlags[f.Name] {
			offense = fmt.Errorf("flag -%s is not valid for %s", f.Name, label)
		}
	})
	return offense
}

// noteConfigRewritten tells the operator the config file was fully
// re-encoded: configedit preserves comments and key order, but yaml.Node has
// no representation for a blank line, so any blank lines anywhere in the file
// are dropped, not just near the edited section. A user who hand-formatted
// the file should learn that from the tool, not from `git diff`.
func noteConfigRewritten(stderr io.Writer, path string) {
	fmt.Fprintf(stderr, "Note: %s was rewritten; comments and key order were preserved, blank lines were not.\n", path)
}

// writeOrReport writes generated credentials to secretsOut, or reports them
// to stderr when secretsOut is empty. A credential that was just set on a
// provider cannot be re-read from it, so a failed write must never be the
// only trace of the value: ReportTo runs before the write error is returned,
// putting the credential on stderr even though the file did not get it.
func writeOrReport(stderr io.Writer, secretsOut string, generated map[string]string) error {
	if secretsOut == "" {
		return secret.ReportTo(stderr, generated)
	}
	if err := secret.WriteFile(secretsOut, generated); err != nil {
		return errors.Join(err, secret.ReportTo(stderr, generated))
	}
	fmt.Fprintf(stderr, "Wrote %d generated credential(s) to %s\n", len(generated), secretsOut)
	return nil
}

// requirePurelymailDomain resolves address's domain in cfg and requires it to
// use only the purelymail provider, whose API is the only one addressed by
// mailbox address rather than a config-scoped identifier: nothing else would
// stop a typo'd or out-of-config address from reaching Purelymail directly.
// operation names the caller's action for the error message.
func requirePurelymailDomain(cfg config.Config, address, operation string) error {
	domainName := domainOf(address)
	d, ok := cfg.Domain(domainName)
	if !ok {
		return fmt.Errorf("domain %s is not in the config", domainName)
	}
	if len(d.Mail.Providers) == 1 && d.Mail.Providers[0] == purelymail.Name {
		return nil
	}
	if len(d.Mail.Providers) == 1 && d.Mail.Providers[0] == ms365.Name {
		return fmt.Errorf(
			"domain %s: %s is only supported for the purelymail provider; manage this ms365 domain from the Microsoft 365 admin center",
			domainName, operation)
	}
	return fmt.Errorf("domain %s: %s is only supported for the purelymail provider", domainName, operation)
}

// changePassword sets a new credential on an existing mailbox. A credential
// never goes in the config file, so this bypasses configedit entirely.
func changePassword(ctx context.Context, cfg config.Config, address, passwordEnv string,
	secrets *secret.Resolver, secretsOut string, stderr io.Writer) error {

	if err := requirePurelymailDomain(cfg, address, "changing a credential"); err != nil {
		return err
	}
	domainName := domainOf(address)

	token := os.Getenv("PURELYMAIL_API_TOKEN")
	if token == "" {
		return errors.New("PURELYMAIL_API_TOKEN is required")
	}
	credential, err := secrets.Password(domainName, config.Mailbox{Address: address, PasswordEnv: passwordEnv})
	if err != nil {
		return err
	}

	client := purelymail.NewClient(cfg.Purelymail.BaseURL, token)
	if err := client.ModifyUser(ctx, purelymail.UserChanges{UserName: address, NewPassword: &credential}); err != nil {
		return fmt.Errorf("mailbox %s: %w", address, err)
	}
	fmt.Fprintf(stderr, "Credential changed for %s\n", address)

	if generated := secrets.Generated(); len(generated) > 0 {
		return writeOrReport(stderr, secretsOut, generated)
	}
	return nil
}

// appPassword creates or deletes an application credential. These are shown
// once and cannot be listed, which is why they are not part of the config.
func appPassword(ctx context.Context, cfg config.Config, verb, address, name, secretsOut string, stderr io.Writer) error {
	if address == "" {
		return errors.New("usage: mailctl apppass create|rm <address> [-name label]")
	}
	if err := requirePurelymailDomain(cfg, address, "an app credential"); err != nil {
		return err
	}

	token := os.Getenv("PURELYMAIL_API_TOKEN")
	if token == "" {
		return errors.New("PURELYMAIL_API_TOKEN is required")
	}
	client := purelymail.NewClient(cfg.Purelymail.BaseURL, token)

	switch verb {
	case "create":
		credential, err := client.CreateAppPassword(ctx, address, name)
		if err != nil {
			return fmt.Errorf("mailbox %s: %w", address, err)
		}
		generated := map[string]string{address + " (app)": credential}
		return writeOrReport(stderr, secretsOut, generated)
	case "rm":
		if name == "" {
			return errors.New("apppass rm needs -name")
		}
		if err := client.DeleteAppPassword(ctx, address, name); err != nil {
			return fmt.Errorf("mailbox %s: app credential %s: %w", address, name, err)
		}
		return nil
	default:
		return fmt.Errorf("unknown apppass verb %q; want create or rm", verb)
	}
}
