# Changelog

Notable changes per release. This project follows
[semantic versioning](https://semver.org). While the major version is `0`, the
config schema and CLI flags may change between minor versions; anything that
would break an existing `mailctl.yaml` or a scripted invocation is called out
under **Breaking**.

## v0.1.1 — 2026-10-13

### Fixed

- Release packages: the deb, rpm and apk descriptions were unquoted YAML and
  broke the release configuration.

### Changed

- The documentation locks zc-supplemental-ui v0.2.0, so the site builds in CI
  with the Arabic translation and the PDF exports.
- The Homebrew cask arrives as a pull request into `develop`, the branch
  `brew tap` clones.
- Dependabot also tracks the gems that build the PDF.

## v0.1.0 — 2026-10-12

First public release.

### Added

- Declarative reconciliation of email configuration from one YAML file: DNS
  records, mailboxes, aliases, routing and deliverability policy.
- `plan`, `apply`, `audit` and `import` commands, plus imperative `mailbox`,
  `alias` and `apppass` subcommands that edit the config and then apply.
- **Purelymail** provider: mailboxes, aliases, catch-all, application
  credentials and password-recovery methods.
- **Microsoft 365** provider: domain registration and verification, the service
  DNS records, and mailboxes as licensed users with a plan-time licence seat
  check. Aliases, catch-all and DKIM enablement are rejected in validation
  because Microsoft Graph cannot express them.
- **Cloudflare Email Routing** provider for forwarding, and **Cloudflare Email
  Sending** for outbound.
- Cloudflare DNS management that refuses to overwrite records it did not create
  unless `-replace-dns` is given.
- Deliverability: SPF, DKIM, DMARC, MTA-STS, TLS-RPT and BIMI, merging every
  provider's SPF requirement into the single TXT record RFC 7208 permits, and
  optionally deploying a Cloudflare Worker to serve the MTA-STS policy.
- `mailctl version` resolves its own version from the module build info, so a
  binary installed from the module proxy reports its release and a local build
  reports its revision.
- Prebuilt binaries for Linux, macOS and Windows on `amd64` and `arm64`, with
  SHA-256 checksums.
- An agent layer, shaped like scoutjobs. `mailctl mcp` serves eleven tools over
  MCP on stdio (`doctor`, `mail_domains`, `mail_plan`, `mail_audit`,
  `mail_import`, `mail_apply`, `mailbox_add`, `mailbox_rm`, `alias_add`,
  `alias_rm`, `apppass_create`) with read-only and destructive annotations,
  and serves the skills as prompts. `mail_apply` applies only a plan saved by
  `mail_plan`, refuses on drift and refuses any deletion; a generated
  credential never appears in a reply.
- A Claude Code plugin: six skills (`mailctl-setup`, `mail-setup`,
  `mail-audit`, `mailbox-admin`, `deliverability-fix`, `provider-migrate`),
  five slash commands, a read-only `deliverability-reviewer` agent, and a
  PreToolUse hook that asks before `mailctl apply` with a prune or replace
  flag, with `-yes`, or without `-plan`. Install with
  `/plugin marketplace add zoolcoder/mailctl`. Adapters for Codex, Cursor,
  Gemini, Copilot and cloud agents live in `adapters/`.
- An eval suite in `evals/`, run with `make evals`.
- `mailctl doctor [-json]`: the binary, the Keychain, the config found and why,
  each credential and where it came from, one read-only call per provider API,
  and an NS lookup per zone.
- `mailctl domains [-json]`: the resolved config per domain, with no secret.
- `apply -plan <file>`: applies exactly a saved `plan -json` and refuses when
  live state has drifted since.
- `-edit-only` on `mailbox add` and `alias add`: edit the config and stop.
- `audit -json`: one report per domain with every check's want and got.
- `plan -json`: the action list as JSON (`schemaVersion` 1).
- Config lookup: `-config`, `$MAILCTL_CONFIG`, `./mailctl.yaml`, then
  `$XDG_CONFIG_HOME/mailctl/mailctl.yaml`.
- Credentials are read from the environment, then the macOS Keychain
  (service `mailctl`, account = the variable's name).
- `mailctl ui`: a local, read-only admin page on
  [toolshell](https://github.com/zoolcoder/toolshell): a dashboard, a page per
  domain, the plan grouped by domain, the audit per check, an activity log and
  Settings, with charts of recent runs and the plan's mix, in English or Arabic
  (right to left). It listens on loopback only, with
  no login, and refuses a foreign Host and any cross-site write.
- A Homebrew cask: `brew tap zoolcoder/mailctl https://github.com/zoolcoder/mailctl`
  then `brew install --cask mailctl`.

### Security

- Generated mailbox and app credentials go to the macOS Keychain by default
  (account = the address, or `address (app name)`). `-secrets-out` still
  writes a `0600` file; without a Keychain they go to stderr, or to a `0600`
  file under `$XDG_STATE_HOME/mailctl` when running under `mailctl mcp`.
- No credential reaches stdout on any path. Generated mailbox credentials go to
  stderr or to a `0600` file created with an exclusive open, and are reported
  only once the mailbox actually exists at the provider.
- A failing OAuth token request never echoes its response body, which can
  contain the client secret.
- Deleting a mailbox requires both `-prune` and `-prune-mailboxes`, then a
  confirmation that asks for the domain name to be typed.
- Omitting `catchAll` from the config means "leave it alone", never "delete it".

### Known limitations

- The Microsoft 365 provider has not been run against a real tenant. It is
  complete and covered by tests against a faked Graph API, but seven behaviours
  are documented rather than verified — see
  [ROADMAP.md](ROADMAP.md).
- The licence seat check is per domain, so several Microsoft 365 domains in one
  config sharing a tenant can each pass a check the other's demand would fail.
  The messages say so.
- Changing a mailbox's licence adds the new SKU without removing the old one.
  The plan output states this.
