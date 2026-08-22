# Changelog

Notable changes per release. This project follows
[semantic versioning](https://semver.org). While the major version is `0`, the
config schema and CLI flags may change between minor versions; anything that
would break an existing `mailctl.yaml` or a scripted invocation is called out
under **Breaking**.

## Unreleased

### Added

- `mailctl ui`: a local, read-only admin page for browsing what `plan` and
  `audit` would report. Server-rendered Go pages on the shared ZoolCoder admin
  shell (`github.com/zoolcoder/zcadmin`): a dashboard, a page per domain with
  its declared mailboxes, aliases, routing, deliverability policy and desired
  DNS records, the plan grouped by domain, the audit with per-check pass/fail,
  an activity log, and Settings. It runs as a foreground server on `127.0.0.1`
  with a kernel-chosen port, reads credentials from the environment exactly
  like every other command, and runs a plan or an audit only when you press the
  button. One password guards it: the first visit sets it, and the hash and the
  activity log are the only files it writes, under `$XDG_DATA_HOME/mailctl` or
  `-data`. A non-loopback `-addr` is refused without `-insecure`. Config
  authoring and `apply` are not part of this release.
- `plan -json`: prints the action list as JSON (`schemaVersion` 1) instead of
  the human summary, for gating a CI pipeline on whether anything would change.
  The local UI renders through the same projection, so a script and the UI can
  never disagree about what a plan intends to do.
- A Homebrew tap: `brew install zoolcoder/tap/mailctl` installs the published
  release binary on macOS and Linux, `arm64` and `amd64`, with every archive's
  SHA-256 pinned. The formula lives in
  [zoolcoder/homebrew-tap](https://github.com/zoolcoder/homebrew-tap); this
  repository is unchanged by it apart from the install instructions.

## v0.1.0 — 2026-08-11

First release.

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
  SHA-256 checksums. Attached shortly after the tag was cut, by a release
  workflow added at the same time.

### Security

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
