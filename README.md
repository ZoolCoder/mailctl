<p align="center">
<img src=".github/mark.png" width="96" alt="mailctl">
</p>

<h1 align="center">mailctl</h1>

<p align="center">
<a href="https://github.com/ZoolCoder/mailctl/releases/latest"><img src="https://img.shields.io/github/v/release/ZoolCoder/mailctl?label=release" alt="Latest release"></a>
<a href="https://github.com/ZoolCoder/mailctl/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ZoolCoder/mailctl/ci.yml?label=ci" alt="CI"></a>
<a href="https://zoolcoder.github.io/mailctl/"><img src="https://img.shields.io/badge/docs-manual-7C3AED" alt="Manual"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/ZoolCoder/mailctl" alt="MIT"></a>
<a href="https://github.com/ZoolCoder/mailctl/issues"><img src="https://img.shields.io/github/issues/ZoolCoder/mailctl" alt="Issues"></a>
</p>


Declarative email configuration for custom domains. One YAML file describes the
DNS records, mailboxes, aliases, routing and deliverability policy for every
domain you own; `mailctl` works out what has to change, shows you, and then
changes it.

It is a single Go binary with three non-stdlib dependencies: a YAML parser,
and two small ZoolCoder modules its local admin page is built on. No daemon, no state file, no
lock — the live provider APIs are the state.

```console
$ mailctl plan

example.com
-----------
  CREATE  dns         MX example.com -> mailserver.purelymail.com  [purelymail]
  CREATE  dns         TXT example.com -> v=spf1 include:_spf.purelymail.com ~all
  CREATE  dns         CNAME purelymail1._domainkey.example.com
  CREATE  domain      add example.com  [purelymail]
  CREATE  mailbox     create contact@example.com  [purelymail]

9 actions

Run `mailctl apply` to make these changes.
```

**Documentation: <https://zoolcoder.github.io/mailctl/>**

## Providers

| Provider | Inbound | Mailboxes | Aliases | Catch-all |
|---|---|---|---|---|
| `purelymail` | yes | yes | yes | yes |
| `ms365` | yes | yes | no ¹ | no ¹ |
| `cfrouting` (Cloudflare Email Routing) | yes | — | yes | yes |
| `zoho` (Zoho Mail) | yes | yes | yes ² | yes ² |
| `gworkspace` (Google Workspace) | yes | yes | yes ² | no ³ |
| `cfsending` (Cloudflare Email Sending) | outbound only | — | — | — |
| `resend` | outbound only | — | — | — |

¹ Not because `mailctl` declines to implement them. Microsoft Graph exposes
`proxyAddresses` as read-only and offers no catch-all surface, so `mailctl`
rejects those config blocks with an error naming the admin centre rather than
accepting them and silently doing nothing.

² An alias is an extra address on one mailbox of the same domain, so it takes
exactly one target and no trailing `*`. The Zoho catch-all takes one target.

³ The Admin SDK has no routing API; set catch-all under Gmail > Default routing
in the Admin console. The Google DKIM key has no API either: copy its TXT value
into `mail.gworkspace.dkim`.

DNS is managed in Cloudflare. Deliverability — SPF, DKIM, DMARC, MTA-STS,
TLS-RPT, BIMI — is managed for any provider combination, including merging every
provider's SPF requirement into the single TXT record RFC 7208 permits.

## Install

On macOS or Linux with Homebrew:

```console
$ brew tap zoolcoder/mailctl https://github.com/zoolcoder/mailctl
$ brew install --cask mailctl
```

Or download a binary for your platform from the
[latest release](https://github.com/zoolcoder/mailctl/releases/latest) — Linux,
macOS and Windows, `amd64` and `arm64`, with SHA-256 checksums:

```console
$ tar -xzf mailctl_linux_amd64.tar.gz
$ ./mailctl version
```

With a Go toolchain, Go 1.26 or newer:

```console
$ go install github.com/zoolcoder/mailctl/cmd/mailctl@latest
```

Or from a checkout:

```console
$ go build ./cmd/mailctl
```

## Quick start

```yaml
# mailctl.yaml
version: 1

cloudflare:
  accountId: ${CLOUDFLARE_ACCOUNT_ID}

domains:
  - name: example.com
    mail:
      provider: purelymail
    mailboxes:
      - address: contact@example.com
```

Put it at `~/.config/mailctl/mailctl.yaml` (or pass `-config`), store the
tokens in the macOS Keychain (or export them), and check the setup:

```console
$ security add-generic-password -U -s mailctl -a CLOUDFLARE_API_TOKEN -w
$ security add-generic-password -U -s mailctl -a PURELYMAIL_API_TOKEN -w
$ mailctl doctor                                 # config, credentials, APIs, DNS
$ mailctl plan                                   # read-only
$ mailctl apply                                  # make it so
$ mailctl audit                                  # verify through a real resolver
```

Omitting `passwordEnv` on a mailbox makes `mailctl` generate the credential and
report it exactly once — when the mailbox is genuinely created, not when it is
planned. On macOS it goes to the Keychain (service `mailctl`, account = the
address); `-secrets-out` writes it to a `0600` file instead and refuses a path
that already exists.

`mailctl ui` opens a local admin page on a loopback port: a dashboard that
names the next step and each domain's health, each domain's declared mailboxes,
aliases and policy, and the same plan and audit the CLI prints, each run only
when you press the button. Light, dark or auto, in English or Arabic (right to
left), with charts of recent runs and the plan's mix. It answers
on this machine only, with no login, and nothing on it applies; the page shows
you a plan, the terminal executes one.

See the [quickstart](https://zoolcoder.github.io/mailctl/mailctl/quickstart.html)
for the full walkthrough.

## Use with an AI agent

mailctl ships as a Claude Code plugin: six skills, five slash commands, a
read-only reviewer agent, a guard hook and an MCP server (`mailctl mcp`).

```console
/plugin marketplace add zoolcoder/mailctl
/plugin install mailctl --marketplace zoolcoder/mailctl
```

Then ask for what you want: "set up mail for example.com", "why does my mail
land in spam", "add a mailbox for sales". The agent edits the config, shows you
the plan, and applies only that plan after you say yes. It cannot delete
anything, and it never sees a credential: generated ones go to the Keychain.
Codex, Cursor, Gemini and Copilot get the same rules from `adapters/`. See
[Agents and MCP](https://zoolcoder.github.io/mailctl/mailctl/agents.html).

## Design principles

These are the rules the code is actually held to, not aspirations.

**Plan before apply.** `plan` reads live state from every provider and prints an
ordered list of actions. It performs no writes, and it performs no I/O once
planning has begun — every provider does its reading first, then computes actions
with none.

**Idempotence.** Running `apply` twice is the same as running it once. A converged
domain reports `No changes.` Actions are ordered so a partial failure can be
resumed by rerunning.

**Never silently ignore configuration.** Where a provider's API cannot express
something, the config rejects it with an error naming the manual route. An
accepted-and-ignored setting reads to the operator as a setting that is in force,
which is worse than an error. An ignored `requireTwoFactorAuthentication` looks
exactly like enforced two-factor authentication.

**Credentials never reach stdout.** Not an API token, not an access token, not a
mailbox password. Generated credentials go to stderr or a `0600` file. Nothing
sensitive is ever stored in the config file — the config names an environment
variable and the value is read when it is needed.

**Destructive operations are awkward on purpose.** Deleting a mailbox destroys
mail, so it needs `-prune` *and* `-prune-mailboxes`, and then a confirmation that
asks you to type the domain name. Omitting `catchAll` from the config means
"leave whatever exists alone", not "delete it", because the two readings are
indistinguishable in YAML and one of them loses mail.

**Records mailctl does not recognise are left alone.** A conflicting record it
did not create fails the plan rather than being silently overwritten. Pass
`-replace-dns` once you have read what would be replaced.

## Testing

The suite runs entirely offline. Every provider API is faked with `httptest`, so
no token is needed and nothing external is contacted.

```console
$ go test ./...
$ gofmt -l .
$ go vet ./...
```

## Documentation

The site under `docs/` (English in `docs/en`, Arabic in `docs/ar`) is built with [Antora](https://antora.org), pinned as a
project-local dev dependency so nothing is installed globally:

```console
$ npm install
$ bundle config set --local path .bundle
$ bundle install      # asciidoctor-pdf, for the PDF export
$ npm run docs        # site and PDF in build/site
```

## Changelog

[CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions the code is held to.
[ROADMAP.md](ROADMAP.md) records what is planned, what is deliberately not
planned, and why. Security issues: [SECURITY.md](SECURITY.md). Help: [SUPPORT.md](SUPPORT.md).
Governance: [GOVERNANCE.md](GOVERNANCE.md).

## License

MIT — see [LICENSE](LICENSE). Third-party notices: [NOTICE.md](NOTICE.md).
