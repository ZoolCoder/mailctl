# mailctl

Declarative email configuration for custom domains. One YAML file describes the
DNS records, mailboxes, aliases, routing and deliverability policy for every
domain you own; `mailctl` works out what has to change, shows you, and then
changes it.

It is a single Go binary with one non-stdlib dependency. No daemon, no state
file, no lock — the live provider APIs are the state.

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
| `cfsending` (Cloudflare Email Sending) | outbound only | — | — | — |

¹ Not because `mailctl` declines to implement them. Microsoft Graph exposes
`proxyAddresses` as read-only and offers no catch-all surface, so `mailctl`
rejects those config blocks with an error naming the admin centre rather than
accepting them and silently doing nothing.

DNS is managed in Cloudflare. Deliverability — SPF, DKIM, DMARC, MTA-STS,
TLS-RPT, BIMI — is managed for any provider combination, including merging every
provider's SPF requirement into the single TXT record RFC 7208 permits.

## Install

On macOS or Linux with Homebrew:

```console
$ brew install zoolcoder/tap/mailctl
```

Or download a binary for your platform from the
[latest release](https://github.com/zoolcoder/mailctl/releases/latest) — Linux,
macOS and Windows, `amd64` and `arm64`, with SHA-256 checksums:

```console
$ tar -xzf mailctl_v0.1.0_linux_amd64.tar.gz
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

```console
$ export CLOUDFLARE_API_TOKEN=... PURELYMAIL_API_TOKEN=...
$ mailctl plan                                   # read-only
$ mailctl apply -secrets-out first-run.txt       # make it so
$ mailctl audit                                  # verify through a real resolver
```

Omitting `passwordEnv` on a mailbox makes `mailctl` generate the credential and
report it exactly once — when the mailbox is genuinely created, not when it is
planned. `-secrets-out` writes those to a `0600` file and refuses a path that
already exists.

See the [quickstart](https://zoolcoder.github.io/mailctl/mailctl/quickstart.html)
for the full walkthrough.

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

The site under `docs/` is built with [Antora](https://antora.org), pinned as a
project-local dev dependency so nothing is installed globally:

```console
$ npm install
$ npm run docs        # output in build/site
```

`docs/superpowers/` holds the design specs and implementation plans. They are
kept in the repository deliberately: they record *why* several non-obvious
decisions are the way they are — the provider limitations, the two-pass domain
verification flow, and the reasoning behind each safety gate.

## Changelog

[CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the conventions the code is held to.
[ROADMAP.md](ROADMAP.md) records what is planned, what is deliberately not
planned, and why. Security issues: [SECURITY.md](SECURITY.md).

## Licence

Apache License 2.0 — see [LICENSE](LICENSE).
