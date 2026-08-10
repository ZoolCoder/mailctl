# mailctl — Design

**Date:** 2026-08-07
**Status:** Approved, ready for implementation planning

## Summary

`mailctl` is a standalone Go CLI that provisions and reconciles email configuration across
multiple domains: mailboxes, aliases, routing rules, DNS records, and deliverability policy.

It replaces `example/internal/mailsetup`, which handled a single domain with Purelymail
hardcoded into the runner. The new tool keeps that tool's plan/apply model and its
conflicting-DNS guardrail, and generalizes everything else behind two interfaces.

## Goals

- One config file describing the desired email state of every domain the user owns.
- Pluggable mail providers. Adding a provider is one package, no engine change.
- Full coverage of the Purelymail API, not just domain creation and user creation.
- Cloudflare Email Routing and Cloudflare Email Sending as first-class providers.
- Deliverability hardening: DMARC policy, MTA-STS (including hosting the policy), TLS-RPT, BIMI.
- Idempotent. Re-running `apply` against a converged system does nothing and says so.

## Non-goals

- Sending mail. `mailctl` configures email infrastructure; it does not deliver messages.
- DNS providers other than Cloudflare. The `DNSProvider` interface exists so a second one
  is possible later, but only Cloudflare is implemented.
- A daemon or continuous reconciliation loop. This is a CLI run by a human or by CI.

## Repository

Standalone Go module and git repository at `the repository root`.
`Tools/` is a flat directory of independent tools and is not itself a repository.

Module path: `github.com/zoolcoder/mailctl`.

Dependencies: `gopkg.in/yaml.v3` only. Everything else is standard library.

## Architecture

### Package layout

```
cmd/mailctl/main.go        CLI parsing and wiring only, no logic
internal/config/           YAML schema, defaults, validation, secret resolution
internal/plan/             Action type, desired-vs-actual diff, plan renderer
internal/dns/              DNSProvider interface, Record type
internal/dns/cloudflare/   Zone lookup, record CRUD, pagination
internal/mail/             MailProvider interface, provider registry
internal/mail/purelymail/  Full /api/v0 surface
internal/mail/cfrouting/   Cloudflare Email Routing
internal/mail/cfsending/   Cloudflare Email Sending
internal/deliver/          SPF, DMARC, MTA-STS, TLS-RPT, BIMI record builders and audit
internal/worker/           Cloudflare Worker upload and custom-domain binding
internal/secret/           Password resolution from env, generation, one-time reporting
internal/cfapi/            Shared Cloudflare v4 envelope, auth, pagination, error mapping
```

`internal/cfapi` exists because three packages (`dns/cloudflare`, `mail/cfrouting`,
`mail/cfsending`, `worker`) all talk to the same API with the same envelope, auth header,
pagination shape, and error format. Duplicating that four times is how the current code
would have grown.

### Core interfaces

```go
// internal/mail
type Provider interface {
    Name() string

    // DesiredDNS returns the records this provider needs published for the domain.
    // Providers that expose a DNS endpoint (Cloudflare) fetch them; providers that
    // do not (Purelymail) construct them.
    DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error)

    // Actual reads current provider-side state for the domain.
    Actual(ctx context.Context, d config.Domain) (State, error)

    // Plan diffs desired against actual and returns ordered actions.
    Plan(d config.Domain, actual State, opts plan.Options) ([]plan.Action, error)

    // Apply executes actions produced by Plan.
    Apply(ctx context.Context, actions []plan.Action) error
}

type State struct {
    DomainExists bool
    Settings     DomainSettings
    Mailboxes    []Mailbox
    Aliases      []Alias
    CatchAll     *CatchAll
    Notes        []string // provider observations surfaced in plan/audit output
}
```

```go
// internal/dns
type Provider interface {
    Zone(ctx context.Context, name string) (Zone, error)
    Records(ctx context.Context, zoneID string) ([]Record, error)
    Apply(ctx context.Context, zoneID string, actions []plan.Action) error
}
```

The engine never branches on a provider name. Provider-specific sequencing lives inside
the provider. In particular, Purelymail's ownership-code dance — call `getOwnershipCode`,
publish the returned value as a TXT record, then call `addDomain` — happens inside
`purelymail.DesiredDNS` and `purelymail.Plan`. The current runner special-cases this in
`Run`, which is why adding a second provider to it would require touching the runner.

### Execution flow

1. Load and validate config.
2. For each domain: resolve the DNS zone, read current DNS records.
3. For each domain: instantiate its mail provider, call `DesiredDNS` and `Actual`.
4. Build the desired DNS set = provider records + deliverability records.
5. Diff DNS, diff mail state, concatenate into one ordered plan.
6. `plan`: render and stop. `apply`: execute, DNS first, then mail.

DNS is applied before mail because Purelymail's `addDomain` fails until the ownership TXT
record resolves. When it does fail — DNS propagation is not instant — the error tells the
user to rerun rather than presenting it as a permanent failure. The current tool already
does this and it is worth keeping.

## Configuration

YAML. Chosen over JSON for comments and readability at multi-domain size; costs one
dependency.

Default path `mailctl.yaml`, overridable with `-config`.

```yaml
version: 1

cloudflare:
  accountId: ${CLOUDFLARE_ACCOUNT_ID}    # required for account-scoped endpoints
  ttl: 1                                  # 1 = automatic

domains:
  - name: example.com
    zoneName: example.com              # defaults to name

    mail:
      provider: purelymail                # string, or a list: [cfrouting, cfsending]
      settings:
        allowAccountReset: true
        symbolicSubaddressing: false

    mailboxes:
      - address: contact@example.com
        passwordEnv: CONTACT_PASSWORD   # omit to generate
        enableSearchIndexing: true
        requireTwoFactorAuthentication: false
        recovery:
          - type: email
            target: fallback@example.com
            description: personal
            allowMfaReset: false

    aliases:
      - match: info                        # local part, or "info*" for prefix match
        to: [contact@example.com]

    catchAll:
      to: [contact@example.com]         # omit the key entirely to leave unmanaged

    deliverability:
      dmarc:
        policy: quarantine                 # none | quarantine | reject
        subdomainPolicy: reject
        pct: 100
        rua: mailto:dmarc@example.com
        ruf: mailto:dmarc@example.com
      mtaSts:
        mode: enforce                      # none | testing | enforce
        maxAge: 604800
        deploy: true                       # upload the policy Worker
      tlsRpt: mailto:tls@example.com
      bimi:
        logo: https://example.com/bimi/logo.svg
        vmc: ""                            # optional Verified Mark Certificate URL
```

`${VAR}` expansion is supported in string values. Unset variables are an error at load
time, not a silent empty string.

`mail.provider` accepts either a single provider name or a list. A list means the domain
uses several providers together — the realistic case being `cfrouting` for inbound plus
`cfsending` for outbound. The engine unions their DNS sets and fails if two providers
demand different content for the same record name and type.

`version: 1` is the config schema version. `mailctl` refuses a version it does not
recognize rather than guessing at unfamiliar fields.

### Validation

At load: every mailbox and alias address must belong to its enclosing domain; DMARC policy
must be one of the three legal values; `pct` must be 1–100; MTA-STS `mode: enforce`
requires a mail provider that publishes MX records. All validation errors are collected
with `errors.Join` and reported together, matching the existing tool's behavior.

## Providers

### Purelymail

Base URL `https://purelymail.com`, auth header `Purelymail-Api-Token`, all calls POST.
Responses are an envelope with `result`, plus `code` and `message` on failure — note that
Purelymail returns HTTP 200 with an error code in the body, so status code alone is not a
success signal. The existing client handles this correctly and that logic carries over.

Endpoint coverage:

| Config concept | Endpoints |
|---|---|
| domain | `addDomain`, `deleteDomain`, `updateDomainSettings`, `listDomains`, `getOwnershipCode` |
| mailbox | `createUser`, `modifyUser`, `deleteUser`, `getUser`, `listUser` |
| recovery methods | `upsertPasswordReset`, `deletePasswordReset`, `listPasswordReset` |
| alias / catch-all | `createRoutingRule`, `deleteRoutingRule`, `listRoutingRules` |
| app password | `createAppPassword`, `deleteAppPassword` |
| audit | `checkAccountCredit` |

Recovery methods move from create-time `createUser` fields to `upsertPasswordReset`. The
current tool sets `recoveryEmail` and friends only when the mailbox is first created, so
editing them in config has no effect on an existing mailbox. Using the dedicated
upsert/list/delete endpoints makes recovery methods genuinely reconcilable.

Aliases map to routing rules: `matchUser` is the local part, `prefix` is true when the
config `match` ends in `*`, `targetAddresses` is the `to` list, `catchall` is false.
Catch-all is the same call with `catchall: true`.

`createUser` request fields beyond `userName` (`domainName`, `password`, and the enable
flags) are confirmed working by the existing tool against the live API; the public
OpenAPI description of this endpoint is incomplete. Implementation should preserve the
field set the current code sends and verify against a live call.

### Cloudflare Email Routing

Zone-scoped except destination addresses.

| Config concept | Endpoint |
|---|---|
| enable | `POST /zones/{z}/email/routing/enable` |
| settings | `GET`/`PATCH /zones/{z}/email/routing` |
| required DNS | `GET /zones/{z}/email/routing/dns` |
| aliases | `GET`/`POST /zones/{z}/email/routing/rules`, `PUT`/`DELETE .../rules/{id}` |
| catch-all | `GET`/`PUT /zones/{z}/email/routing/rules/catch_all` |
| destinations | `GET`/`POST /accounts/{a}/email/routing/addresses` |

This provider has no mailboxes; a config using it with a `mailboxes:` block fails
validation with a message naming the provider.

### Cloudflare Email Sending

| Config concept | Endpoint |
|---|---|
| enable domain | `POST /zones/{z}/email/sending/subdomains` |
| list | `GET /zones/{z}/email/sending/subdomains` |
| disable | `DELETE /zones/{z}/email/sending/subdomains/{id}` |
| required DNS | `GET /zones/{z}/email/sending/subdomains/{id}/dns` |

Outbound only, and like `cfrouting` it has no mailboxes. Pairs with `cfrouting` on the
same domain when both inbound and outbound are wanted, via the list form of
`mail.provider`.

## Declarative and imperative boundary

Two operations cannot be reconciled and are handled imperatively instead of being faked:

**App passwords.** `createAppPassword` returns the secret exactly once and there is no list
endpoint. A declarative config could never detect drift or re-derive the value. Exposed as
`mailctl apppass create|rm`.

**Cloudflare destination addresses.** Creating one sends a verification email that a human
must click. `apply` creates the address and then reports it as a pending manual step; it
does not block or poll.

The plan output distinguishes these as `MANUAL` entries so a converged plan that still
lists them is not mistaken for a failure to converge.

## Deliverability

`internal/deliver` builds records as pure functions of config — cheap to test, no I/O.

- **SPF** — the mail provider supplies its `include:` mechanism; `deliver` merges additional
  includes from config into a single record. Multiple SPF TXT records on one name is a
  hard failure in the spec, so merging rather than appending matters.
- **DMARC** — `_dmarc.<domain>` TXT built from policy, pct, rua, ruf, subdomain policy.
- **TLS-RPT** — `_smtp._tls.<domain>` TXT.
- **BIMI** — `default._bimi.<domain>` TXT with `l=` and optional `a=`.
- **MTA-STS** — see below.

### MTA-STS

Three coupled pieces, all owned by `mailctl`:

1. `TXT _mta-sts.<domain>` with value `v=STSv1; id=<id>`, where `<id>` is a short hash of
   the rendered policy text. Deriving the id from the policy is what makes edits take
   effect — receiving servers cache the policy and only refetch when the id changes. A
   static id means a changed MX list or mode is never picked up.
2. A Worker serving `https://mta-sts.<domain>/.well-known/mta-sts.txt` with
   `Content-Type: text/plain`, uploaded to script name `mailctl-mta-sts-<domain>` via
   `POST /accounts/{a}/workers/scripts/{name}` as multipart with a `metadata` part
   (`main_module`, `compatibility_date`) and the module source.
3. Custom domain `mta-sts.<domain>` bound to that script via
   `PUT /accounts/{a}/workers/domains`, which provisions the DNS record and certificate.

The policy body is generated from the same MX set the mail provider declared, so the
policy cannot drift from published DNS.

Deploying via the Workers REST API directly rather than shelling out to `npx wrangler`
keeps `mailctl` a self-contained binary with no Node dependency. This is a deliberate
exception to the user's standing "drive Workers through wrangler" preference, which is
aimed at Worker *projects*; this is a generated script that `mailctl` owns end to end and
that has no `wrangler.toml` of its own.

Setting `deploy: false` emits the TXT records and skips the Worker, for users hosting the
policy elsewhere.

## Deletion and destructive operations

The reconciler is **additive by default**. Provider-side objects absent from config are
reported as unmanaged and left alone.

- `-prune` deletes unmanaged mailboxes, aliases, and routing rules. It lists every object
  it will delete and requires the user to type the domain name to confirm. `-yes` skips
  the prompt for CI.
- `-replace-dns` deletes conflicting MX, SPF, DKIM, and DMARC records before creating the
  desired ones. Carried over from the existing tool, with the same per-record-kind conflict
  rules: an MX conflicts with any MX, an SPF record conflicts with any TXT starting
  `v=spf1`, the Purelymail ownership TXT conflicts with nothing.
- Mailbox deletion destroys stored mail irreversibly. `-prune` names each mailbox
  individually in the confirmation, not just a count.

Neither flag is implied by the other, and neither is on by default.

## Secrets

Password resolution order per mailbox:

1. `passwordEnv` set and the variable is non-empty — use it.
2. `passwordEnv` absent — generate 24 characters from a 74-character alphabet using
   `crypto/rand`, apply it, and report it once.

Generated passwords go to stderr under a clearly delimited banner, never to stdout (which
may be piped) and never written back into the config file. `-secrets-out <path>` writes
them to a file created with mode 0600 instead.

`mailctl` never logs a password, an API token, or an app password at any verbosity level.

Tokens come from `CLOUDFLARE_API_TOKEN` and `PURELYMAIL_API_TOKEN`, matching the existing
tool.

## Commands

```
mailctl plan [-config f] [-domain d]
mailctl apply [-config f] [-domain d] [-prune] [-replace-dns] [-yes] [-secrets-out f]
mailctl audit [-config f] [-domain d]
mailctl import -domain d [-provider p] [-zone z]
mailctl mailbox add|rm|passwd <address>
mailctl alias add|rm <address>
mailctl apppass create|rm <address>
mailctl version
```

`plan` is the default when no subcommand is given, preserving the safety property of the
current tool where the dangerous path requires an explicit flag.

`audit` resolves DNS through a real resolver rather than reading it back from the
Cloudflare API — the API tells you what you asked for, not what the internet sees. It
checks that MX, SPF, DKIM, DMARC, MTA-STS TXT and policy endpoint, and TLS-RPT all resolve
and match the desired state, folds in the provider's own DNS-pass flags
(Purelymail's `dnsSummary`), and reports Purelymail account credit.

`import` reads live provider and zone state and prints a config block, so existing domains
can be adopted without hand-writing YAML.

The `mailbox`, `alias`, and `apppass` subcommands are conveniences: they edit the config
file and then run the normal reconcile, so the config stays the source of truth.

## Error handling

- Every error names the provider, the domain, and the specific object.
- A failed `apply` reports which actions already succeeded before the failure. Because
  actions are idempotent, the remedy is always to rerun.
- Cloudflare's `success: false` envelope and Purelymail's HTTP-200-with-error-code are both
  mapped to Go errors carrying the provider's own message text; the message is never
  replaced with a generic one.
- Config validation errors are collected and reported together rather than one per run.

## Testing

The current tool has one test file covering config validation and no HTTP tests at all.

- **Provider clients** — `httptest.Server` fake per provider asserting request paths,
  headers, and bodies, and returning recorded response shapes. Covers the envelope
  handling that is easy to get subtly wrong.
- **Diff engine** — table tests. This is where behavior lives and where bugs will be:
  empty state, converged state, partial drift, conflicts with and without `-replace-dns`,
  prune with and without confirmation.
- **Record builders** — pure functions, table tests, including the MTA-STS id changing when
  and only when the policy text changes.
- **Config** — validation errors, `${VAR}` expansion, defaults.

No live API calls in the test suite.

## Migration

1. Build `mailctl` and convert `example/mailsetup.example.json` to YAML with a small
   one-shot converter, or by running `mailctl import -domain example.com`.
2. Run `mailctl plan` against `example.com` and confirm it reports a converged state —
   the domain is already provisioned, so a non-empty plan means the new tool disagrees with
   reality and must be fixed before `apply`.
3. Run `mailctl apply` once to confirm idempotence.
4. Only then remove `example/internal/mailsetup`, `example/cmd/mailsetup`, and the
   example config. This is a separate, explicit step, not part of the build.

## Open items for implementation

- `PUT /accounts/{a}/workers/domains` is the documented custom-domain attach endpoint but
  was not confirmed against a live response; verify the exact method and payload before
  relying on it.
- Purelymail's `createUser` accepts more fields than its public OpenAPI description lists.
  Preserve the field set the existing working code sends and confirm against a live call.
