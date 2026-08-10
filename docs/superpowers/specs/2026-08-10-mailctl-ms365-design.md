# Microsoft 365 Mail Provider — Design

**Status:** approved 2026-08-10
**Supersedes nothing.** Extends the provider set established by
`2026-08-07-mailctl-design.md`.

## Goal

Add `ms365` as a mail provider so a domain's Microsoft 365 mail configuration —
domain registration and verification, the DNS records M365 requires, and mailboxes
as licensed users — is declared in `mailctl.yaml` and reconciled by `mailctl plan`
and `mailctl apply`, with the same guarantees the existing providers give:
plan-before-apply, idempotence, and no silent partial success.

## What Graph can and cannot do

This section is the reason the design looks the way it does. Each limit below was
read from Microsoft's documentation, not assumed.

### Supported through Microsoft Graph

| Capability | Endpoint |
|---|---|
| Add a domain to the tenant | `POST /domains` |
| Read ownership verification record | `GET /domains/{id}/verificationDnsRecords` |
| Verify domain ownership | `POST /domains/{id}/verify` |
| Declare which services use the domain | `PATCH /domains/{id}` (`supportedServices`) |
| Read the records the services need | `GET /domains/{id}/serviceConfigurationRecords` |
| List the domain's users | `GET /domains/{id}/domainNameReferences/microsoft.graph.user` |
| Create a user | `POST /users` |
| Assign a licence | `POST /users/{id}/assignLicense` |
| Read licence inventory | `GET /subscribedSkus` |

### Not supported through Microsoft Graph

**Email aliases.** The `user` resource documents `proxyAddresses` as:

> Read-only in Microsoft Graph; you can update this property only through the
> Microsoft 365 admin center.

Only `mail`, the primary address, is writable. There is no Graph route to a
secondary SMTP address.

**Catch-all.** Requires an Exchange Online transport rule. No Graph surface.

**DKIM.** The required CNAME targets cannot be derived. The current format embeds
a per-tenant dynamic partition character (`n-v1`, `r-v1`, …). Microsoft's DKIM
documentation states:

> The values presented in this article are for illustration only. To get the
> required values for your custom domains or subdomains, use the Defender portal
> or Exchange Online PowerShell procedures.

and:

> The old and new formats can't coexist for the same selector.

So the targets must be read once from the Defender portal by a human.

Graph's `domain` resource documentation also warns that verification alone is not
enough:

> Verifying a domain through Microsoft Graph doesn't configure the domain for use
> with Office 365 services like Exchange.

Mailbox provisioning after `assignLicense` is asynchronous. The design treats
"created but not yet provisioned" as a normal, reportable state rather than a
failure.

### How the gaps are handled

- `aliases:` on an `ms365` domain is a **validation error** naming the admin
  center as the only route. It is never silently ignored — an ignored alias block
  reads as a working alias.
- `catchAll:` on an `ms365` domain is a **validation error** for the same reason.
- DKIM is declarative but human-seeded: an optional `dkimCnames` field takes the
  two targets copied from the Defender portal, after which `mailctl` publishes and
  audits `selector1._domainkey` and `selector2._domainkey` like any other record.

Rejected alternative: shelling out to Exchange Online PowerShell to read the DKIM
values automatically. It would make `pwsh` and the `ExchangeOnlineManagement`
module hard runtime dependencies of a binary that currently has exactly one
non-stdlib dependency.

Rejected alternative: modelling aliases as Graph-created mail-enabled groups. The
semantics differ from a true SMTP alias in ways that would surprise the operator
later, and it enlarges the provider substantially for a poor imitation.

## Architecture

### `internal/graphapi`

A new client package, shaped after `internal/cfapi`: request envelope, redacting
`String()`, generic paged `List` following `@odata.nextLink`.

It differs from `cfapi` in three ways, each driven by Graph rather than taste:

1. **Token acquisition.** Graph uses OAuth2 client credentials, not a static
   bearer token. The client posts to
   `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with
   `grant_type=client_credentials` and `scope=https://graph.microsoft.com/.default`,
   caches the access token until its expiry minus a safety margin, and refreshes
   once on a `401`.
2. **Throttling.** Graph throttles aggressively. The client honours `429` with
   `Retry-After` using bounded retries. This is required for correctness, not an
   optimisation: without it a domain with a dozen mailboxes will fail mid-apply.
3. **Error envelope.** Graph returns proper HTTP status codes together with
   `{"error":{"code":…,"message":…}}`. Both `code` and `message` are surfaced.
   This is the opposite of Purelymail, which returns HTTP 200 with an error body.

Credentials are read through `Deps.Getenv`: `MS365_TENANT_ID`, `MS365_CLIENT_ID`,
`MS365_CLIENT_SECRET`. `mail.Deps` gains `GraphBaseURL` and `LoginBaseURL` for
test injection, following the existing `PurelymailBaseURL` precedent.

The client secret must never appear in output. `String()` redacts it, matching
`cfapi.Client`.

### `internal/mail/ms365`

Implements the existing `mail.Provider` interface unchanged — `Name`,
`DesiredDNS`, `Actual`, `Plan` — registered at init and pulled in by a blank
import in `cmd/mailctl`, so the engine never names the provider. `Plan` performs
no I/O; returned `plan.Action` values carry the closures that do.

Split by responsibility:

| File | Responsibility |
|---|---|
| `api.go` | Typed Graph request and response payloads |
| `records.go` | `domainDnsRecord` → `dns.Record` mapping |
| `licence.go` | `subscribedSkus` lookup and seat arithmetic |
| `provider.go` | The four interface methods |

## Configuration

```yaml
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
        displayName: Other Person
        license: BUSINESS_STANDARD
```

`license` is a `skuPartNumber`, not a `skuId` — the part number is stable,
human-readable, and visible in the admin center, while the GUID is neither.
`licence.go` resolves it against `/subscribedSkus`.

`usageLocation` is a two-letter ISO 3166-1 alpha-2 code. Graph requires it on the
user before `assignLicense` succeeds, so it is required in config rather than
discovered at apply time.

**Amended 2026-08-10 during planning: there is no `services` field.** The domain's
`supportedServices` is set to `["Email"]` and `serviceConfigurationRecords` is
filtered to `supportedService == "Email"`.

The original design exposed a `services` list accepting the three values Graph
permits writing (`Email`, `OfficeCommunicationsOnline`, `Yammer`). Planning found
that unimplementable as specified: `dns.Record` carries only
`Type, Name, Content, TTL, Priority`, with no fields for an SRV record's target,
port and weight. `OfficeCommunicationsOnline` is precisely the service whose
records are SRV, and Teams and SharePoint records are already out of scope.

A knob with one legal value is worse than no knob, so the field is gone. Should a
`domainDnsSrvRecord` ever appear in an `Email`-filtered response, it becomes an
explicit error stating that SRV records are not supported, rather than a silently
dropped record. Adding SRV support means extending `dns.Record` and the Cloudflare
DNS provider together, which is its own piece of work.

`displayName` defaults to the address's local part when omitted.

### Validation rules

- `ms365` joins `KnownProviders` and `InboundProviders` (it publishes MX). It is
  not mailboxless. Existing validation therefore already forbids pairing it with
  `purelymail` or `cfrouting` on one domain.
- `aliases:` present on an `ms365` domain → error naming the admin center.
- `catchAll:` present on an `ms365` domain → error naming the admin center.
- `ms365.license` required and non-empty.
- `ms365.usageLocation` required, exactly two ASCII letters.
- `ms365.dkimCnames`, if present, must hold exactly two entries. Each must be a
  hostname and must not begin with `selector1._domainkey` or
  `selector2._domainkey` — those are the labels mailctl generates, not the
  targets, and pasting a label is the likely mistake.
- The `ms365` block is required when `provider: ms365`, and rejected otherwise.

### Purelymail-only mailbox fields

`config.Mailbox` carries five fields that are Purelymail concepts with no Graph
equivalent: `passwordEnv` aside, they are `enablePasswordReset`,
`enableSearchIndexing`, `requireTwoFactorAuthentication`, `sendWelcomeEmail`, and
`recovery`.

Today no validation rejects them per provider, because every other provider is
mailboxless and so can never reach a mailbox block at all. `ms365` is the first
second provider that hosts mailboxes, which makes this ambiguity reachable for the
first time.

Each of these fields on a mailbox belonging to an `ms365` domain is a **validation
error** naming the field and stating that it is Purelymail-only. Accepting and
ignoring them is not an option: an ignored `requireTwoFactorAuthentication` reads
as enforced two-factor authentication that does not exist.

Conversely `displayName` and the per-mailbox `license` are `ms365` concepts, and
are rejected on a mailbox belonging to a domain using any other provider, for the
same reason and with the same shape of message.
- Unknown keys inside `ms365` are rejected with the field name and YAML line
  number, matching how `mail.settings` already behaves.

## DNS

`DesiredDNS` composes three sources.

**1. Ownership.** `verificationDnsRecords` returns the `MS=ms…` TXT at the apex.

**2. Service records.** `serviceConfigurationRecords` returns typed records
discriminated by `@odata.type`, each carrying `label`, `recordType`, `ttl`,
`supportedService` and `isOptional`.

A record is published when both conditions hold: its `supportedService` is
`Email`, and `isOptional` is `false`. Optional records are never
published. They are service extras rather than requirements, and a record mailctl
publishes is a record mailctl will also defend and prune, so opting in silently on
the operator's behalf is the wrong default. A mail-only domain therefore does not
acquire Teams SRV records.

| `@odata.type` | Fields used | Becomes |
|---|---|---|
| `microsoft.graph.domainDnsMxRecord` | `mailExchange`, `preference` | MX |
| `microsoft.graph.domainDnsTxtRecord` | `text` | TXT |
| `microsoft.graph.domainDnsCnameRecord` | `canonicalName` | CNAME |
| `microsoft.graph.domainDnsSrvRecord` | — | error: SRV is not representable in `dns.Record` |
| `microsoft.graph.domainDnsUnavailableRecord` | — | error |

`domainDnsUnavailableRecord` is Graph signalling that the records are not ready
yet. It becomes an actionable error naming the domain and telling the operator to
rerun — the same shape as the DNS-propagation error the Purelymail provider
already produces, and for the same reason: the correct response is to wait, not to
change the config.

**3. DKIM.** Two CNAMEs at `selector1._domainkey.<domain>` and
`selector2._domainkey.<domain>`. The first `dkimCnames` entry is the target for
`selector1`, the second for `selector2`. Both are omitted when `dkimCnames` is
absent — never one without the other.

### SPF

**Amended 2026-08-10 during planning.** The original design had the provider
extract `include:` mechanisms and discard Graph's SPF record. Reading
`internal/deliver/spf.go` shows that is unnecessary: `MergeSPF` already folds every
provider record whose `Kind` is `KindSPF` and whose name is the apex into a single
TXT, applying the strictest `all` qualifier any input asked for. Purelymail already
relies on this.

So `ms365` returns its SPF record with `Kind: dns.KindSPF` like any other provider,
and the existing merge does the work. Exactly one TXT per name, as RFC 7208
requires, is already guaranteed.

One real hazard remains, and it is worse than the original design assumed.
Microsoft's published example renders the record as
`v=spf1 include: spf.protection.outlook.com ~all`, with a space after the colon.
`SPFMechanisms` splits on `strings.Fields`, so that input yields two mechanisms —
the bare token `include:` and a naked hostname — and the merge would republish the
same broken record rather than failing. A silently invalid SPF record is worse than
a loud error, because it looks configured and fails only at other people's
receiving servers.

Two changes address it:

1. `records.go` normalises the SPF text it receives from Graph, collapsing
   whitespace between `include:` and its value, before constructing the record.
2. `SPFMechanisms` treats a mechanism token that is exactly `include:`,
   `redirect=`, or any other bare name-with-no-value as an error rather than a
   mechanism, so a malformed record from any provider fails loudly.

The second change touches shared code, so it carries its own tests over the
existing providers to prove nothing that works today starts failing.

## Reading actual state

`Actual` reads:

- `GET /domains/{id}` → `DomainExists`, `isVerified`, `supportedServices`
- `GET /domains/{id}/domainNameReferences/microsoft.graph.user` → the domain's
  users, then `$select=id,userPrincipalName,mail,displayName,usageLocation,assignedLicenses`
- `GET /subscribedSkus` → `skuPartNumber` → `skuId`, `prepaidUnits.enabled`,
  `consumedUnits`

`domainNameReferences` is used rather than `GET /users?$filter=endsWith(mail,…)`
because the latter requires advanced query capabilities and a
`ConsistencyLevel: eventual` header, while the former is purpose-built for exactly
this question.

`State.Aliases` and `State.CatchAll` are always empty. Config rejects both, so no
drift is representable and none is reported.

`State.Notes` carries the verification status and a licence line showing seats
used and available — the same role Purelymail's `dnsSummary` note plays.

## Planning

Ordered actions, all I/O deferred into closures:

1. `CREATE domain` — `POST /domains` with `{"id": "<domain>"}`, when the domain is
   absent.
2. `VERIFY domain` — `POST /domains/{id}/verify`, when present but not verified.
   Fails while the ownership TXT has not propagated. That is expected: the error
   names the domain and says to rerun.
3. `UPDATE domain` — `PATCH /domains/{id}` setting `supportedServices` to include
   `Email`, when it is missing.
4. `CREATE mailbox` — one action per absent mailbox, whose closure performs
   `POST /users` followed by `POST /users/{id}/assignLicense`.
5. `DELETE mailbox` — only when both `-prune` and `-prune-mailboxes` are given.

Step 4 is deliberately one action across two API calls. A user created without a
licence has no mailbox at all, so splitting them would let a plan report success
over a domain that cannot receive mail.

**Corrected 2026-08-10 after review of the implementation.** An earlier version of
this section claimed that if the licence call fails, "rerunning will complete it —
the create is idempotent because the user is then found in `Actual`". That
reasoning was wrong, and the error message it justified promised a recovery no code
path performed. `assignLicense` was reachable only from inside the create action,
and the create action was emitted only when the address was *absent* from `Actual`.
After a licence failure the user exists, so the next run finds it, plans nothing,
and reports "No changes" over an account that is live, carries a generated password,
and has no mailbox. Since a generated password is unrecoverable, the operator would
be left resetting a credential they never saw, on a user they were told was fine.

The design therefore requires a third mailbox state, not two. `Actual` already
selects `assignedLicenses` for each user; it must be read:

- address absent from the tenant → `CREATE mailbox` (both calls, as above)
- address present but its `assignedLicenses` does not include the resolved
  `skuId` → `UPDATE mailbox`, whose closure calls **only** `assignLicense`
- address present and licensed → no action

Only with that third case is the create genuinely recoverable, and only then may
the failure message tell the operator that rerunning finishes the job.

`POST /users` sets `accountEnabled: true`, `displayName`, `mailNickname`,
`userPrincipalName`, `usageLocation`, and
`passwordProfile: {password, forceChangePasswordNextSignIn: true}`.

`forceChangePasswordNextSignIn` makes a mailctl-generated credential a genuine
one-time password: the operator hands it over, the recipient replaces it on first
sign-in. This matches how credentials are already reported — once, to a file or
stderr, never to stdout.

### Seat check

`Plan` is pure, and the seat data it needs is already in `Actual`. Before
returning any create actions, `Plan` sums the creates per resolved SKU and
compares against `prepaidUnits.enabled - consumedUnits`. A shortfall is an error
naming the SKU, the number needed and the number available.

This is checked at plan time on purpose. Discovering a seat shortfall halfway
through an apply leaves some mailboxes created and others not; discovering it in
`plan` costs nothing.

An unknown `license` value — a `skuPartNumber` absent from `/subscribedSkus` — is
an error listing the part numbers the tenant actually has.

## Prune

A user present in the tenant but absent from the config is reported as drift in
`State.Notes` **whenever it exists**, not only under `-prune`. Unmanaged mailboxes
are worth knowing about on every `plan`, and gating the report on the flag that
also deletes them would mean the operator learns of them only when reaching for the
destructive option.

Planning a deletion requires `-prune` **and** `-prune-mailboxes`. The resulting
action is destructive, so the existing typed-domain confirmation applies on top.

Two of this project's Critical defects were a prune scope wider than intended
destroying an object the operator never named. Deleting an M365 user destroys that
person's mail, recoverable only for 30 days. The second flag is proportionate to
that blast radius.

`-prune-mailboxes` has no effect without `-prune`, and this is stated in the flag's
help text rather than silently tolerated.

## Deliverability interaction

`ms365` is an inbound provider, so a domain cannot use it alongside `purelymail`
or `cfrouting`. Existing validation enforces this; no new rule is needed.

The existing `deliverability` block — DMARC, TLS-RPT, BIMI, MTA-STS — works
unchanged. MTA-STS derives its `mx` list from the desired records, which for an
M365 domain resolve to `*.mail.protection.outlook.com`. This is asserted by an
explicit test rather than assumed, because a wrong MTA-STS policy silently breaks
inbound mail for compliant senders.

## Testing

Unit tests run against a fake Graph server, following the pattern established by
the Purelymail and Cloudflare providers.

`internal/graphapi`:
- token is requested once and reused until near expiry
- a `401` triggers exactly one refresh and one retry
- `429` with `Retry-After` is honoured, with a bounded retry count
- the error envelope's `code` and `message` both reach the caller
- `String()` does not contain the client secret

`internal/mail/ms365`:
- one mapping case per `@odata.type`; SRV produces the not-supported error
- `isOptional` and `supportedService` filtering
- `domainDnsUnavailableRecord` produces the retry error, not a dropped record
- the SPF record is returned with Kind KindSPF and merges via the existing MergeSPF
- `include:` followed by whitespace is normalised before the record is built
- `SPFMechanisms` rejects a bare `include:` token, and the existing providers'
  records still parse unchanged
- seat arithmetic: exact fit passes, one over fails with SKU and counts named
- unknown `skuPartNumber` lists the available part numbers
- plan ordering: create → verify → update services → mailboxes
- the mailbox action's licence failure reports the user as created but unlicensed
- prune reports drift without `-prune-mailboxes` and plans no deletion

`internal/config`:
- `aliases:` and `catchAll:` rejected for `ms365`, with the admin center named
- `dkimCnames` arity, and rejection of a pasted label instead of a target
- `usageLocation` format
- each of the five Purelymail-only mailbox fields is rejected on an `ms365` domain
- `displayName` and per-mailbox `license` are rejected on a non-`ms365` domain
- unknown key inside `ms365` reports field name and line number
- `ms365` in `KnownProviders` and `InboundProviders`, kept in sync by the existing
  `TestKnownProvidersMatchRegistry`

Integration, via `cmd/mailctl`:
- `-prune-mailboxes` without `-prune` is rejected, not silently ignored
- a scoped flag cannot leak across subcommands, as `rejectScopedFlags` already
  guarantees

## Live verification

A final task verifies against the real tenant, separated so its findings land as
their own fixes. The Purelymail work established that live APIs differ from their
documentation, and that a live pass is where the real defects surface.

Items that only a tenant can settle:

- whether `verificationDnsRecords` still returns the ownership TXT after the
  domain is verified, which decides whether that record stays in the desired set
  or would be pruned
- the exact `assignLicense` failure shape when no seats remain
- ~~whether Graph accepts `removeLicenses` as `null`~~ — **settled from the
  documentation, not left for the tenant.** Graph's `assignLicense` reference states
  `removeLicenses` is "Required. Can be an empty collection", and every published
  example sends `[]`. mailctl sends `[]` for both `removeLicenses` and
  `disabledPlans`. A `null` there would have failed every mailbox create against a
  real tenant
- whether a tenant user whose `mail` differs from its `userPrincipalName` is matched
  correctly against config, which decides whether an address change can produce a
  create and a delete for the same person in one plan
- how long mailbox provisioning lags `assignLicense`, and what `Actual` reports
  during that window
- whether `domainNameReferences` returns users whose licence is still provisioning
- the real `serviceConfigurationRecords` payload for a mail-only domain, including
  whether the SPF `include:` arrives with or without the stray space

## Out of scope

- Aliases, catch-all, and automated DKIM enablement, for the documented reasons
- Shared mailboxes, distribution lists, and mail-enabled groups
- SharePoint, Teams and Intune service records, and SRV records generally, which
  would require extending `dns.Record` and the Cloudflare DNS provider together
- Migrating existing mail into a mailbox
- Federated (`authenticationType: Federated`) domains
