# Roadmap

Grounded in what is actually unfinished or known-limited, not aspiration. Each
item says why it matters and what makes it hard, so anyone picking one up knows
what they are walking into.

Nothing here has a date. Items are ordered by how much they'd improve the tool.

## Next

### Live verification against a Microsoft 365 tenant

The `ms365` provider is complete and fully covered by tests against a faked Graph
API, but it has **never run against a real tenant**. Seven behaviours are
therefore documented-but-unverified, and the design doc lists them explicitly.
The one most likely to need a change:

- Whether `POST /domains/{id}/verify` succeeds in the same apply that publishes
  the ownership TXT record, or reliably fails until DNS propagates. The docs
  describe a two-pass flow; it may actually be three.

Also unverified: whether `/subscribedSkus` ever returns two entries sharing a
`skuPartNumber`; whether `serviceConfigurationRecords` returns Email records
before `supportedServices` includes `Email`; and whether Graph's error body for a
rejected `passwordProfile` echoes the password into the error message.

Requires an Entra app registration with `Domain.ReadWrite.All`,
`User.ReadWrite.All` and `Organization.Read.All`, plus at least one spare licence
seat.

### Tenant-wide licence seat accounting

`checkSeats` refuses at plan time when creating mailboxes would exceed the free
seats for a SKU — but the count is **per domain**. Two `ms365` domains in one
config on the same tenant each read `/subscribedSkus` independently, both see the
same free seats, and both pass. The messages say so plainly rather than implying a
guarantee, but the check cannot deliver what its purpose implies.

Hard because a provider instance is created per domain and the `mail.Provider`
interface carries no cross-domain state. Doing it properly means either a
tenant-keyed cache above the provider layer or a two-pass engine — a structural
change worth designing before writing.

### Decide what a licence *change* should do

Changing a mailbox's `license` currently adds the new SKU and never removes the
old, so the tenant is billed for both until someone releases one by hand. The plan
output says exactly that, and no later run proposes a release. The conservative
behaviour was chosen deliberately, because silently removing a licence is the kind
of thing that should be opted into.

The open question is whether `mailctl` should offer that opt-in — and if so,
whether it belongs in config or on the command line.

## Later

### SRV records, and with them Teams and SharePoint

`dns.Record` carries `Type`, `Name`, `Content`, `TTL` and `Priority` — nothing for
an SRV record's target, port and weight. That is why the `ms365` provider supports
only the `Email` service: `OfficeCommunicationsOnline` needs SRV records, so a
returned SRV becomes an explicit error rather than a silently dropped record.

Adding SRV means extending `dns.Record` and the Cloudflare DNS provider together,
then widening the `ms365` service filter. Worth doing if anyone wants `mailctl` to
configure a whole Microsoft 365 domain rather than only its mail.

### More providers

The provider interface is four methods and the engine never names a provider, so
adding one is genuinely contained — see CONTRIBUTING.md. Candidates that would fit
the existing model: Fastmail, Migadu, Google Workspace, Zoho.

Google Workspace would be the most useful and the most work, since its Admin SDK
splits mailbox, alias and routing concerns across separate APIs.

### Machine-readable plan output

`plan` prints for humans. A `-json` flag emitting the action list would let people
gate a CI pipeline on what `mailctl` intends to change, or diff two plans. The
action model is already structured, so this is mostly a rendering concern.

### Better `import`

`import` prints a config block from live provider state. For `ms365` it emits a
commented stub for the keys that cannot be derived from a tenant — `license` and
`usageLocation` — because they genuinely cannot be read back. It could infer
`license` from what the tenant's users actually hold, and `usageLocation` from the
majority value across those users.

## Not planned

**Aliases and catch-all for Microsoft 365.** Not a gap in `mailctl`. Microsoft
Graph exposes `proxyAddresses` as read-only and offers no catch-all surface, so
these are only reachable through Exchange Online PowerShell. Shelling out to
`pwsh` would make it and the `ExchangeOnlineManagement` module hard runtime
requirements of a binary that otherwise has one dependency. If Graph ever exposes
them, this becomes a small change.

**Automated DKIM enablement for Microsoft 365.** The CNAME targets embed a
per-tenant partition character and Microsoft's own documentation says the
published values are illustrative — they must be read from the Defender portal.
`mailctl` therefore takes them as config and publishes and audits them from there,
which is as far as it can honestly go.

**Sending, receiving or relaying mail.** `mailctl` configures mail infrastructure.
It is not an MTA and will not become one.

**A daemon or a stored state file.** The live provider APIs are the state. There is
nothing to drift out of sync, and nothing to reconcile against a cache.

## Contributing to any of this

Open an issue before starting anything in **Next** — those three have design
decisions still open, and it is worth agreeing on the shape first. Items under
**Later** are more self-contained. See [CONTRIBUTING.md](CONTRIBUTING.md).
