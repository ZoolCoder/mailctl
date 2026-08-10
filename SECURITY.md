# Security

`mailctl` holds API tokens for DNS and mail providers and can create, change and
delete real mailboxes. Its security properties are therefore part of its
behaviour, not an afterthought, and the ones below are enforced by tests.

## Reporting a vulnerability

Please report privately rather than opening a public issue: open a
[security advisory](https://github.com/zoolcoder/mailctl/security/advisories/new)
on this repository.

Include what you did, what happened, and what you expected. If the issue involves
a credential of yours being exposed, rotate it first — do not send it to us.

## What mailctl guarantees

**Nothing sensitive reaches stdout.** Not an API token, not an OAuth access token,
not a mailbox password. Generated mailbox credentials are written to stderr or to
a file created `0600` with an exclusive create, and nowhere else. This is not a
convention: a token on stdout ends up in a pipeline, a CI log, or a shell
scrollback.

**No credential is stored in the config file.** The config names an *environment
variable*; the value is read at the moment it is needed. A referenced variable
that is unset is an error, never an empty string — substituting nothing silently
would publish a broken record or create a mailbox with an empty password.

**Provider client secrets are redacted in diagnostics.** Each API client's
`String()` omits its secret, so a client value included in an error cannot leak it.

**A failing OAuth token request never echoes its response body.** Microsoft's
token endpoint reflects the request on failure, client secret included. The error
reports the status code and names the environment variables to check instead.

**Generated credentials are reported only once they exist.** A password is
reported when the mailbox has actually been created at the provider, not when it
is planned. After a partial failure you are given exactly the credentials that are
live — no more, and no fewer. Where the provider supports it, a generated password
is marked as one that must be changed at first sign-in.

**If writing the credentials file fails, the credentials are still reported.**
They go to stderr instead. Losing a live credential silently is not an acceptable
failure mode; a generated password cannot be read back from any provider.

## Destructive operations

Deleting a mailbox destroys mail. It requires two flags — `-prune` *and*
`-prune-mailboxes` — and then a confirmation prompt that asks you to type the
domain name. `-yes` skips only the prompt.

Omitting `catchAll` from the config means "leave whatever exists alone", not
"delete it". Users are addressed by provider object id where the provider's API
resolves ids, never by an email address that another account might also match.

DNS records `mailctl` did not create are never silently overwritten; a conflict
fails the plan until you pass `-replace-dns`.

## Scoping your tokens

Give the Cloudflare token DNS edit permission on only the zones `mailctl`
manages, not the whole account. An account-wide DNS-write token is convenient
during setup and a liability afterwards.

The Microsoft Entra application needs application permissions
`Domain.ReadWrite.All`, `User.ReadWrite.All` and `Organization.Read.All` with
admin consent. Those are broad; use a dedicated app registration rather than
reusing one that already has other grants.

## Keeping credentials out of version control

Add the ignore rule before creating the file, not after. The config file itself
holds no secrets and is safe to commit — but check it for real addresses before
publishing it anywhere, since mailbox addresses are personal data even when
passwords are not.

## Scope

`mailctl` is a client. It does not receive, store or relay mail, and it exposes
no network listener. The MTA-STS policy Worker it can deploy to Cloudflare serves
one static policy document over HTTPS and reads no input.
