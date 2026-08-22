# Contributing

Thanks for considering it. This document is short and specific, because most of
what matters here is a handful of conventions the code is genuinely held to.

## Getting set up

```console
$ git clone https://github.com/zoolcoder/mailctl
$ cd mailctl
$ go build ./cmd/mailctl
$ go test ./...
```

Go 1.26 or newer. No other tooling is required — the test suite runs entirely
offline, with every provider API faked by `httptest`. You need no tokens and
nothing is contacted, so `go test ./...` on a fresh clone should be green.

Before opening a pull request:

```console
$ gofmt -l .        # must print nothing
$ go vet ./...      # must be silent
$ go test ./...     # must pass every package
```

## The linter

CI also runs golangci-lint:

```console
$ go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...
```

Run it that way rather than adding it to `go.mod` as a tool: a tool directive
would make golangci-lint a direct requirement of the module and break the
dependency rule below. `.golangci.yml` explains every check it disables and
why, including the import boundaries that keep `plan` free of I/O and the
providers independent of each other.

## Conventions that are requirements

These are not style preferences. Reviews will hold you to them.

**Exactly two non-stdlib dependencies.** `gopkg.in/yaml.v3` for the config, and
`github.com/zoolcoder/zcadmin` — the shared shell, login and design tokens the
local admin page is built on, itself pure stdlib. If a change seems to need
another, that is worth discussing in an issue first — the answer is usually that
a few dozen lines of stdlib will do. There is no HTTP client library, no OAuth
library and no provider SDK; the API clients are hand written for this reason.

**The UI holds no logic.** `internal/ui` renders what the engine answers and
reaches providers only through it; `.golangci.yml` enforces the import boundary.
Its pages are Go templates on the zcadmin shell — no JavaScript framework, no
bundle to build or commit.

**`Plan` performs no I/O.** Providers read live state in `Actual`, then compute
actions with no further calls. Each returned action carries a closure that does
the writing. A `plan` that could mutate anything would defeat the tool's central
promise.

**Never accept configuration you will ignore.** If a provider's API cannot express
something, reject it in `config.Validate` with an error naming the manual route.
An accepted-and-ignored setting reads to an operator as a setting in force. This
is the single most important rule in the codebase.

**Nothing sensitive reaches stdout, ever.** See [SECURITY.md](SECURITY.md). If you
touch a credential path, say so in the pull request description so it gets the
attention it deserves.

**Errors name the object and the next step.** Not `invalid licence` but which
domain, which field, and what the operator should do about it — including, where
relevant, which values the provider actually accepts.

**Destructive behaviour earns friction.** Anything that can lose mail needs an
explicit opt-in and a confirmation. If you find yourself widening what `-prune`
covers, that is a design discussion, not a patch.

## Tests

Table-driven where there is more than one case. Every test asserts a value —
"does not panic" is not an assertion.

**Please mutation-check any test guarding a safety property.** Break the code
deliberately, confirm the test fails, then restore it. This has repeatedly caught
tests here that passed for the wrong reason: a cancellation test whose context was
already dead before reaching the code under test, and a deletion test whose fixture
made two distinct identifiers identical so it could not tell them apart. A test
that cannot fail is worse than no test, because it reads as coverage.

Use `httptest` servers rather than interface fakes for HTTP. The point is to
exercise the real request and response handling, including the wire format —
assert on a decoded request body, not on the Go struct you passed in.

## Adding a provider

Implement the four methods of `mail.Provider` in a new package under
`internal/mail/`, register it from an `init` function, and add a blank import in
`cmd/mailctl`. The engine never names a provider.

Then:

- add the name to `config.KnownProviders`, and to `InboundProviders` if it
  publishes MX records or `MailboxlessProviders` if it hosts no mailboxes
- reject, in `config.Validate`, every config block your provider cannot honour
- contribute your SPF requirement to `deliver.MergeSPF` rather than publishing an
  SPF record directly; RFC 7208 permits exactly one per name
- read `internal/mail/purelymail` first. It is the most complete implementation
  and the conventions there — fully-qualified record names, `Proxied` false on
  every CNAME, never setting TTL — are requirements rather than habits

## Commits

Conventional commits: `type(scope): description`, imperative, lowercase, no
trailing period, under 60 characters. Types: `feat`, `fix`, `refactor`, `docs`,
`test`, `chore`, `build`, `ci`, `perf`, `style`.

```
feat(ms365): add the Microsoft 365 mail provider
fix(deliver): reject an SPF mechanism with no value
```

Keep unrelated changes in separate commits. A behavioural change hidden inside a
cleanup diff is the thing reviewers most reliably miss.

## Documentation

The site under `docs/` is Antora, pinned locally:

```console
$ npm install
$ npm run docs        # output in build/site
```

The build treats any Antora warning as an error, because an unresolved
cross-reference otherwise ships as a broken link.

`docs/superpowers/` holds the design specs and implementation plans. They record
why several non-obvious decisions are as they are, and are worth reading before
proposing a change to the provider model.
