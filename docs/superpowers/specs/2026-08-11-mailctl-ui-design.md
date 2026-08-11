# Local UI Client — Design

**Status:** approved 2026-08-11
**Supersedes nothing.** Adds a `ui` command to the CLI established by
`2026-08-07-mailctl-design.md`.

## Goal

A local browser UI for mailctl: `mailctl ui` opens a page that shows what is
configured, what is live, and what a run would change — and, in later phases,
edits the config and applies a plan. The point is to make eight domains legible
at a glance and to make strict validation a guide rather than a wall, without
giving up anything the CLI guarantees.

The full console is three independent subsystems. Each gets its own spec, plan
and merge:

| Phase | Scope |
|---|---|
| 1 (this spec) | Shared foundation, `plan -json`, and the read-only plan/audit viewer |
| 2 | Form-based `mailctl.yaml` authoring with live validation |
| 3 | Apply from the UI, with the destructive-action friction preserved |

Phase 1 ships something useful alone: one screen showing which domains are
converged and which have drifted.

## Constraints this design is built around

These come from the project's existing commitments, not from preference.

**No daemon, no state file.** `ROADMAP.md` lists both under "Not planned",
because the live provider APIs are the state and there is nothing to reconcile
against a cache. A UI is the easiest way to acquire a background service by
accident, so the design refuses it structurally rather than by policy.

**Exactly one non-stdlib Go dependency.** `gopkg.in/yaml.v3`, enforced by a CI
check. The server is therefore stdlib `net/http`. The frontend's npm toolchain is
build-time only and does not appear in `go.mod`.

**No credential is ever typed into a page.** The UI process reads the same
environment variables the CLI does. There is no login form, and no endpoint
accepts a provider credential. (The local auth token below is a different thing:
it authenticates the browser to this process, and is never a provider secret.)

**No credential reaches stdout or any log.** Already true of the CLI; the UI adds
an HTTP layer, so it must not log request bodies or query strings, and generated
mailbox credentials must not pass through the access log.

**`go install` cannot run npm.** This is the constraint that shapes packaging.

## Decisions

### `mailctl ui` is a foreground command

It binds `127.0.0.1` on a port chosen by the kernel, generates a random token for
that one process, prints the URL carrying it, opens the browser, and serves until
interrupted. The token is not single-use: the page keeps it and sends it with
every request, and it dies with the process. No pidfile, no
`--daemon`, no background mode, and nothing written to disk. Closing it ends the
process and discards all in-memory state.

### Every request is authenticated and origin-checked

Binding to `127.0.0.1` is not access control. Any process on the machine, and any
web page in any open tab, can issue requests to a known local port. This process
holds a Cloudflare token with DNS write across every zone it manages, so drive-by
requests are a real threat rather than a theoretical one.

Requests must carry the launch token, and must pass `Origin` and `Host`
validation, which is what defeats DNS rebinding — an attacker-controlled name
resolving to `127.0.0.1` presents a foreign `Origin`. Rejection paths are tested
as first-class cases, not as an afterthought.

### One JSON projection, two consumers

A new package renders `plan.Plan` and `audit.Report` into a documented, stable
schema. Both `mailctl plan -json` and the UI's handlers use it, so the
CI-gating use case and the UI cannot drift apart. `plan -json` is a
`ROADMAP.md` item in its own right and is useful with no UI present.

**The projection deliberately drops `Action.Do`.** `plan.Action` carries
`Do func(context.Context) error`, a closure over live provider clients. It is not
serialisable, and that is the right outcome: the JSON is a description of intent,
never a capability.

This yields a property that constrains phase 3 and is recorded here so it is not
rediscovered later: **apply must never reconstruct a plan from client-supplied
JSON.** The client references actions from a server-held plan by identifier. A
plan round-tripped through the browser would let a page request an action the
plan never contained.

### Live reads happen only on explicit request

Planning and auditing call provider APIs, which cost latency and rate limit.
Neither ever runs on page load, navigation, or re-render — only when the operator
asks. Results arrive per domain as each completes, and a domain that fails shows
its error inline instead of failing the whole view. Results live in memory for
the life of the process.

### The bundle is committed, and CI proves it is current

`go:embed` needs the built assets at compile time, and `go install` cannot run
npm. The built bundle is therefore committed, so `mailctl ui` behaves identically
whether installed by `go install`, Homebrew, or a release archive — the project's
usual position that the same version should not behave differently by install
route.

Committing generated files has an obvious failure mode: silent drift from source.
CI rebuilds the frontend and fails if the committed output differs, the same way
`go.mod` tidiness is already enforced.

### No component framework

Vue 3 with `<script setup>`, TypeScript and Pinia, built by Vite. Quasar is
deliberately not used, departing from the usual default for app projects: for a
read-only screen it earns little and costs embedded bundle size, which is
charged to every binary. The docs site already carries a design-token layer with
light and dark themes, brand fonts, and contrast verified against WCAG AA, so the
UI reuses those tokens and looks like the documentation rather than like a
component library.

If the editor in phase 2 turns out to want real form components, that is the
point to revisit this, with evidence.

## Architecture

```
cmd/mailctl            `ui` subcommand: flag parsing, token, listener, browser
  └── internal/ui      http.Handler, middleware, embedded assets, no provider imports
        ├── internal/planjson   plan.Plan and audit.Report -> stable JSON
        └── internal/engine     existing: Plan, Domains, Desired
              └── providers     unchanged
```

`internal/ui` talks to the engine and to nothing below it. The existing depguard
rules are extended so the UI package cannot import a provider package directly;
a UI that reached past the engine would duplicate the engine's ordering and
safety logic.

### Endpoints

| Method | Path | Reads the network | Returns |
|---|---|---|---|
| `GET` | `/api/domains` | no | the domains in config, from the config file alone |
| `POST` | `/api/plan` | yes | per-domain actions, or a per-domain error |
| `POST` | `/api/audit` | yes | per-domain checks with pass/fail and detail |

`GET /api/domains` performing no network I/O is what makes the first paint
instant and keeps provider calls tied to an explicit request.

### Frontend

One screen: domains listed with a converged-or-drifted summary, expandable to the
actions a run would take and to audit check results. Pinia holds the fetched
state; no client-side persistence.

## Testing

- Handler tests through `httptest`, including a missing token, a wrong token, a
  foreign `Origin`, and a foreign `Host`, each asserted to be rejected.
- Golden-file tests for the JSON schema, so a schema change shows up as a visible
  diff in review rather than as a surprise to a consumer.
- A test asserting no credential-bearing value appears in what the server logs.
- Vitest for the store and rendering.
- The existing suite must stay green with and without `-race`, and
  `golangci-lint` must report nothing.

## Out of scope for phase 1

Editing config, applying a plan, authentication beyond the local token, remote or
multi-user access, TLS, and any form of persistence. Serving assets from a CDN is
rejected outright: the tool configures infrastructure and must work offline.
