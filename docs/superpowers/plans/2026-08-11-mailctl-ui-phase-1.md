# mailctl UI Client, Phase 1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `mailctl ui` serves a local, read-only browser view of what every
configured domain looks like now and what a run would change, and `mailctl plan
-json` emits the same data for scripts.

**Architecture:** One new package projects `plan.Plan` and `audit.Report` into a
stable JSON schema, consumed by both the `-json` CLI flag and an embedded HTTP
server. The server is stdlib `net/http`, binds `127.0.0.1` on a kernel-chosen
port, authenticates every request with a per-process token plus `Origin`/`Host`
checks, and reaches providers only through the existing engine. A Vue frontend is
built by Vite into a committed directory and embedded with `go:embed`.

**Tech Stack:** Go 1.26 (stdlib only for the server), Vue 3 with `<script setup>`,
TypeScript, Pinia, Vite, Vitest.

## Global Constraints

Copied from `docs/superpowers/specs/2026-08-11-mailctl-ui-design.md`. Every task
inherits these.

- **Exactly one non-stdlib Go dependency:** `gopkg.in/yaml.v3`. CI fails on a
  second direct requirement. The server uses stdlib `net/http` only. npm packages
  are build-time and must not appear in `go.mod`.
- **No daemon, no state file.** `mailctl ui` runs in the foreground, writes
  nothing to disk, and exits on interrupt. No pidfile, no background flag, no
  cache on disk.
- **No credential is ever typed into a page.** The process reads the same
  environment variables the CLI does. No login form; no endpoint accepts a
  provider credential.
- **No credential reaches stdout or any log.** Do not log request bodies, query
  strings, or headers.
- **The JSON never carries `Action.Do`.** The projection describes intent and is
  never a capability. Apply is out of scope for this phase, and a later phase must
  not rebuild a plan from client-supplied JSON.
- **Live provider reads happen only on explicit request** — never on page load,
  navigation, or re-render.
- **`internal/ui` must not import a provider package.** It goes through the
  engine. Enforced by depguard in Task 12.
- **Quasar is not used.** Style with the docs site's design tokens.
- **`gofmt` clean, `go vet` silent, `golangci-lint` reports nothing, all packages
  pass with and without `-race`** before every commit. Lint locally with:
  `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...`
- **Conventional commits**, imperative, lowercase, under 60 characters in the
  subject. No attribution trailers of any kind.

---

## File Structure

| File | Responsibility |
|---|---|
| `internal/planjson/plan.go` | `Plan`/`Action` JSON types and `FromPlan` |
| `internal/planjson/audit.go` | `Report`/`Check` JSON types and `FromReport` |
| `internal/planjson/testdata/*.json` | Golden files pinning the schema |
| `internal/ui/server.go` | `Server`, `Deps`, `Planner` interface, routing |
| `internal/ui/auth.go` | Token and `Origin`/`Host` middleware |
| `internal/ui/api.go` | The three API handlers |
| `internal/ui/assets.go` | `go:embed` of `dist`, static and SPA-fallback serving |
| `internal/ui/dist/` | Committed Vite output (generated; never hand-edited) |
| `web/` | Frontend source: Vue app, store, styles, Vitest specs |
| `cmd/mailctl/ui.go` | `ui` subcommand: listener, token, browser, shutdown |

---

### Task 1: JSON projection for a plan

**Files:**
- Create: `internal/planjson/plan.go`
- Create: `internal/planjson/plan_test.go`
- Create: `internal/planjson/testdata/plan.json`

**Interfaces:**
- Consumes: `plan.Plan` and `plan.Action` from `internal/plan` — `Action` has
  fields `Op plan.Op`, `Resource string`, `Domain string`, `Provider string`,
  `Detail string`, `Do func(context.Context) error`. `plan.Op` is a string type
  with constants `OpCreate` (`"CREATE"`), `OpUpdate` (`"UPDATE"`), `OpDelete`
  (`"DELETE"`), `OpManual` (`"MANUAL"`).
- Produces: `planjson.Plan`, `planjson.Action`, and
  `func FromPlan(p plan.Plan) Plan`.

- [ ] **Step 1: Write the failing test**

```go
package planjson

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/zoolcoder/mailctl/internal/plan"
)

func TestFromPlanProjectsEveryFieldExceptDo(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{
		{
			Op: plan.OpCreate, Resource: "dns", Domain: "example.com",
			Provider: "purelymail", Detail: "MX example.com -> mail.example.net",
			Do: func(context.Context) error { return nil },
		},
		{
			Op: plan.OpManual, Resource: "dkim", Domain: "example.com",
			Detail: "read the CNAME targets from the admin portal",
		},
	}}

	got := FromPlan(in)

	if got.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", got.SchemaVersion)
	}
	if len(got.Actions) != 2 {
		t.Fatalf("got %d actions, want 2", len(got.Actions))
	}
	first := got.Actions[0]
	if first.Op != "CREATE" || first.Resource != "dns" || first.Domain != "example.com" {
		t.Errorf("first action = %+v", first)
	}
	if first.Provider != "purelymail" || first.Detail == "" {
		t.Errorf("first action lost provider or detail: %+v", first)
	}
	if first.Manual {
		t.Error("a CREATE action must not be marked manual")
	}
	if !got.Actions[1].Manual {
		t.Error("an OpManual action must be marked manual; it renders but never executes")
	}
}

// The JSON is a description of intent. If a capability ever leaks into it, that
// is a security regression, not a formatting one.
func TestPlanJSONCarriesNoExecutableField(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{{
		Op: plan.OpDelete, Resource: "mailbox", Domain: "example.com",
		Detail: "delete contact@example.com",
		Do:     func(context.Context) error { return nil },
	}}}

	raw, err := json.Marshal(FromPlan(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, forbidden := range []string{"Do", "\"do\"", "func"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Errorf("serialised plan contains %q: %s", forbidden, raw)
		}
	}
}

// An empty plan must serialise as an empty array, not null: a consumer doing
// `for (const a of plan.actions)` would crash on null, and "no changes" is a
// normal, frequent outcome.
func TestEmptyPlanSerialisesAsAnEmptyArray(t *testing.T) {
	raw, err := json.Marshal(FromPlan(plan.Plan{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"actions":[]`)) {
		t.Errorf("empty plan = %s, want an empty actions array", raw)
	}
}

func TestPlanSchemaMatchesTheGoldenFile(t *testing.T) {
	in := plan.Plan{Actions: []plan.Action{{
		Op: plan.OpCreate, Resource: "mailbox", Domain: "example.com",
		Provider: "purelymail", Detail: "create contact@example.com",
	}}}

	got, err := json.MarshalIndent(FromPlan(in), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/plan.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimRight(string(want), "\n") {
		t.Errorf("schema changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
```

Add `"bytes"`, `"context"` and `"strings"` to the import block.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/planjson/`
Expected: FAIL — the package does not exist yet.

- [ ] **Step 3: Write the implementation**

```go
// Package planjson projects mailctl's plan and audit results into a stable JSON
// schema. Both `mailctl plan -json` and the local UI server render through it,
// so a script gating a pipeline and the UI can never disagree about what a run
// intends to do.
package planjson

import "github.com/zoolcoder/mailctl/internal/plan"

// SchemaVersion is incremented when a change would break an existing consumer.
// Adding a field is not such a change; removing or repurposing one is.
const SchemaVersion = 1

// Action is one intended change, described but not executable.
//
// plan.Action carries Do, a closure over live provider clients. It is
// deliberately absent here: this type describes intent, and a plan that has been
// through JSON must never be a way to ask for work. Apply resolves actions from
// a plan it holds itself.
type Action struct {
	// ID identifies the action within this plan only. It is a position, not a
	// durable identity, and it is not stable across runs.
	ID       string `json:"id"`
	Op       string `json:"op"`
	Resource string `json:"resource"`
	Domain   string `json:"domain"`
	Provider string `json:"provider,omitempty"`
	Detail   string `json:"detail"`
	// Manual marks an action a human completes outside mailctl. It renders in
	// the plan and is never executed, so a converged plan may still list one.
	Manual bool `json:"manual"`
}

type Plan struct {
	SchemaVersion int      `json:"schemaVersion"`
	Actions       []Action `json:"actions"`
}

func FromPlan(p plan.Plan) Plan {
	// Non-nil so an empty plan marshals as [] rather than null.
	actions := make([]Action, 0, len(p.Actions))
	for i, a := range p.Actions {
		actions = append(actions, Action{
			ID:       strconv.Itoa(i),
			Op:       string(a.Op),
			Resource: a.Resource,
			Domain:   a.Domain,
			Provider: a.Provider,
			Detail:   a.Detail,
			Manual:   a.Op == plan.OpManual,
		})
	}
	return Plan{SchemaVersion: SchemaVersion, Actions: actions}
}
```

Add `"strconv"` to the imports.

- [ ] **Step 4: Write the golden file**

Create `internal/planjson/testdata/plan.json`:

```json
{
  "schemaVersion": 1,
  "actions": [
    {
      "id": "0",
      "op": "CREATE",
      "resource": "mailbox",
      "domain": "example.com",
      "provider": "purelymail",
      "detail": "create contact@example.com",
      "manual": false
    }
  ]
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/planjson/`
Expected: PASS

- [ ] **Step 6: Verify the test would catch a regression**

Temporarily change `Manual: a.Op == plan.OpManual` to `Manual: false`, run
`go test ./internal/planjson/`, confirm FAIL, then restore it. A test that cannot
fail is worse than no test.

- [ ] **Step 7: Commit**

```bash
git add internal/planjson/plan.go internal/planjson/plan_test.go internal/planjson/testdata/plan.json
git commit -m "feat(planjson): project a plan into a stable json schema"
```

---

### Task 2: JSON projection for an audit report

**Files:**
- Create: `internal/planjson/audit.go`
- Create: `internal/planjson/audit_test.go`
- Create: `internal/planjson/testdata/audit.json`

**Interfaces:**
- Consumes: `audit.Report` from `internal/audit` — fields `Domain string`,
  `Checks []audit.Check`, `Notes []string`; method `OK() bool`. `audit.Check` has
  `Name string`, `Want string`, `Got string`, `OK bool`.
- Produces: `planjson.Report`, `planjson.Check`, and
  `func FromReport(r audit.Report) Report`.

- [ ] **Step 1: Write the failing test**

```go
package planjson

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/audit"
)

func TestFromReportCarriesTheOverallVerdict(t *testing.T) {
	// OK() is a method, so it does not serialise on its own. The UI colours a
	// domain by it, so it has to be an explicit field.
	failing := audit.Report{Domain: "example.com", Checks: []audit.Check{
		{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true},
		{Name: "SPF", Want: "v=spf1 include:example.net ~all", Got: "", OK: false},
	}}

	got := FromReport(failing)

	if got.OK {
		t.Error("OK = true although one check failed")
	}
	if len(got.Checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(got.Checks))
	}
	if got.Checks[1].Name != "SPF" || got.Checks[1].OK {
		t.Errorf("second check = %+v, want the failing SPF check", got.Checks[1])
	}

	passing := audit.Report{Domain: "example.com", Checks: []audit.Check{
		{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true},
	}}
	if !FromReport(passing).OK {
		t.Error("OK = false although every check passed")
	}
}

func TestReportWithNoChecksOrNotesSerialisesAsEmptyArrays(t *testing.T) {
	raw, err := json.Marshal(FromReport(audit.Report{Domain: "example.com"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"checks":[]`, `"notes":[]`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("report = %s, want %s rather than null", raw, want)
		}
	}
}

func TestAuditSchemaMatchesTheGoldenFile(t *testing.T) {
	in := audit.Report{
		Domain: "example.com",
		Checks: []audit.Check{{Name: "MX", Want: "mail.example.net", Got: "mail.example.net", OK: true}},
		Notes:  []string{"DKIM targets are taken from config"},
	}

	got, err := json.MarshalIndent(FromReport(in), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want, err := os.ReadFile("testdata/audit.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if string(got) != strings.TrimRight(string(want), "\n") {
		t.Errorf("schema changed.\ngot:\n%s\nwant:\n%s", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/planjson/ -run Report`
Expected: FAIL — `FromReport` is undefined.

- [ ] **Step 3: Write the implementation**

```go
package planjson

import "github.com/zoolcoder/mailctl/internal/audit"

type Check struct {
	Name string `json:"name"`
	Want string `json:"want"`
	Got  string `json:"got"`
	OK   bool   `json:"ok"`
}

// Report is one domain's audit result. OK is materialised as a field because
// audit.Report.OK() is a method and would otherwise be invisible to a consumer.
type Report struct {
	Domain string   `json:"domain"`
	OK     bool     `json:"ok"`
	Checks []Check  `json:"checks"`
	Notes  []string `json:"notes"`
}

func FromReport(r audit.Report) Report {
	// Non-nil so absent checks and notes marshal as [] rather than null.
	checks := make([]Check, 0, len(r.Checks))
	for _, c := range r.Checks {
		checks = append(checks, Check{Name: c.Name, Want: c.Want, Got: c.Got, OK: c.OK})
	}
	notes := make([]string, 0, len(r.Notes))
	notes = append(notes, r.Notes...)

	return Report{Domain: r.Domain, OK: r.OK(), Checks: checks, Notes: notes}
}
```

- [ ] **Step 4: Write the golden file**

Create `internal/planjson/testdata/audit.json`:

```json
{
  "domain": "example.com",
  "ok": true,
  "checks": [
    {
      "name": "MX",
      "want": "mail.example.net",
      "got": "mail.example.net",
      "ok": true
    }
  ],
  "notes": [
    "DKIM targets are taken from config"
  ]
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/planjson/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/planjson/audit.go internal/planjson/audit_test.go internal/planjson/testdata/audit.json
git commit -m "feat(planjson): project an audit report into json"
```

---

### Task 3: `mailctl plan -json`

**Files:**
- Modify: `cmd/mailctl/main.go` — add the flag beside the existing `plan` flags,
  and branch where the plan is rendered
- Modify: `cmd/mailctl/main_test.go` — add the test below

**Interfaces:**
- Consumes: `planjson.FromPlan` from Task 1.
- Produces: a `-json` flag on `plan`. No new exported Go identifiers.

- [ ] **Step 1: Write the failing test**

Find how existing tests in `cmd/mailctl/main_test.go` invoke `run` and follow
that pattern exactly. The test asserts two things: valid JSON on stdout, and that
human framing (the "N actions" summary and the "Run `mailctl apply`" hint) is
absent, because a consumer piping into `jq` must not receive prose.

Write the config fixture with the same helper the existing `plan` tests in
`cmd/mailctl/main_test.go` use. If they build it inline, do the same: write a
minimal one-domain config into `t.TempDir()` and pass its path to `-config`. A
plan that reaches no provider is enough, because `-json` is a rendering concern.

```go
func TestPlanJSONEmitsOnlyJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"plan", "-json", "-config", fixtureConfigPath}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}

	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Actions       []struct {
			Op     string `json:"op"`
			Domain string `json:"domain"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid json: %v\ngot: %s", err, stdout.String())
	}
	if doc.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", doc.SchemaVersion)
	}

	// stdout must be the document and nothing else. Assert the shape directly:
	// a prose check of the form `contains(prose) && !contains("\"actions\"")`
	// can never fire, because the document always contains "actions".
	out := stdout.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("stdout does not begin with a json object: %q", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Errorf("stdout does not end with a json object; something was appended: %q", out)
	}
	for _, prose := range []string{"Run `mailctl apply`", "No changes.", " actions\n"} {
		if strings.Contains(out, prose) {
			t.Errorf("stdout carries the human rendering %q, which breaks a jq consumer", prose)
		}
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./cmd/mailctl/ -run TestPlanJSON`
Expected: FAIL — `flag provided but not defined: -json`.

- [ ] **Step 3: Add the flag and the branch**

Declare it with the other `plan` flags:

```go
	planJSON := flags.Bool("json", false,
		"print the plan as JSON on stdout instead of the human summary")
```

Add it to `rejectScopedFlags` so `-json` is refused on commands it does not apply
to, matching how the existing scoped flags are handled.

The plan value is named `built` in `run`, and the human path is
`built.Render(stdout)` followed by the `built.Executable()` check that prints the
"Run `mailctl apply`" hint. Branch **before** both, so no prose reaches stdout:

```go
	if command == "plan" && *planJSON {
		// Encode to stdout only. A human summary interleaved with the document
		// would break every consumer that pipes this into a parser.
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(planjson.FromPlan(built))
	}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./cmd/mailctl/`
Expected: PASS, including the existing tests — the human path must be unchanged.

- [ ] **Step 5: Commit**

```bash
git add cmd/mailctl/main.go cmd/mailctl/main_test.go
git commit -m "feat(plan): add -json for machine-readable plan output"
```

---

### Task 4: Frontend scaffold and the committed bundle

**Files:**
- Create: `web/package.json` scripts wired into the root `package.json`
- Create: `web/vite.config.ts`, `web/tsconfig.json`, `web/index.html`
- Create: `web/src/main.ts`, `web/src/App.vue`
- Create: `internal/ui/dist/` (Vite output, committed)
- Modify: `package.json` — add `ui:build` and `ui:dev` scripts
- Modify: `.gitattributes` — mark the bundle as generated

**Interfaces:**
- Produces: `npm run ui:build` writes `internal/ui/dist/index.html` plus hashed
  assets. Task 5 embeds that directory.

- [ ] **Step 1: Scaffold the app**

The root `package.json` already holds the Antora toolchain; add the UI build
beside it rather than creating a second npm root. Vite config must emit into the
Go package so `go:embed` can see it, and must use relative asset paths because
the server mounts at `/`:

```ts
// web/vite.config.ts
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  base: './',
  build: {
    outDir: '../internal/ui/dist',
    emptyOutDir: true,
    // A stable, non-hashed entry name keeps the committed bundle's diff
    // readable in review. Assets keep [name] rather than a content hash for the
    // same reason — but they must keep it: a bare `app.[ext]` collides two
    // same-extension assets onto one filename and silently overwrites one.
    rollupOptions: { output: { entryFileNames: 'app.js', assetFileNames: 'app-[name].[ext]' } },
  },
})
```

- [ ] **Step 2: Mark the bundle as generated**

Add to `.gitattributes`:

```
internal/ui/dist/** linguist-generated=true -diff
```

This keeps bundle diffs collapsed in review. The freshness check in Task 12 is
what actually guarantees the committed output matches source.

- [ ] **Step 3: Build and confirm the output exists**

Run: `npm run ui:build`
Expected: `internal/ui/dist/index.html` and `internal/ui/dist/app.js` exist.

- [ ] **Step 4: Commit**

```bash
git add package.json package-lock.json web/ internal/ui/dist/ .gitattributes
git commit -m "build(ui): scaffold the vue frontend and its bundle"
```

Note: `package-lock.json` is committed as the record of a dependency change. Do
not hand-edit it.

---

### Task 5: Embed and serve the bundle

**Files:**
- Create: `internal/ui/assets.go`
- Create: `internal/ui/assets_test.go`

**Interfaces:**
- Consumes: `internal/ui/dist/` from Task 4.
- Produces: `func assetHandler() (http.Handler, error)`.

- [ ] **Step 1: Write the failing test**

```go
package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetHandlerServesTheIndex(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("body does not look like the app shell: %s", rec.Body.String())
	}
}

// A single-page app owns its routes, so an unknown non-API path must return the
// shell rather than a 404 the user would see as a broken page.
func TestUnknownPathFallsBackToTheIndex(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/domains/example.com", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with the app shell", rec.Code)
	}
}

// A missing asset under a path that looks like a real file should 404 rather
// than silently returning HTML, which would otherwise reach the browser as a
// script and fail with a confusing parse error.
func TestMissingAssetIsNotGivenTheHTMLShell(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/absent.js", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for a missing .js asset, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/ui/`
Expected: FAIL — `assetHandler` is undefined.

- [ ] **Step 3: Write the implementation**

```go
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The bundle is committed so that `mailctl ui` behaves the same however the
// binary was installed: `go install` cannot run npm. CI rebuilds it and fails if
// the committed output differs from source.
//
//go:embed all:dist
var assets embed.FS

func assetHandler() (http.Handler, error) {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		return nil, err
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "" || clean == "." {
			clean = "index.html"
		}
		if _, err := fs.Stat(sub, clean); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		// A miss that names an asset type the bundle actually contains is a
		// genuine 404: serving the HTML shell in place of a missing .js reaches
		// the browser as a script and fails with an unrelated parse error.
		//
		// Do NOT decide this with `path.Ext(clean) != ""`. This tool's
		// client-side routes are domain names, and path.Ext("/domains/
		// example.com") is ".com" — that rule 404s every deep link. Collect the
		// extensions present in the embedded bundle instead (fs.WalkDir at
		// startup) and 404 only when the miss carries one of them.
		if bundleExtensions[path.Ext(clean)] {
			http.NotFound(w, r)
			return
		}
		// Otherwise it is a client-side route: return the shell.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	}), nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/ui/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ui/assets.go internal/ui/assets_test.go
git commit -m "feat(ui): embed and serve the frontend bundle"
```

---

### Task 6: Token and origin authentication

**Files:**
- Create: `internal/ui/auth.go`
- Create: `internal/ui/auth_test.go`

**Interfaces:**
- Produces: `func newAuth(token, host string) func(http.Handler) http.Handler`.
  The returned middleware allows a request when the token matches **and** the
  `Origin` and `Host` checks pass, and returns 403 otherwise.

**Why this task exists:** binding `127.0.0.1` is not access control. Any local
process, and any web page in any open tab, can send requests to a known local
port. This process holds a Cloudflare token with DNS write across every managed
zone. The `Origin` check is what defeats DNS rebinding, where an
attacker-controlled name resolves to `127.0.0.1` and the browser then treats the
server as same-origin by IP while still sending a foreign `Origin`.

- [ ] **Step 1: Write the failing test**

```go
package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func allowed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthAcceptsTheTokenFromTheHeader(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/domains", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "secret")
	req.Header.Set("Origin", "http://127.0.0.1:1234")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a correctly authenticated request", rec.Code)
	}
}

// The launch URL carries the token as a query parameter so the browser can load
// the page; the app then sends it as a header.
func TestAuthAcceptsTheTokenFromTheQueryOnTheInitialLoad(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/?token=secret", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for the initial page load", rec.Code)
	}
}

func TestAuthRejectsEveryUnauthenticatedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"no token at all", func(r *http.Request) {}},
		{"wrong token", func(r *http.Request) { r.Header.Set("X-Mailctl-Token", "guess") }},
		{"empty token", func(r *http.Request) { r.Header.Set("X-Mailctl-Token", "") }},
		{"foreign origin", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Header.Set("Origin", "http://evil.example")
		}},
		{"foreign host, the dns rebinding shape", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Host = "attacker.example"
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := newAuth("secret", "127.0.0.1:1234")(allowed())
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/plan", nil)
			req.Host = "127.0.0.1:1234"
			c.mutate(req)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// A rejection must not disclose the expected token, and must not echo the
// supplied one into a body an attacker can read.
func TestAuthRejectionRevealsNothing(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/plan", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "guess")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	for _, leak := range []string{"secret", "guess"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("rejection body contains %q: %s", leak, rec.Body.String())
		}
	}
}
```

Add `"strings"` to the imports.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/ui/ -run TestAuth`
Expected: FAIL — `newAuth` is undefined.

- [ ] **Step 3: Write the implementation**

```go
package ui

import (
	"crypto/subtle"
	"net/http"
)

// newAuth guards every route. Three things must hold: the request carries the
// per-process token, its Host is the address we are actually listening on, and
// its Origin — when the browser sends one — is ours.
//
// The Host and Origin checks are not belt-and-braces. A local listener is
// reachable by any process on the machine and by any page in any open tab, and
// DNS rebinding lets an attacker-controlled name resolve to 127.0.0.1. In that
// attack the browser sends a foreign Origin and a foreign Host, which is exactly
// what these two checks catch.
func newAuth(token, host string) func(http.Handler) http.Handler {
	expectedOrigin := "http://" + host

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				forbid(w)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != expectedOrigin {
				forbid(w)
				return
			}
			supplied := r.Header.Get("X-Mailctl-Token")
			if supplied == "" {
				supplied = r.URL.Query().Get("token")
			}
			// Constant time so the comparison cannot be used as an oracle.
			if len(supplied) != len(token) ||
				subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
				forbid(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forbid says nothing about why. Naming the expected value, or echoing the
// supplied one, would hand an attacker the thing they are probing for.
func forbid(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/ui/`
Expected: PASS

- [ ] **Step 5: Verify each rejection is real**

Temporarily make `newAuth` return `next` unchanged, run
`go test ./internal/ui/ -run TestAuth`, and confirm every rejection subtest
fails. Restore it. A guard whose tests pass when the guard is removed is not a
guard.

- [ ] **Step 6: Commit**

```bash
git add internal/ui/auth.go internal/ui/auth_test.go
git commit -m "feat(ui): authenticate requests by token, host and origin"
```

---

### Task 7: The server and the domains endpoint

**Files:**
- Create: `internal/ui/server.go`
- Create: `internal/ui/api.go`
- Create: `internal/ui/api_test.go`

**Interfaces:**
- Consumes: `assetHandler` (Task 5), `newAuth` (Task 6), `planjson` (Tasks 1–2).
- Produces:

```go
type Planner interface {
	Domains() ([]config.Domain, error)
	Plan(ctx context.Context) (plan.Plan, error)
	Desired(ctx context.Context, d config.Domain) ([]dns.Record, error)
}

type Auditor func(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report

type Deps struct {
	Token   string
	Host    string
	Planner Planner
	Audit   Auditor
}

func New(deps Deps) (http.Handler, error)
```

`*engine.Engine` satisfies `Planner` as it stands. The interface exists so
handler tests need no provider and no network, and so `internal/ui` never imports
a provider package.

- [ ] **Step 1: Write the failing test**

```go
package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

type fakePlanner struct {
	domains  []config.Domain
	planned  plan.Plan
	planErr  error
	planned_ int // times Plan was called
}

func (f *fakePlanner) Domains() ([]config.Domain, error) { return f.domains, nil }
func (f *fakePlanner) Plan(context.Context) (plan.Plan, error) {
	f.planned_++
	return f.planned, f.planErr
}
func (f *fakePlanner) Desired(context.Context, config.Domain) ([]dns.Record, error) {
	return nil, nil
}

func testServer(t *testing.T, p Planner) http.Handler {
	t.Helper()
	handler, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: p,
		Audit: func(context.Context, config.Domain, []dns.Record) audit.Report {
			return audit.Report{Domain: "example.com"}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return handler
}

func authed(method, target string) *http.Request {
	req := httptest.NewRequest(method, "http://127.0.0.1:1234"+target, nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "secret")
	req.Header.Set("Origin", "http://127.0.0.1:1234")
	return req
}

func TestDomainsEndpointReadsConfigWithoutTouchingProviders(t *testing.T) {
	fake := &fakePlanner{domains: []config.Domain{
		{Name: "example.com", ZoneName: "example.com"},
		{Name: "example.net", ZoneName: "example.net"},
	}}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/domains"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Domains []struct {
			Name string `json:"name"`
		} `json:"domains"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v — %s", err, rec.Body.String())
	}
	if len(doc.Domains) != 2 || doc.Domains[0].Name != "example.com" {
		t.Errorf("domains = %+v", doc.Domains)
	}
	// The first paint must be instant and must not spend a provider call.
	if fake.planned_ != 0 {
		t.Errorf("Plan was called %d times serving /api/domains; it must reach no provider", fake.planned_)
	}
}

func TestAPIRequiresAuthentication(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/domains", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d for an unauthenticated api call, want 403", rec.Code)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/ui/ -run "TestDomains|TestAPIRequires"`
Expected: FAIL — `New` and `Deps` are undefined.

- [ ] **Step 3: Write `server.go`**

```go
// Package ui serves the local read-only view of mailctl's plan and audit
// results. It reaches providers only through the engine: duplicating the
// engine's ordering and safety logic behind an HTTP handler is how the two would
// come to disagree.
package ui

import (
	"context"
	"net/http"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// Planner is the slice of the engine this server needs. It is an interface so
// handler tests need neither a provider nor a network.
type Planner interface {
	Domains() ([]config.Domain, error)
	Plan(ctx context.Context) (plan.Plan, error)
	Desired(ctx context.Context, d config.Domain) ([]dns.Record, error)
}

// Auditor runs one domain's audit. Injected so tests do not perform DNS lookups.
type Auditor func(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report

type Deps struct {
	// Token authenticates the browser to this process. It is not a provider
	// secret and never leaves the machine.
	Token   string
	Host    string
	Planner Planner
	Audit   Auditor
}

func New(deps Deps) (http.Handler, error) {
	static, err := assetHandler()
	if err != nil {
		return nil, err
	}
	s := &server{deps: deps}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/domains", s.handleDomains)
	mux.HandleFunc("POST /api/plan", s.handlePlan)
	mux.HandleFunc("POST /api/audit", s.handleAudit)
	// Everything under /api/ that did not match above ends here rather than at
	// the SPA fallback. This is not defensive tidying: it was measured. With a
	// "/" catch-all registered, ServeMux does NOT answer 405 for a
	// method-pattern mismatch — `GET /api/plan` falls through to "/" and returns
	// the HTML shell with 200. A client would then parse a page as JSON, and the
	// GET-refusal test below would pass against a route that quietly served HTML.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	mux.Handle("/", static)

	return newAuth(deps.Token, deps.Host)(mux), nil
}

type server struct{ deps Deps }
```

- [ ] **Step 4: Write the domains handler in `api.go`**

```go
package ui

import (
	"encoding/json"
	"net/http"
)

type domainSummary struct {
	Name      string   `json:"name"`
	Zone      string   `json:"zone"`
	Providers []string `json:"providers"`
}

// handleDomains answers from the config alone. It performs no provider I/O, which
// is what makes the first paint instant and keeps every network call tied to an
// explicit request from the operator.
func (s *server) handleDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]domainSummary, 0, len(domains))
	for _, d := range domains {
		providers := make([]string, 0, len(d.Mail.Providers))
		providers = append(providers, d.Mail.Providers...)
		out = append(out, domainSummary{Name: d.Name, Zone: d.ZoneName, Providers: providers})
	}
	writeJSON(w, map[string]any{"domains": out})
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	// Any encode failure here has already written a partial body, so there is
	// nothing useful to report to the client.
	_ = json.NewEncoder(w).Encode(payload)
}

// writeError sends the error text. Provider errors are safe to show: the CLI
// already prints them, and none of them carries a credential — a failing token
// request deliberately never echoes its response body.
func writeError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/ui/`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/ui/server.go internal/ui/api.go internal/ui/api_test.go
git commit -m "feat(ui): serve the domain list from config"
```

---

### Task 8: The plan and audit endpoints

**Files:**
- Modify: `internal/ui/api.go`
- Modify: `internal/ui/api_test.go`

**Interfaces:**
- Consumes: `Planner`, `Auditor`, `Deps`, `writeJSON`, `writeError` (Task 7);
  `planjson.FromPlan`, `planjson.FromReport` (Tasks 1–2).
- Produces: `POST /api/plan` returning a `planjson.Plan`, and `POST /api/audit`
  returning `{"reports": [...]}` where each entry is a `planjson.Report` or an
  entry carrying `error` for that domain.

- [ ] **Step 1: Write the failing test**

```go
func TestPlanEndpointReturnsTheProjectedPlan(t *testing.T) {
	fake := &fakePlanner{planned: plan.Plan{Actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "example.com",
			Provider: "purelymail", Detail: "create contact@example.com"},
	}}}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodPost, "/api/plan"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — body: %s", rec.Code, rec.Body.String())
	}
	var doc struct {
		SchemaVersion int `json:"schemaVersion"`
		Actions       []struct {
			Op     string `json:"op"`
			Detail string `json:"detail"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v — %s", err, rec.Body.String())
	}
	if doc.SchemaVersion != 1 || len(doc.Actions) != 1 || doc.Actions[0].Op != "CREATE" {
		t.Errorf("plan body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "func") {
		t.Error("the response must not carry anything executable")
	}
}

// A GET must not plan: planning calls provider APIs, and a GET is what a
// prefetch, a crawler, or an address-bar visit issues.
//
// Asserting the status is not enough on its own. ServeMux with a "/" catch-all
// falls through to the SPA shell for a method mismatch and answers 200 with
// HTML, so this also asserts the body is not the shell — otherwise the test
// passes against a route that silently serves a page where JSON belongs.
func TestPlanEndpointRefusesGET(t *testing.T) {
	fake := &fakePlanner{}
	server := testServer(t, fake)

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/plan"))

	if rec.Code == http.StatusOK {
		t.Error("GET /api/plan returned 200; planning must require an explicit POST")
	}
	if strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Error("GET /api/plan served the html shell; an api path must never fall through to the spa")
	}
	if fake.planned_ != 0 {
		t.Errorf("Plan ran %d times for a GET; a prefetch must not spend provider calls", fake.planned_)
	}
}

// An unknown /api/ path must be a 404, not the html shell.
func TestUnknownAPIPathIsNotTheShell(t *testing.T) {
	server := testServer(t, &fakePlanner{})

	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, authed(http.MethodGet, "/api/nonexistent"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for an unknown api path, want 404 — body: %s", rec.Code, rec.Body.String())
	}
}

// One domain failing must not blank the whole view: the operator needs to see
// the domains that did resolve.
func TestAuditReportsPerDomainErrorsWithoutFailingTheRun(t *testing.T) {
	fake := &fakePlanner{domains: []config.Domain{
		{Name: "good.example"}, {Name: "bad.example"},
	}}
	handler, err := New(Deps{
		Token: "secret", Host: "127.0.0.1:1234", Planner: fake,
		Audit: func(_ context.Context, d config.Domain, _ []dns.Record) audit.Report {
			return audit.Report{Domain: d.Name, Checks: []audit.Check{
				{Name: "MX", OK: d.Name == "good.example"},
			}}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, authed(http.MethodPost, "/api/audit"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Reports []struct {
			Domain string `json:"domain"`
			OK     bool   `json:"ok"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not json: %v", err)
	}
	if len(doc.Reports) != 2 {
		t.Fatalf("got %d reports, want one per domain", len(doc.Reports))
	}
	if !doc.Reports[0].OK || doc.Reports[1].OK {
		t.Errorf("reports = %+v, want good.example passing and bad.example failing", doc.Reports)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/ui/ -run "TestPlanEndpoint|TestAudit"`
Expected: FAIL — the routes return the SPA shell rather than JSON.

- [ ] **Step 3: Write the handlers**

```go
// handlePlan runs a full plan. It is a POST because planning reads live provider
// state: a GET is what a prefetch or an address-bar visit issues, and neither
// should spend a provider call or a rate-limit token.
func (s *server) handlePlan(w http.ResponseWriter, r *http.Request) {
	p, err := s.deps.Planner.Plan(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, planjson.FromPlan(p))
}

// reportOrError is one domain's audit outcome. A domain whose desired records
// cannot be computed reports its own error rather than blanking the view for
// every other domain.
type reportOrError struct {
	planjson.Report
	Error string `json:"error,omitempty"`
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	domains, err := s.deps.Planner.Domains()
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]reportOrError, 0, len(domains))
	for _, d := range domains {
		desired, err := s.deps.Planner.Desired(r.Context(), d)
		if err != nil {
			out = append(out, reportOrError{
				Report: planjson.Report{Domain: d.Name, Checks: []planjson.Check{}, Notes: []string{}},
				Error:  err.Error(),
			})
			continue
		}
		out = append(out, reportOrError{Report: planjson.FromReport(s.deps.Audit(r.Context(), d, desired))})
	}
	writeJSON(w, map[string]any{"reports": out})
}
```

Add the `planjson` import.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test -count=1 ./internal/ui/`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ui/api.go internal/ui/api_test.go
git commit -m "feat(ui): add the plan and audit endpoints"
```

---

### Task 9: The `mailctl ui` subcommand

**Files:**
- Create: `cmd/mailctl/ui.go`
- Modify: `cmd/mailctl/main.go` — accept `ui` in the command switch at
  `main.go:208`, add it to the usage text's command list and to
  `rejectScopedFlags`
- Modify: `cmd/mailctl/main_test.go`

**Interfaces:**
- Consumes: `ui.New`, `ui.Deps` (Tasks 7–8); the existing engine wiring in
  `run` that builds `cfg`, `zones`, `deployer`, `deps`, `secrets` and calls
  `engine.New` at `main.go:425`.
- Produces: `func serveUI(ctx context.Context, runner *engine.Engine, addr string, openBrowser bool, stdout io.Writer) error`.

**Wiring note:** `ui` needs exactly what `plan` needs. Reuse the existing path
rather than duplicating it: let the `ui` command fall through the same config
load, credential check and `engine.New` construction, then branch to `serveUI`
where `audit` branches at `main.go:433`. If that requires extracting the
construction into a helper, extract it and leave every existing command going
through the same helper — do not copy it.

- [ ] **Step 1: Write the failing test**

```go
func TestUICommandIsRecognised(t *testing.T) {
	// -h on the subcommand must exit zero with usage, like every other command.
	var stdout, stderr bytes.Buffer
	err := run([]string{"ui", "-h"}, nil, &stdout, &stderr)
	if err != nil {
		t.Fatalf("ui -h returned %v, want nil — stderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "ui") {
		t.Errorf("usage does not mention the ui command: %s", stdout.String())
	}
}

func TestUsageListsTheUICommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"help"}, nil, &stdout, &stderr); err != nil {
		t.Fatalf("help: %v", err)
	}
	if !strings.Contains(stdout.String(), "mailctl ui") {
		t.Errorf("usage omits the ui command:\n%s", stdout.String())
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./cmd/mailctl/ -run TestUI`
Expected: FAIL — `ui` is rejected as an unknown command.

- [ ] **Step 3: Write `ui.go`**

```go
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/engine"
	"github.com/zoolcoder/mailctl/internal/ui"
)

// serveUI runs the local UI until the context is cancelled. It is a foreground
// server on purpose: mailctl has no daemon and no state file, because the live
// provider APIs are the state. Nothing here writes to disk.
func serveUI(ctx context.Context, runner *engine.Engine, addr string, openBrowser bool, stdout io.Writer) error {
	// Port 0 lets the kernel choose, so two instances cannot collide and the
	// port is not guessable by something scanning a fixed one.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = listener.Close() }()

	token, err := newToken()
	if err != nil {
		return err
	}

	host := listener.Addr().String()
	handler, err := ui.New(ui.Deps{
		Token:   token,
		Host:    host,
		Planner: runner,
		Audit: func(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report {
			return audit.Run(ctx, d, desired, audit.NetResolver(), audit.HTTPFetcher())
		},
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://%s/?token=%s", host, token)
	// The token is in the URL the operator needs, so this line is the one place
	// it is printed. It authenticates a browser to this process and is not a
	// provider credential.
	fmt.Fprintf(stdout, "mailctl ui listening on %s\n", url)
	fmt.Fprintln(stdout, "press Ctrl-C to stop")

	if openBrowser {
		// A browser that will not open is not a reason to fail: the URL is
		// already printed above.
		_ = browse(url)
	}

	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate ui token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func browse(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
```

- [ ] **Step 4: Wire the command**

Add `"ui"` to the command switch at `main.go:208`, declare its two flags beside
the existing flag declarations, and branch to `serveUI` where `audit` branches:

```go
	uiAddr := flags.String("addr", "127.0.0.1:0",
		"address for the ui to listen on; port 0 lets the kernel choose")
	uiNoBrowser := flags.Bool("no-browser", false, "do not open a browser")
```

```go
	if command == "ui" {
		return serveUI(ctx, runner, *uiAddr, !*uiNoBrowser, stdout)
	}
```

Add both flags to `rejectScopedFlags` for every other command, and add a `ui`
entry to the usage text next to `plan`, `apply` and `audit`.

The 10-minute context timeout at `main.go:279` is wrong for a server the operator
leaves open. Give `ui` a context that is cancelled by interrupt instead of by
timeout, and leave every other command's timeout exactly as it is.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -count=1 ./cmd/mailctl/`
Expected: PASS

- [ ] **Step 6: Verify it actually serves**

```bash
go build -o /tmp/mailctl ./cmd/mailctl
/tmp/mailctl ui -no-browser -config <a config with one domain> &
```

Take the printed URL and confirm three things, then stop the server:
- `curl -sS -o /dev/null -w '%{http_code}' "$URL"` prints `200`
- `curl -sS -o /dev/null -w '%{http_code}' "http://$HOST/api/domains"` prints
  `403` — no token
- `curl -sS -H "X-Mailctl-Token: $TOKEN" "http://$HOST/api/domains"` returns the
  domain list

- [ ] **Step 7: Commit**

```bash
git add cmd/mailctl/ui.go cmd/mailctl/main.go cmd/mailctl/main_test.go
git commit -m "feat(cli): add the ui command"
```

---

### Task 10: The viewer frontend

**Files:**
- Create: `web/src/api.ts`, `web/src/stores/domains.ts`
- Create: `web/src/components/DomainList.vue`, `web/src/components/ActionList.vue`
- Modify: `web/src/App.vue`
- Create: `web/src/stores/domains.spec.ts`
- Modify: `internal/ui/dist/**` (rebuilt output)

**Interfaces:**
- Consumes: `GET /api/domains` → `{domains: [{name, zone, providers}]}`;
  `POST /api/plan` → `{schemaVersion, actions: [{id, op, resource, domain,
  provider, detail, manual}]}`; `POST /api/audit` → `{reports: [{domain, ok,
  checks: [{name, want, got, ok}], notes, error?}]}`.
- Produces: nothing consumed by Go.

- [ ] **Step 1: Write the failing store test**

```ts
import { setActivePinia, createPinia } from 'pinia'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useDomainsStore } from './domains'

describe('domains store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('loads domains without requesting a plan', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ domains: [{ name: 'example.com', zone: 'example.com', providers: ['purelymail'] }] }),
    })
    vi.stubGlobal('fetch', fetchMock)

    const store = useDomainsStore()
    await store.loadDomains()

    expect(store.domains).toHaveLength(1)
    // Provider calls cost latency and rate limit, so nothing may plan on load.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0][0]).toContain('/api/domains')
  })

  it('groups plan actions by domain', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schemaVersion: 1,
        actions: [
          { id: '0', op: 'CREATE', resource: 'dns', domain: 'a.example', detail: 'MX', manual: false },
          { id: '1', op: 'CREATE', resource: 'dns', domain: 'b.example', detail: 'MX', manual: false },
          { id: '2', op: 'MANUAL', resource: 'dkim', domain: 'a.example', detail: 'read the portal', manual: true },
        ],
      }),
    }))

    const store = useDomainsStore()
    await store.runPlan()

    expect(store.actionsFor('a.example')).toHaveLength(2)
    expect(store.actionsFor('b.example')).toHaveLength(1)
  })

  it('treats a domain with only manual actions as converged', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        schemaVersion: 1,
        actions: [{ id: '0', op: 'MANUAL', resource: 'dkim', domain: 'a.example', detail: 'read the portal', manual: true }],
      }),
    }))

    const store = useDomainsStore()
    await store.runPlan()

    // A manual action renders but is never executed, so a plan containing only
    // manual actions has converged as far as mailctl is concerned.
    expect(store.isConverged('a.example')).toBe(true)
  })

  it('surfaces an error without discarding what loaded', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      json: async () => ({ error: 'Cloudflare GET /zones: 403' }),
    }))

    const store = useDomainsStore()
    await store.runPlan()

    expect(store.error).toContain('403')
  })
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run web/src/stores/domains.spec.ts`
Expected: FAIL — the store does not exist.

- [ ] **Step 3: Write the API client**

```ts
// web/src/api.ts
// The token arrives in the launch URL and is kept in memory only. It is not put
// in localStorage: it dies with the server process, so persisting it would only
// leave a stale value behind.
const token = new URLSearchParams(window.location.search).get('token') ?? ''

async function request<T>(path: string, method: 'GET' | 'POST'): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: { 'X-Mailctl-Token': token },
  })
  const body = await response.json()
  if (!response.ok) {
    throw new Error(body?.error ?? `${method} ${path} failed with ${response.status}`)
  }
  return body as T
}

export interface Domain { name: string; zone: string; providers: string[] }
export interface Action {
  id: string; op: 'CREATE' | 'UPDATE' | 'DELETE' | 'MANUAL'
  resource: string; domain: string; provider?: string; detail: string; manual: boolean
}
export interface Check { name: string; want: string; got: string; ok: boolean }
export interface Report {
  domain: string; ok: boolean; checks: Check[]; notes: string[]; error?: string
}

export const api = {
  domains: () => request<{ domains: Domain[] }>('/api/domains', 'GET'),
  plan: () => request<{ schemaVersion: number; actions: Action[] }>('/api/plan', 'POST'),
  audit: () => request<{ reports: Report[] }>('/api/audit', 'POST'),
}
```

- [ ] **Step 4: Write the store**

```ts
// web/src/stores/domains.ts
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, type Action, type Domain, type Report } from '../api'

export const useDomainsStore = defineStore('domains', () => {
  const domains = ref<Domain[]>([])
  const actions = ref<Action[]>([])
  const reports = ref<Report[]>([])
  const error = ref('')
  const planning = ref(false)
  const auditing = ref(false)

  async function loadDomains() {
    try {
      domains.value = (await api.domains()).domains
    } catch (e) {
      error.value = (e as Error).message
    }
  }

  async function runPlan() {
    planning.value = true
    error.value = ''
    try {
      actions.value = (await api.plan()).actions
    } catch (e) {
      // Keep whatever already loaded: a failed refresh should not blank the view.
      error.value = (e as Error).message
    } finally {
      planning.value = false
    }
  }

  async function runAudit() {
    auditing.value = true
    error.value = ''
    try {
      reports.value = (await api.audit()).reports
    } catch (e) {
      error.value = (e as Error).message
    } finally {
      auditing.value = false
    }
  }

  const actionsFor = (domain: string) => actions.value.filter((a) => a.domain === domain)

  // A manual action renders but is never executed, so it does not make a domain
  // unconverged — otherwise a domain with DKIM taken from config would look
  // permanently pending.
  const isConverged = (domain: string) => actionsFor(domain).every((a) => a.manual)

  const reportFor = (domain: string) => reports.value.find((r) => r.domain === domain)

  return {
    domains, actions, reports, error, planning, auditing,
    loadDomains, runPlan, runAudit, actionsFor, isConverged, reportFor,
  }
})
```

- [ ] **Step 5: Write the components**

`App.vue` loads the domain list on mount — that call reaches no provider — and
offers explicit "Plan" and "Audit" buttons. `DomainList.vue` renders one row per
domain with its converged state and expands to `ActionList.vue` plus the audit
checks. Keep both components under about 80 lines; if one grows past that, split
the row into its own component.

- [ ] **Step 6: Run the tests and build**

Run: `npx vitest run` — expected PASS
Run: `npm run ui:build` — expected: `internal/ui/dist/` updated
Run: `go test -count=1 ./internal/ui/` — expected PASS, the embedded shell still
serves

- [ ] **Step 7: Commit**

```bash
git add web/ internal/ui/dist/
git commit -m "feat(ui): add the read-only plan and audit viewer"
```

---

### Task 11: Theme, matching the docs site

**Files:**
- Create: `web/src/styles/tokens.css`
- Modify: `web/src/App.vue` to import it
- Modify: `internal/ui/dist/**` (rebuilt)

**Interfaces:** none.

- [ ] **Step 1: Copy the token layer**

Take the `:root` and `:root[data-theme="light"]` custom-property blocks from
`docs/supplemental-ui/css/zoolcoder.css` — colours, fonts, radii, easing — into
`web/src/styles/tokens.css`. Copy the values, not the Antora-specific rules.
Those light-mode values were chosen by measurement: the light accent is
`#0a6b60` because the brand teal fails WCAG AA on the sidebar's tinted
background, and `--zc-text-faint` is `#64748b` for the same reason. Do not
"tidy" them to rounder numbers.

- [ ] **Step 2: Respect the system theme**

Default from `prefers-color-scheme`, and allow an explicit override with
`data-theme` on the root element, so the UI matches the docs site's behaviour.

- [ ] **Step 3: Verify contrast rather than assuming it**

With the UI running, check every text colour against its composited background at
both themes. Two traps, both of which have already produced wrong conclusions in
this repo:

- Chrome reports modern colours as `color(srgb 1 1 1 / 0.78)` and `oklab(...)`.
  A regex parser reads those 0-1 components as `rgb(1,1,1)`, near-black, and
  invents failures. Read true bytes by filling a 1×1 canvas and reading the
  pixel back.
- Changing the theme and reading computed styles in the same evaluation returns
  stale values for `color`. Reload with the theme already set, or measure in a
  separate step.

Every text element must reach 4.5:1, or 3:1 where it is at least 24px, or at
least 18.66px and bold.

- [ ] **Step 4: Commit**

```bash
git add web/src/styles/tokens.css web/src/App.vue internal/ui/dist/
git commit -m "style(ui): adopt the docs design tokens with light and dark"
```

---

### Task 12: CI and the import boundary

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `.golangci.yml`

**Interfaces:** none.

- [ ] **Step 1: Add the bundle freshness check**

The committed bundle exists so `go install` works, and its failure mode is
silent drift from source. Add a step that rebuilds it and fails if the result
differs, mirroring the existing `go.mod` tidiness check:

```yaml
      - uses: actions/setup-node@v7
        with:
          node-version: '22'
          cache: npm

      - name: install the frontend toolchain
        run: npm ci

      - name: frontend tests
        run: npx vitest run

      # The committed bundle exists so `go install` works without npm. If it can
      # drift from source, it will, and the drift would ship.
      - name: verify the committed ui bundle is current
        run: |
          npm run ui:build
          if ! git diff --quiet -- internal/ui/dist; then
            echo "::error::internal/ui/dist is stale; run 'npm run ui:build' and commit the result"
            git diff --stat -- internal/ui/dist
            exit 1
          fi
```

- [ ] **Step 2: Add the depguard rule**

In `.golangci.yml`, under `linters.settings.depguard.rules`:

```yaml
        # The UI reaches providers only through the engine. A handler that talked
        # to a provider directly would duplicate the engine's ordering and safety
        # decisions, and the two would drift apart.
        ui-goes-through-the-engine:
          files:
            - '**/internal/ui/*.go'
          deny:
            - pkg: github.com/zoolcoder/mailctl/internal/mail/ms365
              desc: use the engine, not a provider
            - pkg: github.com/zoolcoder/mailctl/internal/mail/purelymail
              desc: use the engine, not a provider
            - pkg: github.com/zoolcoder/mailctl/internal/mail/cfrouting
              desc: use the engine, not a provider
            - pkg: github.com/zoolcoder/mailctl/internal/mail/cfsending
              desc: use the engine, not a provider
```

- [ ] **Step 3: Verify locally**

```bash
npm run ui:build && git diff --quiet -- internal/ui/dist && echo "bundle current"
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2 run ./...
go test -count=1 ./... && go test -count=1 -race ./...
```

Expected: bundle current, lint reports nothing, every package passes twice.

- [ ] **Step 4: Confirm the dependency count did not change**

```bash
go list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all | tail -n +2 | grep -v '^$'
```

Expected: exactly `gopkg.in/yaml.v3`. If anything else appears, a Go dependency
has been added and the design has been violated.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml .golangci.yml
git commit -m "ci: check the ui bundle is current and guard its imports"
```

---

### Task 13: Documentation

**Files:**
- Modify: `docs/modules/ROOT/pages/commands.adoc` — a `ui` section
- Modify: `docs/modules/ROOT/pages/index.adoc` — mention the UI where commands
  are introduced
- Modify: `README.md`
- Modify: `CHANGELOG.md` under `## Unreleased`
- Modify: `ROADMAP.md`
- Modify: `CONTRIBUTING.md` — the frontend build and the committed-bundle rule

**Interfaces:** none.

- [ ] **Step 1: Document the command**

Cover, in `commands.adoc`: what `mailctl ui` shows, that it is read-only in this
release, that it reads credentials from the environment exactly as the CLI does
and has no login, that it binds `127.0.0.1` on a kernel-chosen port with a
per-process token, that it writes nothing to disk, and that it stops on Ctrl-C.
Document `-addr` and `-no-browser`. Document `plan -json` in the `plan` section
with a worked `jq` example.

- [ ] **Step 2: Update the roadmap**

`ROADMAP.md` currently lists "Machine-readable plan output" under **Later** with
no indication it is now a dependency of planned work. Move it to done-by-this-work
and add the UI's remaining phases — config authoring, then apply — with a pointer
to the design doc. Keep the section's stated discipline: what is unfinished, why
it matters, and what makes it hard.

- [ ] **Step 3: Document the bundle rule for contributors**

In `CONTRIBUTING.md`, state that `internal/ui/dist` is generated, must never be
hand-edited, is rebuilt with `npm run ui:build`, must be committed with the
change that alters it, and that CI fails when it is stale.

- [ ] **Step 4: Build the docs with warnings as errors**

```bash
npx antora antora-playbook.yml 2>&1 | tee /tmp/docs.log
grep '"level":"warn"' /tmp/docs.log && echo "FIX THE WARNINGS" || echo "docs clean"
```

Expected: no warnings. A warning fails the docs workflow.

- [ ] **Step 5: Commit**

```bash
git add docs/ README.md CHANGELOG.md ROADMAP.md CONTRIBUTING.md
git commit -m "docs: document the ui command and plan -json"
```

---

## Self-Review

**Spec coverage.** Every requirement maps to a task: the foreground command and
its lifecycle (9), token with `Origin`/`Host` checks and tested rejections (6),
credentials from the environment with no login form (9, and asserted by the
absence of any credential endpoint in 7–8), one JSON projection with two
consumers (1–3), `Do` excluded and proven absent (1), live reads only on explicit
request (8's GET refusal and 7's provider-free domains endpoint), committed bundle
with a freshness check (4, 12), no provider imports from `internal/ui` (12),
Quasar avoided and docs tokens reused (10, 11), golden-file schema tests (1, 2),
and the endpoint table (7, 8).

**One spec item deliberately deferred:** the spec's "a test asserting no
credential-bearing value appears in what the server logs" has no task, because
this phase adds no request logging at all — there is nothing to assert against.
If logging is added in a later phase, that test is a precondition of adding it,
and Task 13 records that the UI logs nothing.

**Type consistency.** `planjson.Plan`/`Action`/`Report`/`Check` and `FromPlan`/
`FromReport` are named identically in Tasks 1, 2, 3, 8. `ui.Deps` fields
(`Token`, `Host`, `Planner`, `Audit`) match between Tasks 7, 8 and 9. The
`Planner` interface methods match `*engine.Engine`'s real signatures —
`Domains() ([]config.Domain, error)`, `Plan(context.Context) (plan.Plan, error)`,
`Desired(context.Context, config.Domain) ([]dns.Record, error)`. The store's
`actionsFor`, `isConverged`, `reportFor`, `loadDomains`, `runPlan`, `runAudit`
match between the spec test and the implementation in Task 10.

**Known soft spots.** Task 10 Step 5 describes the two components rather than
giving their full source, because their markup is presentational and constraining
it adds nothing a reviewer would enforce; the store they consume is fully
specified and tested. Task 9 Step 4 says to extract the engine wiring "if
required" rather than prescribing a diff, because the exact shape depends on
`main.go`'s state when the task runs — the binding rule is stated instead: every
command must go through one helper, and none may copy it.
