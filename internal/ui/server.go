// Package ui serves the local read-only view of mailctl's plan and audit
// results. It reaches providers only through the engine: duplicating the
// engine's ordering and safety logic behind an HTTP handler is how the two would
// come to disagree.
package ui

import (
	"context"
	"errors"
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

// New wires the routes and returns the guarded handler. It validates deps
// itself rather than letting newAuth's panic stand in for input validation:
// newAuth panics on an empty token deliberately, as a backstop against a
// programming error, but a caller-supplied Deps is user input to this
// package's public door and must fail with an error, not a crash.
func New(deps Deps) (http.Handler, error) {
	if deps.Token == "" {
		return nil, errors.New("ui: Token must not be empty")
	}
	if deps.Host == "" {
		return nil, errors.New("ui: Host must not be empty")
	}
	if deps.Planner == nil {
		return nil, errors.New("ui: Planner must not be nil")
	}
	if deps.Audit == nil {
		return nil, errors.New("ui: Audit must not be nil")
	}

	static, err := assetHandler()
	if err != nil {
		return nil, err
	}
	s := &server{deps: deps}

	api := http.NewServeMux()
	api.HandleFunc("GET /api/domains", s.handleDomains)
	api.HandleFunc("POST /api/plan", s.handlePlan)
	api.HandleFunc("POST /api/audit", s.handleAudit)
	// Everything under /api/ that did not match above ends here rather than at
	// the SPA fallback. This is not defensive tidying: it was measured. With a
	// "/" catch-all registered, ServeMux does NOT answer 405 for a
	// method-pattern mismatch — `GET /api/plan` falls through to "/" and returns
	// the HTML shell with 200. A client would then parse a page as JSON, and the
	// GET-refusal test below would pass against a route that quietly served HTML.
	api.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Only /api/* reaches a credential — the operator's Cloudflare token, via
	// the engine behind Planner — so only /api/* gets the full token guard.
	// The static bundle gets Host and Origin only: see newHostOriginGuard for
	// why the token cannot be required there, and would buy nothing if it
	// could be.
	mux := http.NewServeMux()
	mux.Handle("/api/", newAuth(deps.Token, deps.Host)(api))
	mux.Handle("/", newHostOriginGuard(deps.Host)(static))

	return mux, nil
}

type server struct{ deps Deps }
