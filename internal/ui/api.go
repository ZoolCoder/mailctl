package ui

import (
	"encoding/json"
	"net/http"

	"github.com/zoolcoder/mailctl/internal/planjson"
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
