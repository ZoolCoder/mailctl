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

// handlePlan and handleAudit are wired here so the mux registration in New
// compiles; Task 8 replaces these bodies with the real projection.
func (s *server) handlePlan(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
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
