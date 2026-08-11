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
