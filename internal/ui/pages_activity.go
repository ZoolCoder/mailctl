package ui

// Activity: what this page did — plans, audits, sign-ins — newest first,
// from the JSONL file zcadmin keeps.

import (
	"net/http"
	"strings"

	"github.com/zoolcoder/zcadmin"
)

type activityRow struct {
	zcadmin.Activity
	When   string
	Search string
}

type activityPage struct {
	chrome
	Kind  string
	Kinds []string
	Limit int
	Rows  []activityRow
}

func (s *Server) recentActivity(limit int) []activityRow {
	if s.deps.Activity == nil {
		return nil
	}
	acts, err := s.deps.Activity.Recent(limit)
	if err != nil {
		return nil
	}
	rows := make([]activityRow, 0, len(acts))
	for _, a := range acts {
		rows = append(rows, activityRow{Activity: a, When: ago(a.At, s.deps.Now()),
			Search: strings.ToLower(a.Kind + " " + a.Target + " " + a.Detail)})
	}
	return rows
}

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	p := activityPage{chrome: s.chrome(r, "activity"), Kind: r.URL.Query().Get("kind"),
		Kinds: []string{"plan", "audit", "desired", "auth"}, Limit: activityLimit}
	for _, row := range s.recentActivity(activityLimit) {
		if p.Kind != "" && row.Kind != p.Kind {
			continue
		}
		row.When = row.At.Local().Format("2006-01-02 15:04:05")
		p.Rows = append(p.Rows, row)
	}
	s.render(w, "activity.html", p)
}
