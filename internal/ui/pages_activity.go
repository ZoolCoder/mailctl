package ui

// Activity: what this page did — plans, audits, desired records — newest first,
// from the JSONL file toolshell's activity package keeps.

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zoolcoder/toolshell"
	"github.com/zoolcoder/toolshell/activity"
)

type activityRow struct {
	activity.Entry
	Search string
}

type activityPage struct {
	chrome
	Kind  string
	Kinds []string
	Limit int
	Rows  []activityRow
	// Runs and Mix chart every recorded row, whatever the filter shows.
	Runs runChart
	Mix  shares
}

// chartDays is how far back the activity charts reach.
const chartDays = 14

// runChart is recorded activity a column a day, ok stacked under failed,
// with the totals the page states in words.
type runChart struct {
	Days       []toolshell.Column
	OK, Failed int
}

// Total is every run the chart covers.
func (c runChart) Total() int { return c.OK + c.Failed }

// SuccessPct is the share of runs that went through, 0 with none.
func (c runChart) SuccessPct() int {
	if c.Total() == 0 {
		return 0
	}
	return c.OK * 100 / c.Total()
}

// dailyRuns buckets rows into the days days up to now, oldest first, each
// labelled with its day of the month.
func dailyRuns(rows []activityRow, now time.Time, days int) runChart {
	var c runChart
	today := now.Local()
	start := time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, today.Location()).AddDate(0, 0, 1-days)
	c.Days = make([]toolshell.Column, days)
	for i := range c.Days {
		c.Days[i] = toolshell.Column{Label: fmt.Sprint(start.AddDate(0, 0, i).Day()), Values: []int{0, 0}}
	}
	for _, row := range rows {
		at := row.At.Local()
		if at.Before(start) || at.After(now) {
			continue
		}
		i := int(time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, at.Location()).Sub(start).Hours()+12) / 24
		if i < 0 || i >= days {
			continue
		}
		if row.OK {
			c.Days[i].Values[0]++
			c.OK++
		} else {
			c.Days[i].Values[1]++
			c.Failed++
		}
	}
	return c
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
		rows = append(rows, activityRow{Entry: a, Search: strings.ToLower(a.Kind + " " + a.Target + " " + a.Detail)})
	}
	return rows
}

func (s *Server) activity(w http.ResponseWriter, r *http.Request) {
	p := activityPage{chrome: s.chrome(r, "activity"), Kind: r.URL.Query().Get("kind"),
		Kinds: []string{"plan", "audit", "desired"}, Limit: activityLimit}
	all := s.recentActivity(activityLimit)
	kinds := map[string]int{}
	for _, row := range all {
		kinds[row.Kind]++
		if p.Kind != "" && row.Kind != p.Kind {
			continue
		}
		p.Rows = append(p.Rows, row)
	}
	p.Runs = dailyRuns(all, s.deps.Now(), chartDays)
	for i, kind := range p.Kinds {
		p.Mix = append(p.Mix, share{Name: p.T(kind), Tone: []string{"acc", "man", "p-amber"}[i], N: kinds[kind]})
	}
	s.render(w, "activity.html", p)
}
