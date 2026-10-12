package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/planjson"
)

// printDomains shows the resolved config of the domains in scope, all of them
// when -domain was not given. It names credential variables, never values.
func printDomains(cfg config.Config, scope domainList, asJSON bool, stdout io.Writer) error {
	var selected []config.Domain
	for _, d := range cfg.Domains {
		if len(scope) == 0 || slices.Contains(scope, d.Name) {
			selected = append(selected, d)
		}
	}
	view := planjson.FromDomains(selected)
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(view)
	}
	for _, d := range view.Domains {
		fmt.Fprintf(stdout, "%s  zone %s  provider %s\n", d.Name, d.Zone, strings.Join(d.Providers, ", "))
		for _, m := range d.Mailboxes {
			fmt.Fprintf(stdout, "  mailbox  %s\n", m.Address)
		}
		for _, a := range d.Aliases {
			fmt.Fprintf(stdout, "  alias    %s -> %s\n", a.Match, strings.Join(a.To, ", "))
		}
		if d.CatchAll != nil {
			fmt.Fprintf(stdout, "  catch-all -> %s\n", strings.Join(d.CatchAll.To, ", "))
		}
	}
	return nil
}

// requireSamePlan refuses to apply when the plan built now is not the plan
// that was saved and reviewed. Comparing projections, not raw bytes, keeps the
// check about intent: indentation or a newer reader cannot cause a refusal.
func requireSamePlan(path string, built plan.Plan) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read saved plan: %w", err)
	}
	var saved planjson.Plan
	if err := json.Unmarshal(raw, &saved); err != nil {
		return fmt.Errorf("saved plan %s is not mailctl plan -json output: %w", path, err)
	}
	if saved.SchemaVersion != planjson.SchemaVersion {
		return fmt.Errorf("saved plan %s has schema version %d, want %d", path, saved.SchemaVersion, planjson.SchemaVersion)
	}
	current := planjson.FromPlan(built)
	if !slices.Equal(saved.Actions, current.Actions) {
		return errors.New("live state drifted since the plan was saved: run `mailctl plan -json` again and review it")
	}
	return nil
}
