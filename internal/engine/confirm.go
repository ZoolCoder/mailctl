package engine

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/plan"
)

// Confirm blocks until the operator retypes the affected domain names. It
// returns immediately when the plan deletes nothing. Mailbox deletion destroys
// stored mail irreversibly, so every object is named individually rather than
// summarised as a count.
func Confirm(in io.Reader, out io.Writer, p plan.Plan) error {
	deletions := p.Destructive()
	if len(deletions) == 0 {
		return nil
	}

	domains := map[string]bool{}
	fmt.Fprintf(out, "\nThe following %d changes delete data:\n", len(deletions))
	for _, action := range deletions {
		fmt.Fprintf(out, "  %s %s: %s\n", action.Domain, action.Resource, action.Detail)
		domains[strings.ToLower(action.Domain)] = true
	}

	expected := sortedSet(domains)
	fmt.Fprintf(out, "\nType %s to continue, anything else to abort: ", expected)

	reader := bufio.NewReader(in)
	answer, err := reader.ReadString('\n')
	// Reject any read error, including EOF or incomplete input without a trailing newline.
	// The interactive path always sends a newline; automation should use -yes instead of
	// piping the domain list.
	if err != nil {
		return fmt.Errorf("aborted: confirmation was not read as a complete line (%w)", err)
	}

	if normaliseDomainList(answer) != expected {
		return fmt.Errorf("aborted: expected %q", expected)
	}
	return nil
}

func sortedSet(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// normaliseDomainList lowercases, trims, and re-joins a comma-separated answer
// so spacing and case do not decide the outcome. Order still matters, and the
// prompt shows the expected order.
func normaliseDomainList(answer string) string {
	parts := strings.Split(strings.TrimSpace(answer), ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, ",")
}
