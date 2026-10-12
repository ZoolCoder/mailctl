package keychain

import "testing"

// Set builds a command line for `security -i`; a quote or newline in either
// argument would end the quoted value and let the rest run as a command.
func TestSetRejectsValuesThatWouldBreakTheCommandLine(t *testing.T) {
	for _, bad := range []string{`a"b`, `a\b`, "a\nb"} {
		if err := Set("account", bad); err == nil {
			t.Errorf("Set accepted value %q", bad)
		}
		if err := Set(bad, "value"); err == nil {
			t.Errorf("Set accepted account %q", bad)
		}
	}
}
