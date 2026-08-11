package secret

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
)

func TestPasswordPrefersEnvVar(t *testing.T) {
	r := NewResolver(func(name string) string {
		if name == "BOX_PW" {
			return "from-env"
		}
		return ""
	})

	got, err := r.Password("a.com", config.Mailbox{Address: "box@a.com", PasswordEnv: "BOX_PW"})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if got != "from-env" {
		t.Errorf("secret = %q, want from-env", got)
	}
	if len(r.Generated()) != 0 {
		t.Errorf("nothing should be reported as generated; got %v", r.Generated())
	}
}

func TestPasswordFailsWhenNamedEnvVarIsEmpty(t *testing.T) {
	r := NewResolver(func(string) string { return "" })

	_, err := r.Password("a.com", config.Mailbox{Address: "box@a.com", PasswordEnv: "BOX_PW"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "BOX_PW") || !strings.Contains(err.Error(), "box@a.com") {
		t.Errorf("error should name the variable and the mailbox; got %q", err)
	}
}

func TestPasswordGeneratesWhenNoEnvVarConfigured(t *testing.T) {
	r := NewResolver(func(string) string { return "" })

	got, err := r.Password("a.com", config.Mailbox{Address: "box@a.com"})
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if len(got) != GeneratedLength {
		t.Errorf("generated length = %d, want %d", len(got), GeneratedLength)
	}
	if r.Generated()["box@a.com"] != got {
		t.Errorf("generated value should be recorded for later reporting")
	}
}

func TestPasswordIsStableAcrossCallsForOneMailbox(t *testing.T) {
	r := NewResolver(func(string) string { return "" })
	m := config.Mailbox{Address: "box@a.com"}

	first, _ := r.Password("a.com", m)
	second, _ := r.Password("a.com", m)
	if first != second {
		t.Error("plan and apply must resolve the same mailbox to the same value")
	}
}

func TestGenerateProducesDistinctValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		value, err := Generate(GeneratedLength)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[value] {
			t.Fatalf("Generate returned a duplicate: %q", value)
		}
		seen[value] = true
	}
}

func TestWriteFileIsOwnerReadableOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.secrets")

	if err := WriteFile(path, map[string]string{"box@a.com": "value-1"}); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
	body, _ := os.ReadFile(path)
	if !strings.Contains(string(body), "box@a.com") || !strings.Contains(string(body), "value-1") {
		t.Errorf("file should contain the address and its value; got %q", body)
	}
}

func TestReportToWritesNothingWhenNothingGenerated(t *testing.T) {
	var out strings.Builder
	if err := ReportTo(&out, nil); err != nil {
		t.Fatalf("ReportTo: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output; got %q", out.String())
	}
}

// TestWriteFileRefusesAnExistingFile is the regression guard for finding I4:
// WriteFile previously opened with O_TRUNC and then chmod'd whatever was
// already at path, so -secrets-out pointed at, say, mailctl.yaml would
// silently overwrite the config with a credential and chmod it 0600. O_EXCL
// must refuse the write outright and name the path, leaving the existing file
// untouched.
func TestWriteFileRefusesAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.secrets")
	const original = "do not touch"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	err := WriteFile(path, map[string]string{"box@a.com": "new-value"})
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want an error naming %s", err, path)
	}
	if !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "will not overwrite") {
		t.Fatalf("err = %v, want guidance that the file exists and will not be overwritten", err)
	}

	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(body) != original {
		t.Errorf("existing file was modified; got %q, want %q", body, original)
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("stat: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("existing file's mode was changed: got %o, want unchanged 644", got)
	}
}

// TestWriteFileRefusesASymlink guards against the variant of I4 where path
// exists as a symlink rather than a plain file: O_EXCL must refuse to follow
// it and overwrite whatever it points at.
func TestWriteFileRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yaml")
	const original = "do not touch"
	if err := os.WriteFile(target, []byte(original), 0o644); err != nil {
		t.Fatalf("setup: write target: %v", err)
	}
	link := filepath.Join(dir, "out.secrets")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("setup: symlink: %v", err)
	}

	err := WriteFile(link, map[string]string{"box@a.com": "new-value"})
	if err == nil || !strings.Contains(err.Error(), link) {
		t.Fatalf("err = %v, want an error naming %s", err, link)
	}
	if !strings.Contains(err.Error(), "already exists") || !strings.Contains(err.Error(), "will not overwrite") {
		t.Fatalf("err = %v, want guidance that the file exists and will not be overwritten", err)
	}

	body, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(body) != original {
		t.Errorf("symlink target was modified; got %q, want %q", body, original)
	}
}

func TestStdoutStaysClean(t *testing.T) {
	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	oldStdout := os.Stdout
	os.Stdout = w

	// Call ReportTo on stderr and WriteFile
	generated := map[string]string{"box@a.com": "value-1"}
	path := filepath.Join(t.TempDir(), "out.secrets")

	var stderr strings.Builder
	_ = ReportTo(&stderr, generated)
	_ = WriteFile(path, generated)

	// Restore stdout and close the write end
	os.Stdout = oldStdout
	_ = w.Close()

	// Read whatever was written to stdout
	out, _ := io.ReadAll(r)

	if len(out) != 0 {
		t.Errorf("stdout should be clean; got %q", out)
	}
}

func TestGenerateProducesOnlyAlphabetCharacters(t *testing.T) {
	alphabetSet := make(map[rune]bool)
	for _, ch := range alphabet {
		alphabetSet[ch] = true
	}

	value, err := Generate(GeneratedLength)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	for _, ch := range value {
		if !alphabetSet[ch] {
			t.Errorf("character %q not in alphabet", ch)
		}
	}
}

func TestReportToWithNonEmptyOutput(t *testing.T) {
	var out strings.Builder
	generated := map[string]string{
		"box@a.com": "secret-1",
		"box@b.com": "secret-2",
	}

	if err := ReportTo(&out, generated); err != nil {
		t.Fatalf("ReportTo: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "box@a.com") {
		t.Error("output missing first address")
	}
	if !strings.Contains(output, "box@b.com") {
		t.Error("output missing second address")
	}
	if !strings.Contains(output, "secret-1") {
		t.Error("output missing first value")
	}
	if !strings.Contains(output, "secret-2") {
		t.Error("output missing second value")
	}
	if !strings.Contains(output, "GENERATED CREDENTIALS") {
		t.Error("output missing banner text")
	}

	// Verify the rule line (delimiter) appears both above and below credentials
	rule := "======================================================================"
	ruleCount := strings.Count(output, rule)
	if ruleCount < 2 {
		t.Errorf("rule line should appear twice (above and below); got %d occurrences", ruleCount)
	}

	// Verify addresses appear in sorted order
	idxA := strings.Index(output, "box@a.com")
	idxB := strings.Index(output, "box@b.com")
	if idxA == -1 || idxB == -1 || idxA >= idxB {
		t.Error("addresses should appear in sorted order")
	}
}

func TestAppliedIsEmptyUntilMarked(t *testing.T) {
	r := NewResolver(func(string) string { return "" })
	m := config.Mailbox{Address: "box@a.com"}

	if _, err := r.Password("a.com", m); err != nil {
		t.Fatalf("Password: %v", err)
	}
	if len(r.Applied()) != 0 {
		t.Errorf("Applied() = %v, want none; nothing was marked applied yet", r.Applied())
	}
}

func TestMarkAppliedReportsOnlyMarkedAddress(t *testing.T) {
	r := NewResolver(func(string) string { return "" })
	m := config.Mailbox{Address: "box@a.com"}

	value, err := r.Password("a.com", m)
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	r.MarkApplied("box@a.com")

	applied := r.Applied()
	if len(applied) != 1 || applied["box@a.com"] != value {
		t.Errorf("Applied() = %v, want only box@a.com = %q", applied, value)
	}
}

func TestMarkAppliedIgnoresAddressNotGenerated(t *testing.T) {
	r := NewResolver(func(name string) string {
		if name == "BOX_PW" {
			return "from-env"
		}
		return ""
	})
	m := config.Mailbox{Address: "box@a.com", PasswordEnv: "BOX_PW"}

	if _, err := r.Password("a.com", m); err != nil {
		t.Fatalf("Password: %v", err)
	}
	// An env-sourced credential was never generated, so marking it applied
	// must not make it reportable: only generated credentials are worth
	// reporting.
	r.MarkApplied("box@a.com")

	if len(r.Applied()) != 0 {
		t.Errorf("Applied() = %v, want none; box@a.com's credential came from the environment", r.Applied())
	}
}

func TestGeneratedReturnsCopy(t *testing.T) {
	r := NewResolver(func(string) string { return "" })
	m := config.Mailbox{Address: "box@a.com"}

	// Generate a value
	_, _ = r.Password("a.com", m)

	// Get the generated map and mutate it
	first := r.Generated()
	first["box@new.com"] = "new-value"
	delete(first, "box@a.com")

	// Get the generated map again
	second := r.Generated()

	// The second result should be unaffected by the mutations
	if _, ok := second["box@a.com"]; !ok {
		t.Error("internal generated map was mutated")
	}
	if _, ok := second["box@new.com"]; ok {
		t.Error("internal generated map should not have the added key")
	}
}
