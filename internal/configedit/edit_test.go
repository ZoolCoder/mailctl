package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"gopkg.in/yaml.v3"
)

const startingConfig = `version: 1

domains:
  # our main domain
  - name: a.com
    mail:
      provider: purelymail
    mailboxes:
      - address: contact@a.com
        passwordEnv: CONTACT_PW
`

func write(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(startingConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(body)
}

func TestAddMailboxPreservesComments(t *testing.T) {
	path := write(t)

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}

	got := read(t, path)
	if !strings.Contains(got, "# our main domain") {
		t.Errorf("comments must survive an edit:\n%s", got)
	}
	if !strings.Contains(got, "sales@a.com") || !strings.Contains(got, "SALES_PW") {
		t.Errorf("new mailbox missing:\n%s", got)
	}
	if !strings.Contains(got, "contact@a.com") {
		t.Errorf("existing mailbox must survive:\n%s", got)
	}
}

func TestAddMailboxRejectsADuplicate(t *testing.T) {
	path := write(t)

	err := AddMailbox(path, "a.com", "contact@a.com", "OTHER_PW")
	if err == nil || !strings.Contains(err.Error(), "contact@a.com") {
		t.Fatalf("err = %v, want a duplicate error naming the address", err)
	}
}

func TestAddMailboxRejectsAnUnknownDomain(t *testing.T) {
	path := write(t)

	err := AddMailbox(path, "b.com", "x@b.com", "PW")
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming the missing domain", err)
	}
}

func TestRemoveMailbox(t *testing.T) {
	path := write(t)

	if err := RemoveMailbox(path, "a.com", "contact@a.com"); err != nil {
		t.Fatalf("RemoveMailbox: %v", err)
	}
	if strings.Contains(read(t, path), "contact@a.com") {
		t.Errorf("mailbox should be gone:\n%s", read(t, path))
	}
}

func TestRemoveMailboxRejectsAMissingAddress(t *testing.T) {
	path := write(t)

	err := RemoveMailbox(path, "a.com", "nope@a.com")
	if err == nil || !strings.Contains(err.Error(), "nope@a.com") {
		t.Fatalf("err = %v, want an error naming the address", err)
	}
}

func TestAddAliasCreatesTheSectionWhenAbsent(t *testing.T) {
	path := write(t)

	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	got := read(t, path)
	if !strings.Contains(got, "aliases:") || !strings.Contains(got, "match: info") {
		t.Errorf("alias section missing:\n%s", got)
	}
}

func TestAddAliasRejectsADuplicate(t *testing.T) {
	path := write(t)
	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	err := AddAlias(path, "a.com", "info", []string{"contact@a.com"})
	if err == nil || !strings.Contains(err.Error(), "info") {
		t.Fatalf("err = %v, want a duplicate error naming info", err)
	}
}

func TestRemoveAliasRejectsAMissingMatch(t *testing.T) {
	path := write(t)
	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	err := RemoveAlias(path, "a.com", "nope")
	if err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("err = %v, want an error naming nope", err)
	}
}

func TestRemoveAlias(t *testing.T) {
	path := write(t)
	if err := AddAlias(path, "a.com", "info", []string{"contact@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	if err := RemoveAlias(path, "a.com", "info"); err != nil {
		t.Fatalf("RemoveAlias: %v", err)
	}
	if strings.Contains(read(t, path), "match: info") {
		t.Errorf("alias should be gone:\n%s", read(t, path))
	}
}

func TestEditsRoundTripThroughYAML(t *testing.T) {
	path := write(t)

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}
	if err := AddAlias(path, "a.com", "info", []string{"sales@a.com"}); err != nil {
		t.Fatalf("AddAlias: %v", err)
	}

	// The result must still be a config the loader accepts.
	if _, err := loadForTest(path); err != nil {
		t.Fatalf("edited config no longer loads: %v\n%s", err, read(t, path))
	}
}

func loadForTest(path string) (config.Config, error) {
	return config.Load(path, func(string) string { return "x" })
}

// bareMailboxesConfig has a mailboxes: key with no value at all, which
// yaml.v3 parses as a null scalar rather than an empty sequence. Appending to
// a null scalar's .Content used to be discarded silently by the encoder
// (finding C2); ensureSequence must replace it with a real sequence first.
const bareMailboxesConfig = `version: 1

domains:
  - name: a.com
    mail:
      provider: purelymail
    mailboxes:
`

func TestAddMailboxIntoABareMailboxesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(bareMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}

	got := read(t, path)
	if !strings.Contains(got, "sales@a.com") {
		t.Errorf("mailbox missing after add into a bare mailboxes key:\n%s", got)
	}
	if _, err := loadForTest(path); err != nil {
		t.Fatalf("edited config no longer loads: %v\n%s", err, got)
	}
}

func TestRemoveMailboxRefusesABareMailboxesKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(bareMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := RemoveMailbox(path, "a.com", "sales@a.com")
	if err == nil || !strings.Contains(err.Error(), "a.com") {
		t.Fatalf("err = %v, want an error naming a.com", err)
	}
}

// anchoredMailboxesConfig gives shared.com's mailboxes an anchor and has
// b.com alias it. The anchor must be defined before it is referenced, since
// yaml.v3 parses anchors and aliases in a single pass.
const anchoredMailboxesConfig = `version: 1

domains:
  - name: shared.com
    mail:
      provider: purelymail
    mailboxes: &sharedBoxes
      - address: keep@shared.com
  - name: b.com
    mail:
      provider: purelymail
    mailboxes: *sharedBoxes
`

func TestAddMailboxRefusesAnAliasedSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := AddMailbox(path, "b.com", "new@b.com", "PW")
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming b.com", err)
	}
	if strings.Contains(read(t, path), "new@b.com") {
		t.Errorf("an alias section must never be appended to")
	}
}

func TestRemoveMailboxRefusesAnAliasedSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := RemoveMailbox(path, "b.com", "keep@shared.com")
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming b.com", err)
	}
	if !strings.Contains(read(t, path), "keep@shared.com") {
		t.Errorf("an alias section must never be mutated")
	}
}

// TestAddMailboxRefusesAnAnchoredSection is the regression guard for finding
// I6: mutating an anchored sequence directly is YAML-correct but rewrites
// what every domain aliasing that anchor declares.
func TestAddMailboxRefusesAnAnchoredSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := AddMailbox(path, "shared.com", "new@shared.com", "PW")
	if err == nil || !strings.Contains(err.Error(), "shared.com") || !strings.Contains(err.Error(), "sharedBoxes") {
		t.Fatalf("err = %v, want an error naming shared.com and the sharedBoxes anchor", err)
	}
	if strings.Contains(read(t, path), "new@shared.com") {
		t.Errorf("an anchored section must never be appended to")
	}
}

func TestRemoveMailboxRefusesAnAnchoredSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredMailboxesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := RemoveMailbox(path, "shared.com", "keep@shared.com")
	if err == nil || !strings.Contains(err.Error(), "shared.com") || !strings.Contains(err.Error(), "sharedBoxes") {
		t.Fatalf("err = %v, want an error naming shared.com and the sharedBoxes anchor", err)
	}
	if !strings.Contains(read(t, path), "keep@shared.com") {
		t.Errorf("an anchored section must never be mutated")
	}
}

// anchoredAliasesConfig mirrors anchoredMailboxesConfig for the aliases key,
// confirming the same kind checks apply there.
const anchoredAliasesConfig = `version: 1

domains:
  - name: shared.com
    mail:
      provider: purelymail
    aliases: &sharedAliases
      - match: info
        to: [keep@shared.com]
  - name: b.com
    mail:
      provider: purelymail
    aliases: *sharedAliases
`

func TestAddAliasRefusesAnAliasedSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredAliasesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := AddAlias(path, "b.com", "sales", []string{"x@b.com"})
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming b.com", err)
	}
}

func TestRemoveAliasRefusesAnAliasedSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredAliasesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := RemoveAlias(path, "b.com", "info")
	if err == nil || !strings.Contains(err.Error(), "b.com") {
		t.Fatalf("err = %v, want an error naming b.com", err)
	}
}

func TestAddAliasRefusesAnAnchoredSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredAliasesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := AddAlias(path, "shared.com", "sales", []string{"x@shared.com"})
	if err == nil || !strings.Contains(err.Error(), "shared.com") || !strings.Contains(err.Error(), "sharedAliases") {
		t.Fatalf("err = %v, want an error naming shared.com and the sharedAliases anchor", err)
	}
}

func TestRemoveAliasRefusesAnAnchoredSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(anchoredAliasesConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := RemoveAlias(path, "shared.com", "info")
	if err == nil || !strings.Contains(err.Error(), "shared.com") || !strings.Contains(err.Error(), "sharedAliases") {
		t.Fatalf("err = %v, want an error naming shared.com and the sharedAliases anchor", err)
	}
}

// TestAddMailboxOnAMailboxlessProviderLeavesTheFileUnchanged is the
// regression guard for finding I1: a mutate that renders fine but produces a
// config that no longer loads must never reach the real file.
func TestAddMailboxOnAMailboxlessProviderLeavesTheFileUnchanged(t *testing.T) {
	const mailboxlessConfig = `version: 1

domains:
  - name: a.com
    mail:
      provider: cfrouting
`
	path := filepath.Join(t.TempDir(), "mailctl.yaml")
	if err := os.WriteFile(path, []byte(mailboxlessConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW")
	if err == nil || !strings.Contains(err.Error(), "a.com") {
		t.Fatalf("err = %v, want an error naming a.com", err)
	}

	if got := read(t, path); got != mailboxlessConfig {
		t.Errorf("a rejected edit must leave the file byte-identical:\n%s", got)
	}
}

// TestCommitPreservesFilePermissionsAndLeavesNoTempFile is the regression
// guard for finding I9: the write must be atomic (a sibling temp file
// renamed over the original) and preserve the original file's mode, and it
// must never leave a stray temp file behind, on success or on failure.
func TestCommitPreservesFilePermissionsAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mailctl.yaml")
	if err := os.WriteFile(path, []byte(startingConfig), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := AddMailbox(path, "a.com", "sales@a.com", "SALES_PW"); err != nil {
		t.Fatalf("AddMailbox: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}

	// A rejected edit takes the same commit path and must clean up too.
	if err := AddMailbox(path, "b.com", "x@b.com", "PW"); err == nil {
		t.Fatalf("AddMailbox: want an error for an unknown domain")
	}

	leftovers, err := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

// scalarFixture exercises the raw yaml.Node round trip (unmarshal followed by
// a fresh encode) that edit() relies on to leave every untouched scalar
// exactly as written: YAML 1.1-style booleans that YAML 1.2 treats as plain
// strings (yes/no/on), quoted strings that look numeric (1.0, 0755, 007), a
// timestamp, an explicit null (~), and an explicit empty string, all quoted
// in the source below.
const scalarFixture = `values:
  yesish: yes
  noish: no
  onish: on
  version: '1.0'
  mode: '0755'
  umask: '007'
  when: 2024-01-02T03:04:05Z
  empty: ~
  blank: ''
`

func TestRawRoundTripPreservesTrickyScalars(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(scalarFixture), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}

	var out strings.Builder
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("render: %v", err)
	}

	if out.String() != scalarFixture {
		t.Errorf("round trip changed the document:\nwant:\n%s\ngot:\n%s", scalarFixture, out.String())
	}
}

// TestExampleConfigRoundTripsWithCommentsIntact guards the shipped example
// config against a regression in the node round trip: every comment in the
// file must still be present in the re-encoded output, and the result must
// still be a config config.Load accepts. Blank lines are excluded
// deliberately: yaml.Node carries no representation for them, so they are
// known and documented to be lost on any edit (see the package doc comment).
func TestExampleConfigRoundTripsWithCommentsIntact(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "mailctl.example.yaml"))
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse example config: %v", err)
	}
	var out strings.Builder
	encoder := yaml.NewEncoder(&out)
	encoder.SetIndent(2)
	if err := encoder.Encode(&doc); err != nil {
		t.Fatalf("render example config: %v", err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatalf("render example config: %v", err)
	}
	rendered := out.String()

	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") && !strings.Contains(rendered, trimmed) {
			t.Errorf("comment lost by the round trip: %q", trimmed)
		}
	}

	examplePath := filepath.Join(t.TempDir(), "mailctl.example.yaml")
	if err := os.WriteFile(examplePath, []byte(rendered), 0o600); err != nil {
		t.Fatalf("write rendered example: %v", err)
	}
	if _, err := loadForTest(examplePath); err != nil {
		t.Fatalf("re-encoded example config no longer loads: %v\n%s", err, rendered)
	}
}
