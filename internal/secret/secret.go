// Package secret resolves mailbox credentials and reports generated ones
// exactly once. Nothing in this package writes to stdout.
package secret

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
)

// GeneratedLength is the length of a generated credential.
const GeneratedLength = 24

// alphabet is 76 characters with no quote, backslash, or backtick, so a
// generated value pastes into a shell or a mail client without escaping.
const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%()*+,-.:;=?@[]^_"

// Resolver resolves one credential per mailbox and remembers what it generated.
type Resolver struct {
	getenv    func(string) string
	generated map[string]string
	applied   map[string]string
	cache     map[string]string
}

func NewResolver(getenv func(string) string) *Resolver {
	if getenv == nil {
		getenv = os.Getenv
	}
	return &Resolver{
		getenv:    getenv,
		generated: map[string]string{},
		applied:   map[string]string{},
		cache:     map[string]string{},
	}
}

// Password returns the credential for a mailbox. A configured passwordEnv must
// be set and non-empty; with no passwordEnv a value is generated once and
// cached, so plan and apply agree within a single run.
func (r *Resolver) Password(domain string, m config.Mailbox) (string, error) {
	if cached, ok := r.cache[m.Address]; ok {
		return cached, nil
	}

	if m.PasswordEnv != "" {
		value := r.getenv(m.PasswordEnv)
		if value == "" {
			return "", fmt.Errorf(
				"domain %s: mailbox %s needs environment variable %s to be set",
				domain, m.Address, m.PasswordEnv)
		}
		r.cache[m.Address] = value
		return value, nil
	}

	value, err := Generate(GeneratedLength)
	if err != nil {
		return "", fmt.Errorf("domain %s: generate credential for %s: %w", domain, m.Address, err)
	}
	r.cache[m.Address] = value
	r.generated[m.Address] = value
	return value, nil
}

// Generated returns the credentials this resolver created, keyed by address.
func (r *Resolver) Generated() map[string]string {
	out := make(map[string]string, len(r.generated))
	for k, v := range r.generated {
		out[k] = v
	}
	return out
}

// MarkApplied records that a generated credential was successfully set on the
// provider. Only applied credentials are worth reporting: a value generated
// during planning and never used would send the operator chasing a mailbox
// that does not exist.
func (r *Resolver) MarkApplied(address string) {
	value, ok := r.generated[address]
	if !ok {
		return
	}
	r.applied[address] = value
}

// Applied returns the generated credentials that were actually applied.
func (r *Resolver) Applied() map[string]string {
	out := make(map[string]string, len(r.applied))
	for k, v := range r.applied {
		out[k] = v
	}
	return out
}

// Generate returns a cryptographically random string of the given length.
func Generate(length int) (string, error) {
	limit := big.NewInt(int64(len(alphabet)))
	var b strings.Builder
	b.Grow(length)
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

// ReportTo writes generated credentials under a delimited banner. Callers pass
// os.Stderr; stdout may be piped and must stay free of these values.
func ReportTo(w io.Writer, generated map[string]string) error {
	if len(generated) == 0 {
		return nil
	}

	const rule = "======================================================================"
	if _, err := fmt.Fprintf(w, "\n%s\nGENERATED CREDENTIALS - shown once, not stored anywhere\n%s\n", rule, rule); err != nil {
		return err
	}
	for _, address := range sortedKeys(generated) {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", address, generated[address]); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s\n\n", rule)
	return err
}

// WriteFile writes generated credentials to a new 0600 file, one
// address<TAB>value pair per line. It refuses to write over an existing path,
// including a symlink: O_EXCL fails the open rather than following a symlink
// to overwrite and chmod whatever it points at, which a plain O_TRUNC would
// do silently.
func WriteFile(path string, generated map[string]string) error {
	if len(generated) == 0 {
		return nil
	}
	var body strings.Builder
	for _, address := range sortedKeys(generated) {
		fmt.Fprintf(&body, "%s\t%s\n", address, generated[address])
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf(
				"secrets file %s already exists; mailctl will not overwrite it because it may hold credentials, so move it aside or choose another -secrets-out path: %w",
				path, err)
		}
		return fmt.Errorf("write secrets file %s: %w", path, err)
	}
	// Closes the file on the write-error path below. The success path closes it
	// explicitly and reports that error, because a credential file whose final
	// flush failed must not be reported as written; this deferred close then
	// runs as a harmless no-op.
	defer func() { _ = file.Close() }()

	if _, err := file.WriteString(body.String()); err != nil {
		return fmt.Errorf("write secrets file %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write secrets file %s: %w", path, err)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
