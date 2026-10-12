package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zoolcoder/mailctl/internal/keychain"
	"github.com/zoolcoder/mailctl/internal/secret"
)

// The Keychain is reached through these so tests never touch the real one.
var (
	keychainGet       = keychain.Get
	keychainSet       = keychain.Set
	keychainAvailable = keychain.Available
)

// mcpMode is set while the MCP server runs: a generated credential must then
// never reach stderr, because stderr is part of the reply an agent reads.
var mcpMode bool

var credentialCache sync.Map

// getenv resolves a variable from the environment, then from the Keychain
// (service mailctl, account = the variable's name), so a token never has to
// sit in a shell profile.
func getenv(name string) string {
	value, _ := lookupCredential(name)
	return value
}

// lookupCredential is getenv that also says where the value came from: "env",
// "keychain", or "" when it is set nowhere. Keychain answers are cached for
// the life of the process, misses included.
func lookupCredential(name string) (string, string) {
	if value := os.Getenv(name); value != "" {
		return value, "env"
	}
	cached, ok := credentialCache.Load(name)
	if !ok {
		value, _ := keychainGet(name)
		cached, _ = credentialCache.LoadOrStore(name, value)
	}
	if value := cached.(string); value != "" {
		return value, "keychain"
	}
	return "", ""
}

// resolveConfigPath picks the config file: -config, then $MAILCTL_CONFIG,
// then ./mailctl.yaml, then $XDG_CONFIG_HOME/mailctl/mailctl.yaml (default
// ~/.config/mailctl/mailctl.yaml). source is "" when none of them exists, and
// the path is then ./mailctl.yaml so the load error names a real place.
func resolveConfigPath(explicit string) (path, source string) {
	if explicit != "" {
		return explicit, "-config"
	}
	if p := os.Getenv("MAILCTL_CONFIG"); p != "" {
		return p, "MAILCTL_CONFIG"
	}
	if fileExists("mailctl.yaml") {
		return "mailctl.yaml", "working directory"
	}
	if p := userConfigPath(); p != "" && fileExists(p) {
		return p, "user config"
	}
	return "mailctl.yaml", ""
}

// userConfigPath is the per-user config location, "" without a home.
func userConfigPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "mailctl", "mailctl.yaml")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// errNoConfig explains the lookup order when no config was found anywhere.
func errNoConfig() error {
	return fmt.Errorf("no config found: pass -config, set MAILCTL_CONFIG, or create ./mailctl.yaml or %s", userConfigPath())
}

// writeOrReport puts generated credentials where the operator can read them
// and nothing else can: the -secrets-out file when given, otherwise the
// Keychain, otherwise stderr. A credential that was just set on a provider
// cannot be re-read from it, so a failed write must never be the only trace
// of the value: the fallback runs before the write error is returned.
func writeOrReport(stderr io.Writer, secretsOut string, generated map[string]string) error {
	if secretsOut == "" && keychainAvailable() {
		return storeInKeychain(stderr, generated)
	}
	if secretsOut == "" {
		return reportFallback(stderr, generated)
	}
	if err := secret.WriteFile(secretsOut, generated); err != nil {
		return errors.Join(err, reportFallback(stderr, generated))
	}
	fmt.Fprintf(stderr, "Wrote %d generated credential(s) to %s\n", len(generated), secretsOut)
	return nil
}

// storeInKeychain stores each credential under its address and names only
// where each one went.
func storeInKeychain(stderr io.Writer, generated map[string]string) error {
	var stored []string
	var errs []error
	refused := map[string]string{}
	for _, account := range sortedAccounts(generated) {
		if err := keychainSet(account, generated[account]); err != nil {
			errs = append(errs, err)
			refused[account] = generated[account]
			continue
		}
		stored = append(stored, account)
	}
	if len(stored) > 0 {
		fmt.Fprintf(stderr, "Stored %d generated credential(s) in the Keychain, service %s: %s\n",
			len(stored), keychain.Service, strings.Join(stored, ", "))
		fmt.Fprintf(stderr, "Read one with: security find-generic-password -s %s -a <account> -w\n", keychain.Service)
	}
	if len(refused) > 0 {
		errs = append(errs, reportFallback(stderr, refused))
	}
	return errors.Join(errs...)
}

// reportFallback is the last resort: stderr for a person at a terminal, a
// 0600 file under the state directory when an agent is reading stderr.
func reportFallback(stderr io.Writer, generated map[string]string) error {
	if !mcpMode {
		return secret.ReportTo(stderr, generated)
	}
	dir := stateDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("generated %d credential(s) but could not store them: %w", len(generated), err)
	}
	path := filepath.Join(dir, "secrets-"+time.Now().UTC().Format("20060102T150405.000000000")+".txt")
	if err := secret.WriteFile(path, generated); err != nil {
		return fmt.Errorf("generated %d credential(s) but could not store them: %w", len(generated), err)
	}
	fmt.Fprintf(stderr, "Wrote %d generated credential(s) to %s\n", len(generated), path)
	return nil
}

// stateDir holds saved plans and fallback credential files:
// $XDG_STATE_HOME/mailctl, default ~/.local/state/mailctl.
func stateDir() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "mailctl")
}

func sortedAccounts(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
