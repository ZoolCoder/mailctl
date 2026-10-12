// Package keychain keeps mailctl's tokens and generated credentials in the
// macOS login Keychain, under one service, through the security CLI. On any
// other platform it reports itself unavailable and every lookup misses.
package keychain

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Service is the Keychain service every mailctl item is stored under.
const Service = "mailctl"

// Available reports whether this machine has a Keychain mailctl can use.
func Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath("security")
	return err == nil
}

// Get returns the item stored under account, or false when there is none.
func Get(account string) (string, bool) {
	if !Available() {
		return "", false
	}
	out, err := exec.Command("security", "find-generic-password", "-s", Service, "-a", account, "-w").Output()
	if err != nil {
		return "", false
	}
	return strings.TrimRight(string(out), "\n"), true
}

// Set stores value under account, replacing any item already there. The
// value reaches security on stdin, in its interactive mode, never on a
// command line that any process on the machine can read.
func Set(account, value string) error {
	if !Available() {
		return errors.New("the macOS Keychain is not available on this platform")
	}
	for _, s := range []string{account, value} {
		if strings.ContainsAny(s, "\"\\\n") {
			return fmt.Errorf("keychain item for %s: a quote, backslash or newline cannot be stored this way", account)
		}
	}
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader("add-generic-password -U -s \"" + Service + "\" -a \"" + account + "\" -w \"" + value + "\"\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("keychain item for %s: %s", account, strings.TrimSpace(string(out)))
	}
	return nil
}
