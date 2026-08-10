// Package importer turns live provider state into a YAML config block, so an
// existing domain can be adopted without hand-writing it.
package importer

import (
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/zoolcoder/mailctl/internal/mail"
)

// Render returns a domains-list entry describing the live state. The caller
// prints it; nothing here writes a file.
func Render(domain, zoneName, provider string, state mail.State) (string, error) {
	if !state.DomainExists {
		return "", fmt.Errorf("domain %s does not exist at provider %s; there is nothing to import", domain, provider)
	}

	// Build a map of derived names to their addresses to detect collisions.
	addressByName := make(map[string][]string)
	for _, box := range state.Mailboxes {
		base := basePlaceholderVar(box.Address)
		addressByName[base] = append(addressByName[base], box.Address)
	}

	// Identify which names have collisions.
	colliding := make(map[string]bool)
	for _, addrs := range addressByName {
		if len(addrs) > 1 {
			for _, addr := range addrs {
				colliding[addr] = true
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "- name: %s\n", domain)
	if zoneName != "" && zoneName != domain {
		fmt.Fprintf(&b, "  zoneName: %s\n", zoneName)
	}
	fmt.Fprintf(&b, "  mail:\n    provider: %s\n", provider)
	if provider == "ms365" {
		// license and usageLocation are not derivable from tenant state:
		// Microsoft Graph reports a user's assigned licence as a skuId GUID,
		// not the skuPartNumber config wants, and does not return the
		// domain-level default at all. Leave the block commented rather than
		// guessing a value that would either fail validation for real
		// reasons or, worse, parse as a plausible-looking wrong one.
		fmt.Fprintf(&b, "    # ms365 needs a license and usageLocation config cannot read back from\n")
		fmt.Fprintf(&b, "    # Microsoft Graph. Uncomment and fill in before the next plan or apply.\n")
		fmt.Fprintf(&b, "    # ms365:\n")
		fmt.Fprintf(&b, "    #   license: BUSINESS_BASIC   # a skuPartNumber this tenant subscribes to\n")
		fmt.Fprintf(&b, "    #   usageLocation: DE          # ISO 3166-1 alpha-2 code\n")
	}
	if state.Settings.AllowAccountReset || state.Settings.SymbolicSubaddressing {
		fmt.Fprintf(&b, "    settings:\n")
		fmt.Fprintf(&b, "      allowAccountReset: %t\n", state.Settings.AllowAccountReset)
		fmt.Fprintf(&b, "      symbolicSubaddressing: %t\n", state.Settings.SymbolicSubaddressing)
	}

	if len(state.Mailboxes) > 0 {
		fmt.Fprintf(&b, "\n  # Credentials cannot be read back from any provider. Set each variable\n")
		fmt.Fprintf(&b, "  # below to the credential already in use, or delete the passwordEnv line\n")
		fmt.Fprintf(&b, "  # to have mailctl generate a new one on the next apply.\n")
		fmt.Fprintf(&b, "  mailboxes:\n")
		for _, box := range state.Mailboxes {
			fmt.Fprintf(&b, "    - address: %s\n", box.Address)
			varName := basePlaceholderVar(box.Address)
			if colliding[box.Address] {
				varName = disambiguatePlaceholderVar(box.Address)
			}
			fmt.Fprintf(&b, "      passwordEnv: %s\n", varName)
			if len(box.Recovery) > 0 {
				fmt.Fprintf(&b, "      recovery:\n")
				for _, method := range box.Recovery {
					fmt.Fprintf(&b, "        - type: %s\n          target: %s\n", method.Type, method.Target)
					if method.Description != "" {
						fmt.Fprintf(&b, "          description: %s\n", method.Description)
					}
				}
			}
		}
	}

	if len(state.Aliases) > 0 {
		fmt.Fprintf(&b, "\n  aliases:\n")
		for _, alias := range state.Aliases {
			match := alias.Match
			if alias.Prefix {
				match += "*"
			}
			fmt.Fprintf(&b, "    - match: %s\n      to: [%s]\n", match, strings.Join(alias.To, ", "))
		}
	}

	if state.CatchAll != nil {
		fmt.Fprintf(&b, "\n  catchAll:\n    to: [%s]\n", strings.Join(state.CatchAll.To, ", "))
	}

	return b.String(), nil
}

// basePlaceholderVar derives an environment variable name from an address:
// contact@a.com becomes MAILCTL_CONTACT_A_COM_PASSWORD.
// Does not include collision detection; use disambiguatePlaceholderVar for
// addresses that collide with others.
func basePlaceholderVar(address string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, address)
	return "MAILCTL_" + strings.ToUpper(cleaned) + "_PASSWORD"
}

// disambiguatePlaceholderVar derives a unique variable name for an address,
// appending a short hash of the full address to avoid collisions. The hash is
// deterministic: the same address always produces the same output.
func disambiguatePlaceholderVar(address string) string {
	h := fnv.New32a()
	h.Write([]byte(address))
	hash := h.Sum32()
	hashStr := fmt.Sprintf("%08x", hash)[:6] // Take first 6 hex chars
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, address)
	return "MAILCTL_" + strings.ToUpper(cleaned) + "_" + hashStr + "_PASSWORD"
}
