// Package config defines the mailctl YAML schema and loads it into a desired-state tree.
package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only config schema version this build understands.
const SchemaVersion = 1

const (
	DefaultCloudflareBaseURL = "https://api.cloudflare.com/client/v4"
	DefaultPurelymailBaseURL = "https://purelymail.com"
	DefaultTTL               = 1
	// DefaultDMARCPct is applied when dmarc is configured but pct is omitted,
	// so pct is not a required key.
	DefaultDMARCPct = 100
)

type Config struct {
	Version    int              `yaml:"version"`
	Cloudflare CloudflareConfig `yaml:"cloudflare"`
	Purelymail PurelymailConfig `yaml:"purelymail"`
	Domains    []Domain         `yaml:"domains"`
}

type CloudflareConfig struct {
	AccountID string `yaml:"accountId"`
	BaseURL   string `yaml:"baseUrl"`
	TTL       int    `yaml:"ttl"`
}

type PurelymailConfig struct {
	BaseURL string `yaml:"baseUrl"`
}

type Domain struct {
	Name           string         `yaml:"name"`
	ZoneName       string         `yaml:"zoneName"`
	Mail           Mail           `yaml:"mail"`
	Mailboxes      []Mailbox      `yaml:"mailboxes"`
	Aliases        []Alias        `yaml:"aliases"`
	CatchAll       *CatchAll      `yaml:"catchAll"`
	Deliverability Deliverability `yaml:"deliverability"`
}

// Mail holds the provider selection and provider-level domain settings.
// provider accepts either a scalar name or a list of names.
type Mail struct {
	Providers []string
	Settings  DomainSettings
	MS365     *MS365
}

// MS365 holds the Microsoft 365 settings for a domain. Fields Graph cannot
// change are absent by design; see the ms365 design doc.
type MS365 struct {
	// License is a skuPartNumber such as BUSINESS_BASIC, not a skuId GUID.
	// It is the domain-level default; a mailbox's own Mailbox.License
	// overrides it for that mailbox only.
	License string `yaml:"license"`
	// UsageLocation is an ISO 3166-1 alpha-2 code. Graph requires it on a user
	// before a licence can be assigned.
	UsageLocation string `yaml:"usageLocation"`
	// DKIMCnames are the two targets copied from the Defender portal, for
	// selector1 and selector2 in that order. Graph cannot supply them.
	DKIMCnames []string `yaml:"dkimCnames"`
}

// UnmarshalYAML decodes the mail: mapping by hand rather than via
// node.Decode(&raw): that call starts a fresh decode that does not inherit
// the top-level decoder's KnownFields(true), so a typo'd key would load
// silently. Walking Content in pairs keeps strictness for mail.provider,
// mail.settings, and the two settings keys, which are the domain-level
// security settings.
func (m *Mail) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("mail at line %d must be a mapping", node.Line)
	}

	var providerNode, settingsNode, ms365Node *yaml.Node
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "provider":
			providerNode = value
		case "settings":
			settingsNode = value
		case "ms365":
			ms365Node = value
		default:
			return fmt.Errorf(
				"mail.%s at line %d is not a known field; expected provider, settings or ms365",
				key.Value, key.Line)
		}
	}

	if settingsNode != nil {
		settings, err := decodeDomainSettings(settingsNode)
		if err != nil {
			return err
		}
		m.Settings = settings
	}

	if ms365Node != nil {
		parsed, err := decodeMS365(ms365Node)
		if err != nil {
			return err
		}
		m.MS365 = parsed
	}

	if providerNode == nil {
		return nil
	}
	switch providerNode.Kind {
	case yaml.ScalarNode:
		var name string
		if err := providerNode.Decode(&name); err != nil {
			return err
		}
		m.Providers = []string{name}
	case yaml.SequenceNode:
		return providerNode.Decode(&m.Providers)
	default:
		return fmt.Errorf("mail.provider at line %d must be a string or a list of strings", providerNode.Line)
	}
	return nil
}

// decodeDomainSettings strictly decodes the mail.settings mapping, rejecting
// any key other than allowAccountReset and symbolicSubaddressing.
func decodeDomainSettings(node *yaml.Node) (DomainSettings, error) {
	var out DomainSettings
	if node.Kind != yaml.MappingNode {
		return out, fmt.Errorf("mail.settings at line %d must be a mapping", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "allowAccountReset":
			var v bool
			if err := value.Decode(&v); err != nil {
				return out, err
			}
			out.AllowAccountReset = &v
		case "symbolicSubaddressing":
			var v bool
			if err := value.Decode(&v); err != nil {
				return out, err
			}
			out.SymbolicSubaddressing = &v
		default:
			return out, fmt.Errorf(
				"mail.settings.%s at line %d is not a known field; expected allowAccountReset or symbolicSubaddressing",
				key.Value, key.Line)
		}
	}
	return out, nil
}

// decodeMS365 strictly decodes the mail.ms365 mapping. Like
// decodeDomainSettings it walks Content in pairs rather than calling
// node.Decode, because that would start a fresh decode without
// KnownFields(true) and let a typo load silently.
func decodeMS365(node *yaml.Node) (*MS365, error) {
	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("mail.ms365 at line %d must be a mapping", node.Line)
	}
	out := &MS365{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "license":
			if err := value.Decode(&out.License); err != nil {
				return nil, err
			}
		case "usageLocation":
			if err := value.Decode(&out.UsageLocation); err != nil {
				return nil, err
			}
		case "dkimCnames":
			if err := value.Decode(&out.DKIMCnames); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf(
				"mail.ms365.%s at line %d is not a known field; expected license, usageLocation or dkimCnames",
				key.Value, key.Line)
		}
	}
	return out, nil
}

type DomainSettings struct {
	AllowAccountReset     *bool `yaml:"allowAccountReset"`
	SymbolicSubaddressing *bool `yaml:"symbolicSubaddressing"`
}

type Mailbox struct {
	Address                        string     `yaml:"address"`
	PasswordEnv                    string     `yaml:"passwordEnv"`
	EnablePasswordReset            *bool      `yaml:"enablePasswordReset"`
	EnableSearchIndexing           *bool      `yaml:"enableSearchIndexing"`
	RequireTwoFactorAuthentication *bool      `yaml:"requireTwoFactorAuthentication"`
	SendWelcomeEmail               *bool      `yaml:"sendWelcomeEmail"`
	Recovery                       []Recovery `yaml:"recovery"`
	// DisplayName and License are ms365 fields. Validation rejects them on a
	// domain using any other provider. License, when set, overrides
	// MS365.License's domain-level default for this mailbox only.
	DisplayName string `yaml:"displayName"`
	License     string `yaml:"license"`
}

// Recovery is one password-reset method attached to a mailbox.
type Recovery struct {
	Type          string `yaml:"type"` // email | phone
	Target        string `yaml:"target"`
	Description   string `yaml:"description"`
	AllowMfaReset bool   `yaml:"allowMfaReset"`
}

type Alias struct {
	Match string   `yaml:"match"`
	To    []string `yaml:"to"`
}

type CatchAll struct {
	To []string `yaml:"to"`
}

// Deliverability configures the SPF, DMARC, MTA-STS, TLS-RPT, and BIMI
// records mailctl publishes alongside whatever a mail provider asks for.
type Deliverability struct {
	SPFIncludes []string `yaml:"spfIncludes"`
	DMARC       *DMARC   `yaml:"dmarc"`
	MTASts      *MTASts  `yaml:"mtaSts"`
	TLSRpt      string   `yaml:"tlsRpt"`
	BIMI        *BIMI    `yaml:"bimi"`
}

type DMARC struct {
	Policy          string `yaml:"policy"`
	SubdomainPolicy string `yaml:"subdomainPolicy"`
	Pct             int    `yaml:"pct"`
	RUA             string `yaml:"rua"`
	RUF             string `yaml:"ruf"`
}

type MTASts struct {
	Mode   string `yaml:"mode"`
	MaxAge int    `yaml:"maxAge"`
	Deploy bool   `yaml:"deploy"`
}

type BIMI struct {
	Logo string `yaml:"logo"`
	VMC  string `yaml:"vmc"`
}

// LocalPart returns the portion of the address before the @.
func (m Mailbox) LocalPart() string {
	local, _, _ := strings.Cut(m.Address, "@")
	return local
}

// Prefix reports whether the alias match is a prefix match (trailing *).
func (a Alias) Prefix() bool { return strings.HasSuffix(a.Match, "*") }

// MatchUser returns the alias local part with any trailing * removed.
func (a Alias) MatchUser() string { return strings.TrimSuffix(a.Match, "*") }

// Domain returns the domain with the given name, and whether it was found.
func (c Config) Domain(name string) (Domain, bool) {
	for _, d := range c.Domains {
		if strings.EqualFold(d.Name, name) {
			return d, true
		}
	}
	return Domain{}, false
}

// BoolOr resolves an optional YAML bool against a default.
func BoolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

// AllTargets returns every address this domain forwards to, deduplicated.
// Cloudflare Email Routing requires each of them to be a verified destination.
func (d Domain) AllTargets() []string {
	var out []string
	seen := map[string]bool{}
	add := func(list []string) {
		for _, address := range list {
			key := strings.ToLower(address)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, address)
		}
	}
	for _, alias := range d.Aliases {
		add(alias.To)
	}
	if d.CatchAll != nil {
		add(d.CatchAll.To)
	}
	return out
}
