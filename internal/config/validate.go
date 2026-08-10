package config

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// KnownProviders is every mail provider name the config accepts. Providers are
// registered at init time in internal/mail, but config must be able to reject a
// typo without importing that package, so the list is duplicated here
// deliberately and kept in sync by TestKnownProvidersMatchRegistry.
var KnownProviders = []string{"purelymail", "cfrouting", "cfsending", "ms365"}

// MailboxlessProviders route mail but do not host it. A domain using only these
// providers may not declare mailboxes.
var MailboxlessProviders = []string{"cfrouting", "cfsending"}

// InboundProviders accept inbound mail: each publishes MX records and creates
// its own alias routing rules. A domain may name at most one; cfsending is
// outbound-only and may pair with either.
var InboundProviders = []string{"purelymail", "cfrouting", "ms365"}

var dmarcPolicies = []string{"none", "quarantine", "reject"}

var mtaStsModes = []string{"none", "testing", "enforce"}

// maxMTAStsMaxAge is RFC 8461's cap on max_age, in seconds (365 days).
const maxMTAStsMaxAge = 31557600

// allQualifiers lists every SPF "all" mechanism qualifier form, matching
// internal/deliver's own list; spfIncludes may not smuggle one in.
var allQualifiers = []string{"all", "+all", "?all", "~all", "-all"}

func (c Config) Validate() error {
	var errs []error

	seenDomains := map[string]bool{}
	for _, d := range c.Domains {
		if d.Name == "" {
			errs = append(errs, errors.New("every domain needs a name"))
			continue
		}
		if seenDomains[d.Name] {
			errs = append(errs, fmt.Errorf("domain %s is declared twice", d.Name))
		}
		seenDomains[d.Name] = true
		errs = append(errs, d.validate()...)
	}

	return errors.Join(errs...)
}

func (d Domain) validate() []error {
	var errs []error

	if len(d.Mail.Providers) == 0 {
		errs = append(errs, fmt.Errorf("domain %s: mail.provider is required", d.Name))
	}
	for _, name := range d.Mail.Providers {
		if !contains(KnownProviders, name) {
			errs = append(errs, fmt.Errorf(
				"domain %s: unknown mail provider %q; known providers are %s",
				d.Name, name, strings.Join(KnownProviders, ", ")))
		}
	}

	if inbound := d.inboundProviders(); len(inbound) > 1 {
		errs = append(errs, fmt.Errorf(
			"domain %s: providers %s are both inbound (each publishes MX and its own alias rules); only one inbound provider is supported per domain",
			d.Name, strings.Join(inbound, " and ")))
	}

	if len(d.Mailboxes) > 0 && d.onlyMailboxless() {
		errs = append(errs, fmt.Errorf(
			"domain %s: provider %s routes mail but does not host mailboxes; remove the mailboxes block",
			d.Name, strings.Join(d.Mail.Providers, "+")))
	}

	seenMailbox := map[string]bool{}
	for _, m := range d.Mailboxes {
		if err := checkAddress(d.Name, "mailbox", m.Address); err != nil {
			errs = append(errs, err)
			continue
		}
		if seenMailbox[m.Address] {
			errs = append(errs, fmt.Errorf("domain %s: duplicate mailbox %s", d.Name, m.Address))
		}
		seenMailbox[m.Address] = true
		errs = append(errs, m.validate(d.Name)...)
	}

	seenAlias := map[string]bool{}
	for _, a := range d.Aliases {
		if a.Match == "" {
			errs = append(errs, fmt.Errorf("domain %s: alias match is required", d.Name))
			continue
		}
		if strings.Contains(a.Match, "@") {
			errs = append(errs, fmt.Errorf(
				"domain %s: alias %q must be a local part, not a full address", d.Name, a.Match))
		}
		if seenAlias[a.Match] {
			errs = append(errs, fmt.Errorf("domain %s: duplicate alias %s", d.Name, a.Match))
		}
		seenAlias[a.Match] = true
		if len(a.To) == 0 {
			errs = append(errs, fmt.Errorf("domain %s: alias %s needs at least one to: address", d.Name, a.Match))
		}
		for _, target := range a.To {
			if !strings.Contains(target, "@") {
				errs = append(errs, fmt.Errorf(
					"domain %s: alias %s target %q is not an email address", d.Name, a.Match, target))
			}
		}
	}

	if d.CatchAll != nil {
		if len(d.CatchAll.To) == 0 {
			errs = append(errs, fmt.Errorf(
				"domain %s: catchAll needs at least one to: address; omit the key entirely to leave the catch-all unmanaged",
				d.Name))
		}
		for _, target := range d.CatchAll.To {
			if !strings.Contains(target, "@") {
				errs = append(errs, fmt.Errorf(
					"domain %s: catchAll target %q is not an email address", d.Name, target))
			}
		}
	}

	errs = append(errs, d.Deliverability.validate(d)...)
	errs = append(errs, validateMS365(d)...)
	return errs
}

func (m Mailbox) validate(domain string) []error {
	var errs []error
	for _, r := range m.Recovery {
		switch r.Type {
		case "email":
			if !strings.Contains(r.Target, "@") {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s recovery email %q is not an email address", domain, m.Address, r.Target))
			}
		case "phone":
			if r.Target == "" {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s recovery phone needs a target", domain, m.Address))
			}
		default:
			errs = append(errs, fmt.Errorf(
				"domain %s: mailbox %s recovery type %q must be email or phone", domain, m.Address, r.Type))
		}
	}
	return errs
}

func (v Deliverability) validate(d Domain) []error {
	var errs []error

	for _, entry := range v.SPFIncludes {
		if err := checkSPFInclude(d.Name, entry); err != nil {
			errs = append(errs, err)
		}
	}

	if v.DMARC != nil {
		if !contains(dmarcPolicies, v.DMARC.Policy) {
			errs = append(errs, fmt.Errorf(
				"domain %s: dmarc.policy %q must be one of %s",
				d.Name, v.DMARC.Policy, strings.Join(dmarcPolicies, ", ")))
		}
		if v.DMARC.SubdomainPolicy != "" && !contains(dmarcPolicies, v.DMARC.SubdomainPolicy) {
			errs = append(errs, fmt.Errorf(
				"domain %s: dmarc.subdomainPolicy %q must be one of %s",
				d.Name, v.DMARC.SubdomainPolicy, strings.Join(dmarcPolicies, ", ")))
		}
		if v.DMARC.Pct < 1 || v.DMARC.Pct > 100 {
			errs = append(errs, fmt.Errorf("domain %s: dmarc.pct %d must be between 1 and 100", d.Name, v.DMARC.Pct))
		}
		if v.DMARC.RUA != "" {
			if err := checkReportingAddr(d.Name, "dmarc.rua", v.DMARC.RUA); err != nil {
				errs = append(errs, err)
			}
		}
		if v.DMARC.RUF != "" {
			if err := checkReportingAddr(d.Name, "dmarc.ruf", v.DMARC.RUF); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if v.TLSRpt != "" {
		if err := checkReportingAddr(d.Name, "tlsRpt", v.TLSRpt); err != nil {
			errs = append(errs, err)
		}
	}

	if v.MTASts != nil {
		if !contains(mtaStsModes, v.MTASts.Mode) {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.mode %q must be one of %s",
				d.Name, v.MTASts.Mode, strings.Join(mtaStsModes, ", ")))
		}
		if v.MTASts.Mode != "" && v.MTASts.Mode != "none" && !d.publishesMX() {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.mode %s requires a mail provider that publishes MX records; %s does not",
				d.Name, v.MTASts.Mode, strings.Join(d.Mail.Providers, "+")))
		}
		if v.MTASts.Mode != "" && v.MTASts.MaxAge < 0 {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.maxAge %d must be positive or zero (for default)",
				d.Name, v.MTASts.MaxAge))
		}
		if v.MTASts.MaxAge > maxMTAStsMaxAge {
			errs = append(errs, fmt.Errorf(
				"domain %s: mtaSts.maxAge %d exceeds RFC 8461's maximum of %d seconds",
				d.Name, v.MTASts.MaxAge, maxMTAStsMaxAge))
		}
	}

	if v.BIMI != nil {
		if v.BIMI.Logo == "" {
			errs = append(errs, fmt.Errorf("domain %s: bimi.logo is required when bimi is configured", d.Name))
		}
		if v.BIMI.Logo != "" {
			if err := checkReportingAddr(d.Name, "bimi.logo", v.BIMI.Logo); err != nil {
				errs = append(errs, err)
			}
		}
		if v.BIMI.VMC != "" {
			if err := checkReportingAddr(d.Name, "bimi.vmc", v.BIMI.VMC); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

// publishesMX reports whether any configured provider publishes inbound MX records.
// cfsending is outbound only.
func (d Domain) publishesMX() bool {
	for _, name := range d.Mail.Providers {
		if name != "cfsending" {
			return true
		}
	}
	return false
}

// inboundProviders returns the configured providers that accept inbound mail,
// in declaration order.
func (d Domain) inboundProviders() []string {
	var found []string
	for _, name := range d.Mail.Providers {
		if contains(InboundProviders, name) {
			found = append(found, name)
		}
	}
	return found
}

func (d Domain) onlyMailboxless() bool {
	for _, name := range d.Mail.Providers {
		if !contains(MailboxlessProviders, name) {
			return false
		}
	}
	return len(d.Mail.Providers) > 0
}

func checkAddress(domain, kind, address string) error {
	if address == "" {
		return fmt.Errorf("domain %s: %s address is required", domain, kind)
	}
	local, host, ok := strings.Cut(address, "@")
	if !ok || local == "" || host == "" {
		return fmt.Errorf("domain %s: %q is not a valid email address", domain, address)
	}
	if !strings.EqualFold(host, domain) {
		return fmt.Errorf("domain %s: %s %s must use domain %s", domain, kind, address, domain)
	}
	return nil
}

func checkReportingAddr(domain, field, value string) error {
	if strings.ContainsAny(value, ";") {
		return fmt.Errorf(
			"domain %s: %s %q contains semicolon, which is the DMARC/TLS-RPT tag separator; multiple reporting addresses are comma-separated",
			domain, field, value)
	}
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return fmt.Errorf(
			"domain %s: %s %q contains whitespace",
			domain, field, value)
	}
	for _, element := range strings.Split(value, ",") {
		if !strings.HasPrefix(element, "mailto:") && !strings.HasPrefix(element, "https:") {
			return fmt.Errorf(
				"domain %s: %s %q element %q must begin with mailto: or https:",
				domain, field, value, element)
		}
	}
	return nil
}

// checkSPFInclude validates one spfIncludes entry. It is the one
// deliverability string interpolated into TXT content with no other check,
// so a malformed entry can flip the record's qualifier, override it entirely
// with a redirect, or smuggle a second mechanism into one line.
func checkSPFInclude(domain, entry string) error {
	if strings.TrimSpace(entry) == "" {
		return fmt.Errorf("domain %s: spfIncludes entry %q is empty", domain, entry)
	}
	if strings.ContainsFunc(entry, unicode.IsSpace) {
		return fmt.Errorf(
			"domain %s: spfIncludes entry %q contains whitespace; each entry must be exactly one SPF mechanism",
			domain, entry)
	}
	lower := strings.ToLower(entry)
	if contains(allQualifiers, lower) {
		return fmt.Errorf(
			"domain %s: spfIncludes entry %q is an all qualifier; mailctl derives the strictest qualifier itself",
			domain, entry)
	}
	if strings.HasPrefix(lower, "redirect=") {
		return fmt.Errorf(
			"domain %s: spfIncludes entry %q is a redirect modifier, which would override the entire SPF record",
			domain, entry)
	}
	return nil
}

// validateMS365 checks the rules that only apply when a domain does, or does
// not, use the ms365 provider.
func validateMS365(d Domain) []error {
	uses := contains(d.Mail.Providers, "ms365")
	var errs []error

	if !uses {
		if d.Mail.MS365 != nil {
			errs = append(errs, fmt.Errorf(
				"domain %s: a mail.ms365 block is set but provider ms365 is not selected; remove the mail.ms365 block or add ms365 to mail.provider",
				d.Name))
		}
		for _, box := range d.Mailboxes {
			if box.DisplayName != "" {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s sets displayName, which only the ms365 provider uses; remove it",
					d.Name, box.Address))
			}
			if box.License != "" {
				errs = append(errs, fmt.Errorf(
					"domain %s: mailbox %s sets license, which only the ms365 provider uses; remove it",
					d.Name, box.Address))
			}
		}
		return errs
	}

	if len(d.Aliases) > 0 {
		errs = append(errs, fmt.Errorf(
			"domain %s: provider ms365 cannot manage aliases because Microsoft Graph exposes proxyAddresses as read-only; add them in the Microsoft 365 admin center and remove the aliases block",
			d.Name))
	}
	if d.CatchAll != nil {
		errs = append(errs, fmt.Errorf(
			"domain %s: provider ms365 cannot manage a catch-all because it requires an Exchange transport rule; create it in the Microsoft 365 admin center and remove the catchAll block",
			d.Name))
	}

	settings := d.Mail.MS365
	if settings == nil {
		errs = append(errs, fmt.Errorf(
			"domain %s: provider ms365 requires an ms365 block with license and usageLocation", d.Name))
		return append(errs, mailboxFieldErrors(d)...)
	}

	if strings.TrimSpace(settings.License) == "" {
		errs = append(errs, fmt.Errorf(
			"domain %s: mail.ms365.license is required; use a skuPartNumber such as BUSINESS_BASIC, not a skuId",
			d.Name))
	}
	if err := validateUsageLocation(d.Name, settings.UsageLocation); err != nil {
		errs = append(errs, err)
	}
	errs = append(errs, validateDKIMCnames(d.Name, settings.DKIMCnames)...)

	return append(errs, mailboxFieldErrors(d)...)
}

// mailboxFieldErrors rejects Purelymail-only mailbox fields on an ms365 domain.
func mailboxFieldErrors(d Domain) []error {
	var errs []error
	for _, box := range d.Mailboxes {
		for _, field := range purelymailOnlySet(box) {
			errs = append(errs, fmt.Errorf(
				"domain %s: mailbox %s sets %s, which is a Purelymail feature with no Microsoft 365 equivalent; remove it",
				d.Name, box.Address, field))
		}
	}
	return errs
}

// purelymailOnlySet returns the names of the Purelymail-only fields this
// mailbox actually sets.
func purelymailOnlySet(box Mailbox) []string {
	var set []string
	if box.EnablePasswordReset != nil {
		set = append(set, "enablePasswordReset")
	}
	if box.EnableSearchIndexing != nil {
		set = append(set, "enableSearchIndexing")
	}
	if box.RequireTwoFactorAuthentication != nil {
		set = append(set, "requireTwoFactorAuthentication")
	}
	if box.SendWelcomeEmail != nil {
		set = append(set, "sendWelcomeEmail")
	}
	if len(box.Recovery) > 0 {
		set = append(set, "recovery")
	}
	return set
}

func validateUsageLocation(domain, value string) error {
	if value == "" {
		return fmt.Errorf(
			"domain %s: mail.ms365.usageLocation is required because Microsoft Graph will not assign a licence without it; use a two-letter country code such as DE",
			domain)
	}
	if len(value) != 2 || !isASCIILetters(value) {
		return fmt.Errorf(
			"domain %s: mail.ms365.usageLocation %q must be a two-letter ISO 3166-1 alpha-2 code",
			domain, value)
	}
	return nil
}

func isASCIILetters(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func validateDKIMCnames(domain string, targets []string) []error {
	if len(targets) == 0 {
		return nil
	}
	if len(targets) != 2 {
		return []error{fmt.Errorf(
			"domain %s: mail.ms365.dkimCnames must hold exactly two targets, for selector1 and selector2 in that order; got %d",
			domain, len(targets))}
	}

	var errs []error
	for i, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			errs = append(errs, fmt.Errorf(
				"domain %s: mail.ms365.dkimCnames[%d] is empty", domain, i))
			continue
		}
		if strings.ContainsAny(trimmed, " \t") {
			errs = append(errs, fmt.Errorf(
				"domain %s: mail.ms365.dkimCnames[%d] %q contains whitespace", domain, i, target))
		}
		// The likely mistake is pasting the label mailctl generates instead of
		// the target it should point at.
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "selector1._domainkey") || strings.HasPrefix(lower, "selector2._domainkey") {
			errs = append(errs, fmt.Errorf(
				"domain %s: mail.ms365.dkimCnames[%d] %q looks like the record label, not its target; paste the value the Defender portal shows as the CNAME target",
				domain, i, target))
		}
	}
	return errs
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
