// Package ms365 configures Microsoft 365 mail for a domain through Microsoft
// Graph. Aliases, catch-all and DKIM enablement are not automatable through
// Graph; config validation rejects the first two and takes the DKIM targets as
// input. See docs/superpowers/specs/2026-08-10-mailctl-ms365-design.md.
package ms365

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/graphapi"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
)

// Name is the value used in the config's mail.provider field.
const Name = "ms365"

func init() {
	mail.Register(Name, func(deps mail.Deps) (mail.Provider, error) {
		getenv := deps.Getenv
		if getenv == nil {
			return nil, fmt.Errorf("ms365: no environment accessor supplied")
		}
		client, err := graphapi.New(graphapi.Config{
			TenantID:     getenv("MS365_TENANT_ID"),
			ClientID:     getenv("MS365_CLIENT_ID"),
			ClientSecret: getenv("MS365_CLIENT_SECRET"),
			GraphBaseURL: deps.GraphBaseURL,
			LoginBaseURL: deps.LoginBaseURL,
		})
		if err != nil {
			return nil, err
		}
		return &Provider{
			client:   client,
			skus:     map[string]map[string]licenceInfo{},
			skuNames: map[string]map[string]string{},
		}, nil
	})
}

type Provider struct {
	client *graphapi.Client

	// skus caches the seat index Actual read, keyed by domain, so Plan can do
	// the seat arithmetic without I/O. The engine calls Actual then Plan for
	// each domain, so the entry is always fresh when Plan runs.
	skus map[string]map[string]licenceInfo

	// skuNames caches, per domain, the reverse of skus: skuId to
	// skuPartNumber. Plan needs it to name a licence a mailbox already holds
	// (Actual only records the raw GUID in AssignedSkuIDs), without doing I/O
	// of its own.
	skuNames map[string]map[string]string
}

var _ mail.Provider = (*Provider)(nil)

func (p *Provider) Name() string { return Name }

// notFound reports whether an error is Graph's 404.
func notFound(err error) bool {
	var apiErr *graphapi.APIError
	return errors.As(err, &apiErr) && apiErr.Status == 404
}

func domainPath(domain string) string {
	return "/domains/" + url.PathEscape(domain)
}

func (p *Provider) DesiredDNS(ctx context.Context, d config.Domain) ([]dns.Record, error) {
	if d.Mail.MS365 == nil {
		return nil, fmt.Errorf("ms365: domain %s: mail.ms365 is required for the ms365 provider", d.Name)
	}

	ownership, err := graphapi.List[domainDNSRecord](ctx, p.client, domainPath(d.Name)+"/verificationDnsRecords")
	if err != nil {
		if !notFound(err) {
			return nil, fmt.Errorf("domain %s: %w", d.Name, err)
		}
		// The domain is not in the tenant yet; Plan will add it, and there are
		// no ownership or service records to read until then.
		ownership = nil
	}

	service, err := graphapi.List[domainDNSRecord](ctx, p.client, domainPath(d.Name)+"/serviceConfigurationRecords")
	if err != nil {
		if !notFound(err) {
			return nil, fmt.Errorf("domain %s: %w", d.Name, err)
		}
		service = nil
	}

	return desiredFromGraph(ownership, service, d.Mail.MS365.DKIMCnames, d.Name)
}

func (p *Provider) Actual(ctx context.Context, d config.Domain) (mail.State, error) {
	var state mail.State

	var domain graphDomain
	if err := p.client.Do(ctx, "GET", domainPath(d.Name), nil, &domain); err != nil {
		if notFound(err) {
			state.Notes = append(state.Notes,
				"the domain is not yet added to the tenant; its DNS records become readable after the first apply, so expect a second plan to show them")
			return state, nil
		}
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}

	state.DomainExists = true
	state.Verified = domain.IsVerified
	state.SupportedServices = domain.SupportedServices

	if domain.AuthenticationType == "Federated" {
		state.Notes = append(state.Notes, fmt.Sprintf(
			"domain %s is federated; mailctl only manages managed domains, so this domain's users authenticate elsewhere",
			d.Name))
	}

	if !state.Verified {
		state.Notes = append(state.Notes, fmt.Sprintf(
			"domain %s is not verified yet; configured mailboxes are created once verification completes",
			d.Name))
	}

	users, err := graphapi.List[graphUser](ctx, p.client,
		domainPath(d.Name)+"/domainNameReferences/microsoft.graph.user"+
			"?$select=id,userPrincipalName,mail,displayName,usageLocation,assignedLicenses")
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	for _, u := range users {
		state.Mailboxes = append(state.Mailboxes, mail.Mailbox{
			ID:               u.ID,
			Address:          preferredAddress(u),
			AlternateAddress: alternateAddress(u),
			AssignedSkuIDs:   assignedSkuIDs(u),
		})
	}

	skus, err := graphapi.List[graphSku](ctx, p.client, "/subscribedSkus")
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	index, err := indexSkus(skus)
	if err != nil {
		return state, fmt.Errorf("domain %s: %w", d.Name, err)
	}
	if p.skus == nil {
		p.skus = map[string]map[string]licenceInfo{}
	}
	p.skus[d.Name] = index

	names := make(map[string]string, len(skus))
	for _, sku := range skus {
		names[sku.SkuID] = sku.SkuPartNumber
	}
	if p.skuNames == nil {
		p.skuNames = map[string]map[string]string{}
	}
	p.skuNames[d.Name] = names

	total := map[string]int{}
	for _, sku := range skus {
		total[sku.SkuPartNumber] = sku.PrepaidUnits.Enabled
	}
	for _, part := range referencedLicenses(d) {
		info, ok := index[part]
		if !ok {
			state.Notes = append(state.Notes, fmt.Sprintf(
				"licence %s is configured for this domain but the tenant does not subscribe to it", part))
			continue
		}
		state.Notes = append(state.Notes, fmt.Sprintf(
			"licence %s: %d of %d seats free in this domain's read of the tenant "+
				"(per domain, not per tenant — another domain sharing this tenant is not counted here)",
			part, info.Available, total[part]))
	}

	managed := map[string]bool{}
	for _, box := range d.Mailboxes {
		managed[strings.ToLower(box.Address)] = true
	}
	for _, box := range state.Mailboxes {
		if matchesManaged(managed, box) {
			continue
		}
		state.Notes = append(state.Notes, fmt.Sprintf(
			"unmanaged mailbox %s exists in the tenant; -prune -prune-mailboxes would delete it", box.Address))
	}

	// A mailbox already carrying a licence that is not the one config
	// resolves to is a billing hazard, not merely a plan input: Plan's fix
	// (below) adds the wanted licence without removing the held one, so the
	// tenant pays for both until an operator releases one by hand. Surface
	// that here, in the same note stream the operator already reads, rather
	// than only in the plan action's Detail.
	for _, box := range d.Mailboxes {
		have, exists := state.Mailbox(box.Address)
		if !exists || len(have.AssignedSkuIDs) == 0 {
			continue
		}
		part := effectiveLicense(d, box)
		skuID := index[part].SkuID
		if skuID != "" && containsString(have.AssignedSkuIDs, skuID) {
			continue
		}
		state.Notes = append(state.Notes, fmt.Sprintf(
			"mailbox %s holds licence %s but config wants %s; apply will add %s without removing %s, so the tenant will be billed for both until you release one in the admin centre",
			box.Address, describeSkus(names, have.AssignedSkuIDs), part, part, describeSkus(names, have.AssignedSkuIDs)))
	}

	// Aliases and catch-all are not representable through Graph; config
	// validation rejects both, so no drift can exist to report.
	return state, nil
}

func (p *Provider) Plan(d config.Domain, actual mail.State, opts mail.Options) ([]plan.Action, error) {
	if d.Mail.MS365 == nil {
		return nil, fmt.Errorf("ms365: domain %s: mail.ms365 is required for the ms365 provider", d.Name)
	}

	if !actual.DomainExists {
		name := d.Name
		return []plan.Action{{
			Op:       plan.OpCreate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "add domain " + name,
			Do: func(ctx context.Context) error {
				if err := p.client.Do(ctx, "POST", "/domains", map[string]string{"id": name}, nil); err != nil {
					return fmt.Errorf("add Microsoft 365 domain %s: %w", name, err)
				}
				return nil
			},
		}}, nil
	}

	if !actual.Verified {
		name := d.Name
		return []plan.Action{{
			Op:       plan.OpUpdate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "verify domain " + name,
			Do: func(ctx context.Context) error {
				if err := p.client.Do(ctx, "POST", domainPath(name)+"/verify", nil, nil); err != nil {
					return fmt.Errorf(
						"verify Microsoft 365 domain %s failed; the ownership TXT record may not have propagated yet; rerun in a few minutes: %w",
						name, err)
				}
				return nil
			},
		}}, nil
	}

	var actions []plan.Action

	if !containsFold(actual.SupportedServices, emailService) {
		name := d.Name
		wantServices := append(append([]string{}, actual.SupportedServices...), emailService)
		actions = append(actions, plan.Action{
			Op:       plan.OpUpdate,
			Resource: "domain",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "update supportedServices to include " + emailService,
			Do: func(ctx context.Context) error {
				if err := p.client.Do(ctx, "PATCH", domainPath(name),
					patchDomainRequest{SupportedServices: wantServices}, nil); err != nil {
					return fmt.Errorf("update supportedServices for domain %s: %w", name, err)
				}
				return nil
			},
		})
	}

	// A mailbox has three possible states relative to config: absent from the
	// tenant (create both the user and its licence), present but not carrying
	// the resolved licence's skuId (assign only the licence — the user
	// already exists), or present and already licensed (nothing to do).
	var toCreate []config.Mailbox
	var toLicense []mailboxToLicense
	wanted := map[string]int{}

	for _, box := range d.Mailboxes {
		part := effectiveLicense(d, box)
		have, exists := actual.Mailbox(box.Address)
		if !exists {
			toCreate = append(toCreate, box)
			wanted[part]++
			continue
		}
		skuID := p.skus[d.Name][part].SkuID
		if skuID != "" && containsString(have.AssignedSkuIDs, skuID) {
			continue
		}
		toLicense = append(toLicense, mailboxToLicense{box: box, userID: have.ID, heldSkuIDs: have.AssignedSkuIDs})
		wanted[part]++
	}
	if len(toCreate) > 0 || len(toLicense) > 0 {
		if err := checkSeats(p.skus[d.Name], wanted); err != nil {
			return nil, fmt.Errorf("domain %s: %w", d.Name, err)
		}
	}

	for _, box := range toCreate {
		box := box
		domainName := d.Name
		address := box.Address
		part := effectiveLicense(d, box)
		skuID := p.skus[domainName][part].SkuID
		usageLocation := d.Mail.MS365.UsageLocation

		actions = append(actions, plan.Action{
			Op:       plan.OpCreate,
			Resource: "mailbox",
			Domain:   d.Name,
			Provider: Name,
			Detail:   "create " + address,
			Do: func(ctx context.Context) error {
				credential, err := opts.Secrets.Password(domainName, box)
				if err != nil {
					return err
				}

				local := box.LocalPart()
				displayName := box.DisplayName
				if displayName == "" {
					displayName = local
				}

				var created graphUser
				if err := p.client.Do(ctx, "POST", "/users", createUserRequest{
					AccountEnabled:    true,
					DisplayName:       displayName,
					MailNickname:      local,
					UserPrincipalName: address,
					UsageLocation:     usageLocation,
					PasswordProfile: passwordProfile{
						Password:                      credential,
						ForceChangePasswordNextSignIn: true,
					},
				}, &created); err != nil {
					return fmt.Errorf("domain %s: create mailbox %s: %w", domainName, address, err)
				}

				// The password profile above is what set this user's password.
				// The instant POST /users succeeds, the credential is live on a
				// real account, so it must be reported now — before the licence
				// call, which can still fail — rather than after.
				opts.Secrets.MarkApplied(address)

				if err := p.client.Do(ctx, "POST", "/users/"+url.PathEscape(created.ID)+"/assignLicense",
					assignLicenseRequest{
						AddLicenses:    []addLicense{{SkuID: skuID, DisabledPlans: []string{}}},
						RemoveLicenses: []string{},
					}, nil); err != nil {
					return fmt.Errorf(
						"created the user %s but could not assign its %s licence, so it has no mailbox yet; fix the licence and rerun — the user will be found and only the licence assigned: %w",
						address, part, err)
				}
				return nil
			},
		})
	}

	for _, item := range toLicense {
		box := item.box
		userID := item.userID
		domainName := d.Name
		address := box.Address
		part := effectiveLicense(d, box)
		skuID := p.skus[domainName][part].SkuID

		// A mailbox reaches this branch two ways: it has no licence at all
		// (still has no mailbox — Exchange Online provisions one on licence
		// assignment), or it already holds a *different* licence, in which
		// case claiming "no mailbox" would be false and the operator would
		// approve the action without knowing a second licence is being added
		// on top of the first rather than replacing it.
		detail := fmt.Sprintf("assign the %s licence to %s (the user exists but has no mailbox)", part, address)
		if len(item.heldSkuIDs) > 0 {
			held := describeSkus(p.skuNames[domainName], item.heldSkuIDs)
			detail = fmt.Sprintf(
				"add the %s licence to %s; it already holds %s, which will not be removed — release it in the admin centre if it is no longer needed",
				part, address, held)
		}

		actions = append(actions, plan.Action{
			Op:       plan.OpUpdate,
			Resource: "mailbox",
			Domain:   d.Name,
			Provider: Name,
			Detail:   detail,
			Do: func(ctx context.Context) error {
				if err := p.client.Do(ctx, "POST", "/users/"+url.PathEscape(userID)+"/assignLicense",
					assignLicenseRequest{
						AddLicenses:    []addLicense{{SkuID: skuID, DisabledPlans: []string{}}},
						RemoveLicenses: []string{},
					}, nil); err != nil {
					return fmt.Errorf("domain %s: assign the %s licence to %s: %w", domainName, part, address, err)
				}
				return nil
			},
		})
	}

	if opts.Prune && opts.PruneMailboxes {
		managed := map[string]bool{}
		for _, box := range d.Mailboxes {
			managed[strings.ToLower(box.Address)] = true
		}
		for _, have := range actual.Mailboxes {
			if matchesManaged(managed, have) {
				continue
			}
			domainName := d.Name
			address := have.Address
			id := have.ID
			// Graph resolves /users/{...} by object id or userPrincipalName,
			// never by an arbitrary mail attribute. Deleting by address would
			// either 404 or, worse, hit a different user whose UPN happens to
			// equal this address. Refuse rather than guess a delete target.
			if id == "" {
				return nil, fmt.Errorf(
					"domain %s: cannot prune mailbox %s: Microsoft Graph reported no object id for it, so mailctl will not guess a delete target",
					domainName, address)
			}
			actions = append(actions, plan.Action{
				Op:       plan.OpDelete,
				Resource: "mailbox",
				Domain:   d.Name,
				Provider: Name,
				Detail:   "delete mailbox " + address,
				Do: func(ctx context.Context) error {
					if err := p.client.Do(ctx, "DELETE", "/users/"+url.PathEscape(id), nil, nil); err != nil {
						return fmt.Errorf("domain %s: delete mailbox %s: %w", domainName, address, err)
					}
					return nil
				},
			})
		}
	}

	return actions, nil
}

// mailboxToLicense is a mailbox present in the tenant but not yet carrying
// its resolved licence's skuId; only assignLicense needs to run for it.
// heldSkuIDs is empty when the mailbox has no licence at all, and non-empty
// when it holds a different one — the distinction that keeps the plan's
// Detail text honest (see the loop in Plan that builds it).
type mailboxToLicense struct {
	box        config.Mailbox
	userID     string
	heldSkuIDs []string
}

// describeSkus renders a mailbox's held skuIds as their skuPartNumbers, for
// an operator-facing message. names is the domain's skuId-to-part-number
// reverse index; a skuId absent from it (a licence type the tenant used to
// have, or a stale read) falls back to the raw GUID rather than being
// dropped silently.
func describeSkus(names map[string]string, skuIDs []string) string {
	parts := make([]string, 0, len(skuIDs))
	for _, id := range skuIDs {
		if part, ok := names[id]; ok && part != "" {
			parts = append(parts, part)
			continue
		}
		parts = append(parts, id)
	}
	return strings.Join(parts, ", ")
}

// preferredAddress prefers a user's mail attribute, falling back to the
// userPrincipalName when mail is unset.
func preferredAddress(u graphUser) string {
	if u.Mail != "" {
		return u.Mail
	}
	return u.UserPrincipalName
}

// alternateAddress returns the identity attribute preferredAddress did not
// choose, when it is set and differs from the chosen one — the case an admin
// creates by changing a user's primary SMTP address or its
// userPrincipalName independently of the other.
func alternateAddress(u graphUser) string {
	if u.Mail == "" {
		return ""
	}
	if u.UserPrincipalName == "" || strings.EqualFold(u.UserPrincipalName, u.Mail) {
		return ""
	}
	return u.UserPrincipalName
}

// assignedSkuIDs extracts the skuIds Graph reports as already assigned to a
// user.
func assignedSkuIDs(u graphUser) []string {
	ids := make([]string, 0, len(u.AssignedLicenses))
	for _, lic := range u.AssignedLicenses {
		ids = append(ids, lic.SkuID)
	}
	return ids
}

// matchesManaged reports whether a tenant mailbox corresponds to one of the
// addresses in managed, checking both identity attributes Microsoft Graph can
// expose for one account so a mailbox is not mistaken for unmanaged (or
// managed) just because config named the attribute this mailbox does not
// display as its primary Address.
func matchesManaged(managed map[string]bool, box mail.Mailbox) bool {
	if managed[strings.ToLower(box.Address)] {
		return true
	}
	return box.AlternateAddress != "" && managed[strings.ToLower(box.AlternateAddress)]
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// effectiveLicense resolves the skuPartNumber a mailbox uses: its own
// override, or the domain's default. It returns "" when neither is set,
// including when d.Mail.MS365 is nil — a state Plan now refuses up front,
// but Actual's billing-hazard note (the loop above referencedLicenses) has
// no guard of its own and reaches this helper regardless. Every caller
// already treats "" as nothing to add: checkSeats skips a zero-count part,
// and the licence-held comparisons all gate on skuID != "".
func effectiveLicense(d config.Domain, box config.Mailbox) string {
	if box.License != "" {
		return box.License
	}
	if d.Mail.MS365 == nil {
		return ""
	}
	return d.Mail.MS365.License
}

// referencedLicenses returns every skuPartNumber this domain's config could
// need, deduplicated and sorted so Actual's notes are stable across runs.
func referencedLicenses(d config.Domain) []string {
	seen := map[string]bool{}
	if d.Mail.MS365 != nil && d.Mail.MS365.License != "" {
		seen[d.Mail.MS365.License] = true
	}
	for _, box := range d.Mailboxes {
		if box.License != "" {
			seen[box.License] = true
		}
	}
	out := make([]string, 0, len(seen))
	for part := range seen {
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}
