package purelymail

import (
	"context"
	"encoding/json"
)

type Domain struct {
	Name                  string     `json:"name"`
	AllowAccountReset     bool       `json:"allowAccountReset"`
	SymbolicSubaddressing bool       `json:"symbolicSubaddressing"`
	IsShared              bool       `json:"isShared"`
	DNSSummary            DNSSummary `json:"dnsSummary"`
}

type DNSSummary struct {
	PassesMX    bool `json:"passesMx"`
	PassesSPF   bool `json:"passesSpf"`
	PassesDKIM  bool `json:"passesDkim"`
	PassesDMARC bool `json:"passesDmarc"`
}

// NewUser is the createUser request. Every field is sent, matching the field
// set the previous mailsetup tool used successfully against the live API; the
// published OpenAPI description of this endpoint is incomplete.
type NewUser struct {
	UserName                 string `json:"userName"`
	DomainName               string `json:"domainName"`
	Password                 string `json:"password"`
	EnablePasswordReset      bool   `json:"enablePasswordReset"`
	EnableSearchIndexing     bool   `json:"enableSearchIndexing"`
	SendWelcomeEmail         bool   `json:"sendWelcomeEmail"`
	RecoveryEmail            string `json:"recoveryEmail,omitempty"`
	RecoveryEmailDescription string `json:"recoveryEmailDescription,omitempty"`
	RecoveryPhone            string `json:"recoveryPhone,omitempty"`
	RecoveryPhoneDescription string `json:"recoveryPhoneDescription,omitempty"`
}

// UserChanges is the modifyUser request. Pointer fields are omitted when nil so
// a change to one setting never resets another.
type UserChanges struct {
	UserName                       string  `json:"userName"`
	NewPassword                    *string `json:"newPassword,omitempty"`
	EnablePasswordReset            *bool   `json:"enablePasswordReset,omitempty"`
	EnableSearchIndexing           *bool   `json:"enableSearchIndexing,omitempty"`
	RequireTwoFactorAuthentication *bool   `json:"requireTwoFactorAuthentication,omitempty"`
}

// ResetMethod is one password-reset method. ID is json.Number because the
// live shape has never been verified and Purelymail may return it as either a
// quoted string or a bare number; json.Number decodes both.
type ResetMethod struct {
	ID          json.Number `json:"id,omitempty"`
	Type        string      `json:"type"`
	Target      string      `json:"target"`
	Description string      `json:"description,omitempty"`
}

type RoutingRule struct {
	ID              int      `json:"id,omitempty"`
	DomainName      string   `json:"domainName"`
	MatchUser       string   `json:"matchUser"`
	Prefix          bool     `json:"prefix"`
	TargetAddresses []string `json:"targetAddresses"`
	Catchall        bool     `json:"catchall"`
}

// GetOwnershipCode returns the TXT value proving domain ownership.
func (c *Client) GetOwnershipCode(ctx context.Context) (string, error) {
	var out struct {
		Code string `json:"code"`
	}
	if err := c.post(ctx, "getOwnershipCode", nil, &out); err != nil {
		return "", err
	}
	return out.Code, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	var out struct {
		Domains []Domain `json:"domains"`
	}
	if err := c.post(ctx, "listDomains", map[string]any{"includeShared": false}, &out); err != nil {
		return nil, err
	}
	return out.Domains, nil
}

func (c *Client) AddDomain(ctx context.Context, domain string) error {
	return c.post(ctx, "addDomain", map[string]any{"domainName": domain}, nil)
}

func (c *Client) DeleteDomain(ctx context.Context, domain string) error {
	return c.post(ctx, "deleteDomain", map[string]any{"name": domain}, nil)
}

// UpdateDomainSettings changes domain-level settings. Pass recheckDNS to make
// Purelymail re-read the zone after records have been published.
func (c *Client) UpdateDomainSettings(ctx context.Context, domain string, allowReset, symbolic *bool, recheckDNS bool) error {
	body := map[string]any{"name": domain}
	if allowReset != nil {
		body["allowAccountReset"] = *allowReset
	}
	if symbolic != nil {
		body["symbolicSubaddressing"] = *symbolic
	}
	if recheckDNS {
		body["recheckDns"] = true
	}
	return c.post(ctx, "updateDomainSettings", body, nil)
}

// ListUsers returns every mailbox address on the account.
func (c *Client) ListUsers(ctx context.Context) ([]string, error) {
	var out struct {
		Users []string `json:"users"`
	}
	if err := c.post(ctx, "listUser", nil, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

func (c *Client) CreateUser(ctx context.Context, u NewUser) error {
	return c.post(ctx, "createUser", u, nil)
}

func (c *Client) ModifyUser(ctx context.Context, changes UserChanges) error {
	return c.post(ctx, "modifyUser", changes, nil)
}

func (c *Client) DeleteUser(ctx context.Context, address string) error {
	return c.post(ctx, "deleteUser", map[string]any{"userName": address}, nil)
}

func (c *Client) ListPasswordReset(ctx context.Context, address string) ([]ResetMethod, error) {
	var out struct {
		Methods []ResetMethod `json:"methods"`
	}
	if err := c.post(ctx, "listPasswordReset", map[string]any{"userName": address}, &out); err != nil {
		return nil, err
	}
	return out.Methods, nil
}

func (c *Client) UpsertPasswordReset(ctx context.Context, address string, m ResetMethod) error {
	body := map[string]any{
		"userName":    address,
		"type":        m.Type,
		"target":      m.Target,
		"description": m.Description,
	}
	if m.ID != "" {
		body["id"] = m.ID.String()
	}
	return c.post(ctx, "upsertPasswordReset", body, nil)
}

func (c *Client) DeletePasswordReset(ctx context.Context, address, id string) error {
	return c.post(ctx, "deletePasswordReset", map[string]any{"userName": address, "id": id}, nil)
}

func (c *Client) ListRoutingRules(ctx context.Context) ([]RoutingRule, error) {
	var out struct {
		Rules []RoutingRule `json:"rules"`
	}
	if err := c.post(ctx, "listRoutingRules", nil, &out); err != nil {
		return nil, err
	}
	return out.Rules, nil
}

func (c *Client) CreateRoutingRule(ctx context.Context, rule RoutingRule) error {
	return c.post(ctx, "createRoutingRule", map[string]any{
		"domainName":      rule.DomainName,
		"matchUser":       rule.MatchUser,
		"prefix":          rule.Prefix,
		"targetAddresses": rule.TargetAddresses,
		"catchall":        rule.Catchall,
	}, nil)
}

func (c *Client) DeleteRoutingRule(ctx context.Context, id int) error {
	return c.post(ctx, "deleteRoutingRule", map[string]any{"routingRuleId": id}, nil)
}

// CreateAppPassword returns a credential that is shown exactly once. There is
// no endpoint to list or re-read it, which is why app credentials are an
// imperative subcommand rather than part of the reconciled config.
func (c *Client) CreateAppPassword(ctx context.Context, address, name string) (string, error) {
	var out struct {
		AppPassword string `json:"appPassword"`
	}
	body := map[string]any{"userName": address}
	if name != "" {
		body["name"] = name
	}
	if err := c.post(ctx, "createAppPassword", body, &out); err != nil {
		return "", err
	}
	return out.AppPassword, nil
}

func (c *Client) DeleteAppPassword(ctx context.Context, address, name string) error {
	return c.post(ctx, "deleteAppPassword", map[string]any{"userName": address, "name": name}, nil)
}

// CheckAccountCredit returns the account's remaining credit as Purelymail
// reports it. The audit command surfaces this.
func (c *Client) CheckAccountCredit(ctx context.Context) (string, error) {
	var out struct {
		Credit string `json:"credit"`
	}
	if err := c.post(ctx, "checkAccountCredit", nil, &out); err != nil {
		return "", err
	}
	return out.Credit, nil
}
