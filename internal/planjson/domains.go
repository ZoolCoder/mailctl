package planjson

import "github.com/zoolcoder/mailctl/internal/config"

// Domains is `mailctl domains -json`: the config as mailctl resolved it, per
// domain. It names the environment variable a credential comes from and
// never a value.
type Domains struct {
	SchemaVersion int      `json:"schemaVersion"`
	Domains       []Domain `json:"domains"`
}

type Domain struct {
	Name           string         `json:"name"`
	Zone           string         `json:"zone"`
	Providers      []string       `json:"providers"`
	Mailboxes      []Mailbox      `json:"mailboxes"`
	Aliases        []Alias        `json:"aliases"`
	CatchAll       *CatchAll      `json:"catchAll,omitempty"` // absent: left alone
	Deliverability Deliverability `json:"deliverability"`
}

type Mailbox struct {
	Address string `json:"address"`
	// PasswordEnv names where the credential comes from; empty means mailctl
	// generates one when it creates the mailbox.
	PasswordEnv string `json:"passwordEnv,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	License     string `json:"license,omitempty"`
	Recovery    int    `json:"recovery"`
}

type Alias struct {
	Match string   `json:"match"`
	To    []string `json:"to"`
}

type CatchAll struct {
	To []string `json:"to"`
}

type Deliverability struct {
	SPFIncludes []string `json:"spfIncludes"`
	DMARC       *DMARC   `json:"dmarc,omitempty"`
	MTASts      *MTASts  `json:"mtaSts,omitempty"`
	TLSRpt      string   `json:"tlsRpt,omitempty"`
	BIMI        *BIMI    `json:"bimi,omitempty"`
}

type DMARC struct {
	Policy          string `json:"policy"`
	SubdomainPolicy string `json:"subdomainPolicy,omitempty"`
	Pct             int    `json:"pct,omitempty"`
	RUA             string `json:"rua,omitempty"`
	RUF             string `json:"ruf,omitempty"`
}

type MTASts struct {
	Mode   string `json:"mode"`
	MaxAge int    `json:"maxAge,omitempty"`
	Deploy bool   `json:"deploy"`
}

type BIMI struct {
	Logo string `json:"logo"`
	VMC  string `json:"vmc,omitempty"`
}

func FromDomains(domains []config.Domain) Domains {
	out := Domains{SchemaVersion: SchemaVersion, Domains: make([]Domain, 0, len(domains))}
	for _, d := range domains {
		out.Domains = append(out.Domains, fromDomain(d))
	}
	return out
}

func fromDomain(d config.Domain) Domain {
	zone := d.ZoneName
	if zone == "" {
		zone = d.Name
	}
	out := Domain{
		Name:      d.Name,
		Zone:      zone,
		Providers: nonNil(d.Mail.Providers),
		Mailboxes: make([]Mailbox, 0, len(d.Mailboxes)),
		Aliases:   make([]Alias, 0, len(d.Aliases)),
	}
	for _, m := range d.Mailboxes {
		out.Mailboxes = append(out.Mailboxes, Mailbox{Address: m.Address, PasswordEnv: m.PasswordEnv,
			DisplayName: m.DisplayName, License: m.License, Recovery: len(m.Recovery)})
	}
	for _, a := range d.Aliases {
		out.Aliases = append(out.Aliases, Alias{Match: a.Match, To: nonNil(a.To)})
	}
	if d.CatchAll != nil {
		out.CatchAll = &CatchAll{To: nonNil(d.CatchAll.To)}
	}
	del := d.Deliverability
	out.Deliverability = Deliverability{SPFIncludes: nonNil(del.SPFIncludes), TLSRpt: del.TLSRpt}
	if del.DMARC != nil {
		out.Deliverability.DMARC = &DMARC{Policy: del.DMARC.Policy, SubdomainPolicy: del.DMARC.SubdomainPolicy,
			Pct: del.DMARC.Pct, RUA: del.DMARC.RUA, RUF: del.DMARC.RUF}
	}
	if del.MTASts != nil {
		out.Deliverability.MTASts = &MTASts{Mode: del.MTASts.Mode, MaxAge: del.MTASts.MaxAge, Deploy: del.MTASts.Deploy}
	}
	if del.BIMI != nil {
		out.Deliverability.BIMI = &BIMI{Logo: del.BIMI.Logo, VMC: del.BIMI.VMC}
	}
	return out
}

// nonNil keeps an empty list as [] in JSON, never null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
