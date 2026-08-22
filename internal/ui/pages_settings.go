package ui

// Settings: the password, and where things are. The config path and the
// credential environment variables come from the command line and the
// environment; this page shows whether each credential is present and never
// its value.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/zcadmin"
)

// credential is one provider environment variable and whether it is set.
type credential struct {
	Env    string
	Set    bool
	Needed bool   // a configured domain uses the provider that reads it
	For    string // which provider reads it
}

type settingsPage struct {
	chrome
	ConfigPath   string
	DataDir      string
	ActivityPath string
	Credentials  []credential
}

func (s *Server) settingsData(r *http.Request) settingsPage {
	p := settingsPage{chrome: s.chrome(r, "settings"), ConfigPath: s.deps.ConfigPath, DataDir: s.deps.DataDir}
	if s.deps.Activity != nil {
		p.ActivityPath = s.deps.Activity.Path
	}
	used := map[string]bool{}
	if domains, err := s.deps.Planner.Domains(); err == nil {
		for _, d := range domains {
			for _, name := range d.Mail.Providers {
				used[name] = true
			}
		}
	}
	for _, c := range []credential{
		{Env: "CLOUDFLARE_API_TOKEN", Needed: true, For: "cloudflare dns, cfrouting, cfsending"},
		{Env: "PURELYMAIL_API_TOKEN", Needed: used["purelymail"], For: "purelymail"},
		{Env: "MS365_TENANT_ID", Needed: used["ms365"], For: "ms365"},
		{Env: "MS365_CLIENT_ID", Needed: used["ms365"], For: "ms365"},
		{Env: "MS365_CLIENT_SECRET", Needed: used["ms365"], For: "ms365"},
	} {
		c.Set = s.deps.Getenv(c.Env) != ""
		p.Credentials = append(p.Credentials, c)
	}
	return p
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "settings.html", s.settingsData(r))
}

func (s *Server) settingsPassword(w http.ResponseWriter, r *http.Request) {
	if err := s.auth.ChangePassword(r.FormValue("current"), r.FormValue("password"), r.FormValue("confirm")); err != nil {
		zcadmin.Back(w, r, "/settings", "", err)
		return
	}
	zcadmin.Back(w, r, "/settings", "password changed — other browsers stay signed in until the server restarts", nil)
}

// domainSettings flattens the provider-level settings a domain declares.
func domainSettings(d config.Domain) []kv {
	var out []kv
	if v := d.Mail.Settings.AllowAccountReset; v != nil {
		out = append(out, kv{"allowAccountReset", strconv.FormatBool(*v)})
	}
	if v := d.Mail.Settings.SymbolicSubaddressing; v != nil {
		out = append(out, kv{"symbolicSubaddressing", strconv.FormatBool(*v)})
	}
	if m := d.Mail.MS365; m != nil {
		if m.License != "" {
			out = append(out, kv{"ms365 license", m.License})
		}
		if m.UsageLocation != "" {
			out = append(out, kv{"ms365 usageLocation", m.UsageLocation})
		}
		if len(m.DKIMCnames) > 0 {
			out = append(out, kv{"ms365 dkimCnames", strings.Join(m.DKIMCnames, ", ")})
		}
	}
	return out
}

// deliverabilityPolicy flattens the deliverability block into rows.
func deliverabilityPolicy(d config.Domain) []kv {
	var out []kv
	del := d.Deliverability
	if len(del.SPFIncludes) > 0 {
		out = append(out, kv{"SPF includes", strings.Join(del.SPFIncludes, ", ")})
	}
	if m := del.DMARC; m != nil {
		v := "p=" + m.Policy
		if m.SubdomainPolicy != "" {
			v += " sp=" + m.SubdomainPolicy
		}
		if m.Pct != 0 {
			v += " pct=" + strconv.Itoa(m.Pct)
		}
		if m.RUA != "" {
			v += " rua=" + m.RUA
		}
		if m.RUF != "" {
			v += " ruf=" + m.RUF
		}
		out = append(out, kv{"DMARC", v})
	}
	if m := del.MTASts; m != nil {
		v := "mode " + m.Mode
		if m.MaxAge != 0 {
			v += ", max_age " + strconv.Itoa(m.MaxAge)
		}
		if m.Deploy {
			v += ", policy deployed by mailctl"
		}
		out = append(out, kv{"MTA-STS", v})
	}
	if del.TLSRpt != "" {
		out = append(out, kv{"TLS-RPT", del.TLSRpt})
	}
	if b := del.BIMI; b != nil {
		v := b.Logo
		if b.VMC != "" {
			v += " (VMC " + b.VMC + ")"
		}
		out = append(out, kv{"BIMI", v})
	}
	return out
}
