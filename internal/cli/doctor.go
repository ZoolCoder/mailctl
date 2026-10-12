package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/mail/purelymail"
	"github.com/zoolcoder/mailctl/internal/planjson"
)

// The network checks are reached through these so tests stay offline.
var (
	verifyCloudflare = func(ctx context.Context, cfg config.Config, token string) error {
		return cfapi.New(cfg.Cloudflare.BaseURL, token).Do(ctx, "GET", "/user/tokens/verify", nil, nil)
	}
	verifyPurelymail = func(ctx context.Context, cfg config.Config, token string) error {
		_, err := purelymail.NewClient(cfg.Purelymail.BaseURL, token).CheckAccountCredit(ctx)
		return err
	}
	lookupNS = func(ctx context.Context, zone string) error {
		_, err := net.DefaultResolver.LookupNS(ctx, zone)
		return err
	}
)

const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	SchemaVersion int           `json:"schemaVersion"`
	Version       string        `json:"version"`
	Checks        []doctorCheck `json:"checks"`
}

// runDoctor checks everything mailctl needs before it can plan: the binary,
// the config, each credential and where it came from, and the provider APIs.
// It reads only; no check changes provider state.
func runDoctor(cfgPath, cfgSource string, asJSON bool, stdout io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report := doctorReport{SchemaVersion: planjson.SchemaVersion, Version: buildVersion()}
	add := func(name, status, detail string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Detail: detail})
	}

	status, detail := binaryStatus()
	add("binary", status, detail)
	if keychainAvailable() {
		add("keychain", checkOK, "available, service mailctl")
	} else {
		add("keychain", checkWarn, "not available; credentials come from the environment only")
	}

	cfg, ok := doctorConfig(cfgPath, cfgSource, add)
	if ok {
		doctorCredentials(ctx, cfg, add)
		for _, d := range cfg.Domains {
			zone := d.ZoneName
			if zone == "" {
				zone = d.Name
			}
			if err := lookupNS(ctx, zone); err != nil {
				add("dns "+zone, checkFail, err.Error())
			} else {
				add("dns "+zone, checkOK, "NS records resolve")
			}
		}
	}

	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		for _, c := range report.Checks {
			fmt.Fprintf(stdout, "%-4s  %-28s %s\n", c.Status, c.Name, c.Detail)
		}
	}
	if slices.ContainsFunc(report.Checks, func(c doctorCheck) bool { return c.Status == checkFail }) {
		return errors.New("doctor found problems")
	}
	return nil
}

func binaryStatus() (string, string) {
	self, err := os.Executable()
	if err != nil {
		return checkWarn, err.Error()
	}
	onPath, err := exec.LookPath("mailctl")
	if err != nil {
		return checkWarn, self + " (mailctl is not on PATH)"
	}
	return checkOK, self + " (PATH: " + onPath + ")"
}

func doctorConfig(cfgPath, cfgSource string, add func(name, status, detail string)) (config.Config, bool) {
	if cfgSource == "" {
		add("config", checkFail, errNoConfig().Error())
		return config.Config{}, false
	}
	cfg, err := config.Load(cfgPath, getenv)
	if err != nil {
		add("config", checkFail, err.Error())
		return config.Config{}, false
	}
	add("config", checkOK, fmt.Sprintf("%s (from %s), %d domain(s)", cfgPath, cfgSource, len(cfg.Domains)))
	return cfg, true
}

// doctorCredentials reports where each needed credential comes from, never
// its value, then proves the provider tokens with one read-only call each.
func doctorCredentials(ctx context.Context, cfg config.Config, add func(name, status, detail string)) {
	credential := func(name string) string {
		value, source := lookupCredential(name)
		if value == "" {
			add(name, checkFail, "set nowhere: export it or store it in the Keychain")
		} else {
			add(name, checkOK, "from "+source)
		}
		return value
	}

	if token := credential("CLOUDFLARE_API_TOKEN"); token != "" {
		apiCheck(add, "cloudflare api", verifyCloudflare(ctx, cfg, token))
	}
	if usesProvider(cfg, "purelymail") {
		if token := credential("PURELYMAIL_API_TOKEN"); token != "" {
			apiCheck(add, "purelymail api", verifyPurelymail(ctx, cfg, token))
		}
	}
	if usesProvider(cfg, "ms365") {
		for _, name := range []string{"MS365_TENANT_ID", "MS365_CLIENT_ID", "MS365_CLIENT_SECRET"} {
			credential(name)
		}
	}
	for _, d := range cfg.Domains {
		for _, m := range d.Mailboxes {
			if m.PasswordEnv == "" {
				continue
			}
			if value, source := lookupCredential(m.PasswordEnv); value == "" {
				add(m.PasswordEnv, checkWarn, m.Address+": set nowhere")
			} else {
				add(m.PasswordEnv, checkOK, m.Address+": from "+source)
			}
		}
	}
}

func apiCheck(add func(name, status, detail string), name string, err error) {
	if err != nil {
		add(name, checkFail, err.Error())
		return
	}
	add(name, checkOK, "token accepted")
}

func usesProvider(cfg config.Config, provider string) bool {
	for _, d := range cfg.Domains {
		if slices.Contains(d.Mail.Providers, provider) {
			return true
		}
	}
	return false
}
