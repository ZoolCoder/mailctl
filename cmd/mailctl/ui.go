package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/ui"
	"github.com/zoolcoder/zcadmin"
	"github.com/zoolcoder/zcadmin/auth"
)

// uiOptions is what the ui command takes from its flags.
type uiOptions struct {
	addr        string
	insecure    bool
	dataDir     string
	configPath  string
	openBrowser bool
}

// serveUI runs the local admin page until the context is cancelled. It is a
// foreground server on purpose: mailctl has no daemon, because the live
// provider APIs are the state. The only things it writes are the password
// hash and the activity log, under the data directory.
func serveUI(ctx context.Context, runner ui.Planner, opts uiOptions, stdout io.Writer) error {
	if err := loopbackOnly(opts.addr, opts.insecure); err != nil {
		return err
	}
	dataDir := opts.dataDir
	if dataDir == "" {
		dataDir = filepath.Dir(auth.DefaultFile("mailctl"))
	}

	// Port 0 lets the kernel choose, so two instances cannot collide and the
	// port is not guessable by something scanning a fixed one.
	listener, err := net.Listen("tcp", opts.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", opts.addr, err)
	}
	defer func() { _ = listener.Close() }()

	host := listener.Addr().String()
	handler, err := ui.New(ui.Deps{
		Planner:    runner,
		Audit:      liveAudit,
		Passwords:  auth.FileStore{Path: filepath.Join(dataDir, "auth.json")},
		Activity:   &zcadmin.ActivityLog{Path: filepath.Join(dataDir, "activity.jsonl")},
		ConfigPath: opts.configPath,
		DataDir:    dataDir,
		Host:       host,
		Getenv:     os.Getenv,
		Now:        time.Now,
	})
	if err != nil {
		return err
	}

	url := "http://" + host + "/"
	fmt.Fprintf(stdout, "mailctl ui on %s — first visit sets the password; Ctrl-C to stop\n", url)

	if opts.openBrowser {
		// A browser that will not open is not a reason to fail: the URL is
		// already printed above.
		_ = browse(url)
	}

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// Go's net/http special-cases a request whose target is the literal
		// "*" with method OPTIONS: by default it is answered 200 by an
		// internal handler before Handler ever sees it, bypassing every
		// middleware including the login guard. Disabling it routes that
		// request through the normal handler chain like anything else.
		DisableGeneralOptionsHandler: true,
	}
	errs := make(chan error, 1)
	go func() { errs <- server.Serve(listener) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// liveAudit is the real auditor: a real resolver and a real HTTP fetcher.
func liveAudit(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report {
	return audit.Run(ctx, d, desired, audit.NetResolver(), audit.HTTPFetcher())
}

// loopbackOnly refuses to expose the page — and the provider credentials
// behind it — to anything but this machine, unless told twice. The page has
// a login, but a password on a public port is a weaker promise than "only
// this machine can reach it", and the operator should say so explicitly.
func loopbackOnly(addr string, insecure bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-addr %q: %w", addr, err)
	}
	if insecure || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("-addr %q is not loopback; pass -insecure if you mean to expose the page beyond this machine", addr)
}

func browse(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// unconfiguredPlanner is the ui's Planner when no Cloudflare token is set:
// it lists the config's domains so every page renders, and every call that
// would reach a provider returns the one error that explains the fix.
type unconfiguredPlanner struct {
	cfg     config.Config
	domains domainList
	err     error
}

func (u unconfiguredPlanner) Domains() ([]config.Domain, error) {
	var out []config.Domain
	for _, d := range u.cfg.Domains {
		if len(u.domains) == 0 || slices.Contains(u.domains, d.Name) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (u unconfiguredPlanner) Plan(context.Context) (plan.Plan, error) { return plan.Plan{}, u.err }

func (u unconfiguredPlanner) Desired(context.Context, config.Domain) ([]dns.Record, error) {
	return nil, u.err
}
