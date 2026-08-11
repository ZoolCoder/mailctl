package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/zoolcoder/mailctl/internal/audit"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/engine"
	"github.com/zoolcoder/mailctl/internal/ui"
)

// serveUI runs the local UI until the context is cancelled. It is a foreground
// server on purpose: mailctl has no daemon and no state file, because the live
// provider APIs are the state. Nothing here writes to disk.
func serveUI(ctx context.Context, runner *engine.Engine, addr string, openBrowser bool, stdout io.Writer) error {
	// Port 0 lets the kernel choose, so two instances cannot collide and the
	// port is not guessable by something scanning a fixed one.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer func() { _ = listener.Close() }()

	token, err := newToken()
	if err != nil {
		return err
	}

	host := listener.Addr().String()
	handler, err := ui.New(ui.Deps{
		Token:   token,
		Host:    host,
		Planner: runner,
		Audit: func(ctx context.Context, d config.Domain, desired []dns.Record) audit.Report {
			return audit.Run(ctx, d, desired, audit.NetResolver(), audit.HTTPFetcher())
		},
	})
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://%s/?token=%s", host, token)
	// The token is in the URL the operator needs, so this line is the one place
	// it is printed. It authenticates a browser to this process and is not a
	// provider credential.
	fmt.Fprintf(stdout, "mailctl ui listening on %s\n", url)
	fmt.Fprintln(stdout, "press Ctrl-C to stop")

	if openBrowser {
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
		// middleware including the auth guard in internal/ui. That would let
		// an unauthenticated "OPTIONS * HTTP/1.1" through regardless of
		// token or Host. Disabling it routes that request through the normal
		// handler chain like anything else.
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

func newToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate ui token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
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
