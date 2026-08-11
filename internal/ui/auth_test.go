package ui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// reached is a marker only the guarded handler can write, so an acceptance
// test can tell "the middleware forwarded to next" apart from "the middleware
// wrote nothing at all" — a black-hole middleware that neither forbids nor
// forwards would otherwise still report 200 from httptest.NewRecorder's
// default status.
const reached = "reached"

func allowed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, reached)
	})
}

func TestNewAuthPanicsOnEmptyToken(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("newAuth(\"\", host) did not panic; an empty token must fail closed at construction")
		}
	}()
	newAuth("", "127.0.0.1:1234")
}

func TestAuthAcceptsTheTokenFromTheHeader(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/domains", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "secret")
	req.Header.Set("Origin", "http://127.0.0.1:1234")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a correctly authenticated request", rec.Code)
	}
	if rec.Body.String() != reached {
		t.Errorf("body = %q, want %q; the guard must have forwarded to next", rec.Body.String(), reached)
	}
}

// The launch URL carries the token as a query parameter so the browser can load
// the page; the app then sends it as a header.
func TestAuthAcceptsTheTokenFromTheQueryOnTheInitialLoad(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/?token=secret", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for the initial page load", rec.Code)
	}
	if rec.Body.String() != reached {
		t.Errorf("body = %q, want %q; the guard must have forwarded to next", rec.Body.String(), reached)
	}
}

func TestAuthRejectsEveryUnauthenticatedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"no token at all", func(r *http.Request) {}},
		{"wrong token", func(r *http.Request) { r.Header.Set("X-Mailctl-Token", "guess") }},
		{"empty token", func(r *http.Request) { r.Header.Set("X-Mailctl-Token", "") }},
		{"token that is a prefix of the real one", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secre")
		}},
		{"token that is a superstring of the real one", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secretx")
		}},
		{"foreign origin", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Header.Set("Origin", "http://evil.example")
		}},
		{"origin null, the sandboxed-iframe/data:/file: shape", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Header.Set("Origin", "null")
		}},
		{"origin differing only in scheme", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Header.Set("Origin", "https://127.0.0.1:1234")
		}},
		{"foreign host, the dns rebinding shape", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Host = "attacker.example"
		}},
		{"correct host, wrong port", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Host = "127.0.0.1:9999"
		}},
		{"token in the Authorization header instead", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer secret")
		}},
		{"token in a cookie instead", func(r *http.Request) {
			r.Header.Set("Cookie", "token=secret")
		}},
		{"token under an unsupported query key", func(r *http.Request) {
			q := r.URL.Query()
			q.Set("access_token", "secret")
			r.URL.RawQuery = q.Encode()
		}},
		{"duplicated header token, one correct one wrong", func(r *http.Request) {
			r.Header.Add("X-Mailctl-Token", "secret")
			r.Header.Add("X-Mailctl-Token", "guess")
		}},
		{"duplicated query token, one correct one wrong", func(r *http.Request) {
			q := r.URL.Query()
			q.Add("token", "secret")
			q.Add("token", "guess")
			r.URL.RawQuery = q.Encode()
		}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handler := newAuth("secret", "127.0.0.1:1234")(allowed())
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/plan", nil)
			req.Host = "127.0.0.1:1234"
			c.mutate(req)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403", rec.Code)
			}
		})
	}
}

// A rejection must not disclose the expected token, and must not echo the
// supplied one into a body an attacker can read.
func TestAuthRejectionRevealsNothing(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/api/plan", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "guess")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; the disclosure assertions below are meaningless if the request wasn't rejected", rec.Code)
	}
	for _, leak := range []string{"secret", "guess"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("rejection body contains %q: %s", leak, rec.Body.String())
		}
	}
}

// The query-parameter path must be guarded exactly as strictly as the header
// path: a wrong token in the query must be rejected too, not just accepted
// because it arrived via the URL instead of a header.
func TestAuthRejectsWrongTokenFromTheQuery(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:1234/?token=guess", nil)
	req.Host = "127.0.0.1:1234"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a wrong token supplied via the query", rec.Code)
	}
}

// The query fallback exists solely for the browser to load the launch URL. A
// POST carrying the correct token only in the query string must still be
// rejected: the query channel is reachable without a preflight and without an
// Origin header, so honouring it on a state-changing method would leave only
// token secrecy protecting every write.
func TestAuthRejectsPostWithOnlyQueryToken(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api/plan?token=secret", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("Origin", "http://127.0.0.1:1234")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a POST authenticated only via the query token", rec.Code)
	}
}

// Browsers send Origin on every state-changing request, same-origin included,
// so a POST with a correct token but no Origin at all must still be rejected
// — otherwise a caller that simply never sets Origin gets a free pass that a
// real browser request never needs.
func TestAuthRejectsNonSafeMethodWithNoOrigin(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api/plan", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("X-Mailctl-Token", "secret")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a POST with no Origin", rec.Code)
	}
}

// Every other rejection case in this file is a GET; this pins that a
// state-changing method with no token at all is guarded too.
func TestAuthRejectsNonSafeMethodWithNoToken(t *testing.T) {
	handler := newAuth("secret", "127.0.0.1:1234")(allowed())

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:1234/api/plan", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set("Origin", "http://127.0.0.1:1234")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a POST with no token", rec.Code)
	}
}
