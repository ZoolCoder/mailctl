package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func allowed() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
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
		{"foreign origin", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Header.Set("Origin", "http://evil.example")
		}},
		{"foreign host, the dns rebinding shape", func(r *http.Request) {
			r.Header.Set("X-Mailctl-Token", "secret")
			r.Host = "attacker.example"
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
