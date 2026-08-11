package ui

import (
	"crypto/subtle"
	"net/http"
)

// newAuth guards every route. Three things must hold: the request carries the
// per-process token exactly once, its Host is the address we are actually
// listening on, and its Origin — mandatory on every state-changing method,
// absent only because a browser omits it on a safe top-level navigation — is
// ours.
//
// The Host check defends against a browser: DNS rebinding lets an
// attacker-controlled name resolve to 127.0.0.1, and in that attack the
// browser still sends the foreign Host it was told to use. It does not, and
// is not meant to, defend against a local process constructing an
// absolute-form request-target that overrides Host parsing — no browser can
// produce that shape, and a local process gains nothing from it, since it
// already has an unauthenticated path straight to this port. Stopping a
// local process is the token's job, not the Host check's.
//
// token must be non-empty. An empty token would make the constant-time
// compare below vacuously true for a request carrying no credential at all,
// so newAuth fails closed at construction time instead of at request time.
func newAuth(token, host string) func(http.Handler) http.Handler {
	if token == "" {
		panic("ui: newAuth requires a non-empty token")
	}

	expectedOrigin := "http://" + host

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				forbid(w)
				return
			}

			// A missing Origin is unavoidable on a safe top-level navigation
			// (the browser doesn't send one there), but browsers send Origin on
			// every state-changing request, same-origin included, so requiring
			// it there costs the real app nothing and closes a free pass for a
			// caller that simply never sets Origin.
			origin := r.Header.Get("Origin")
			switch {
			case origin != "" && origin != expectedOrigin:
				forbid(w)
				return
			case origin == "" && r.Method != http.MethodGet && r.Method != http.MethodHead:
				forbid(w)
				return
			}

			// A repeated header or query value is the classic smuggling
			// primitive should a proxy that prefers the last value ever end up
			// in front of this server; reject outright rather than pick one.
			if len(r.Header.Values("X-Mailctl-Token")) > 1 || len(r.URL.Query()["token"]) > 1 {
				forbid(w)
				return
			}

			// The query fallback exists only so the launch URL is openable in a
			// browser tab; it is deliberately not honoured beyond that one
			// shape. <img>, <script>, <link>, <iframe>, and top-level
			// navigation all reach a query parameter with no preflight and no
			// Origin header, so widening this to every method or every Accept
			// type would leave only token secrecy standing between any open
			// tab and the API.
			supplied := r.Header.Get("X-Mailctl-Token")
			if supplied == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && acceptsHTML(r) {
				supplied = r.URL.Query().Get("token")
			}
			// Constant time so the comparison cannot be used as a timing
			// oracle. The length check is fine to short-circuit on: it leaks
			// nothing an attacker doesn't already know (the token length is
			// not the secret, its value is), and ConstantTimeCompare itself
			// requires equal-length inputs to be meaningful.
			if len(supplied) != len(token) ||
				subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) != 1 {
				forbid(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// forbid says nothing about why. Naming the expected value, or echoing the
// supplied one, would hand an attacker the thing they are probing for. It also
// must not log: the supplied token is a credential candidate and belongs
// nowhere but this comparison.
func forbid(w http.ResponseWriter) {
	http.Error(w, "forbidden", http.StatusForbidden)
}
