package ui

import (
	"crypto/subtle"
	"net/http"
)

// newAuth guards every route. Three things must hold: the request carries the
// per-process token, its Host is the address we are actually listening on, and
// its Origin — when the browser sends one — is ours.
//
// The Host and Origin checks are not belt-and-braces. A local listener is
// reachable by any process on the machine and by any page in any open tab, and
// DNS rebinding lets an attacker-controlled name resolve to 127.0.0.1. In that
// attack the browser sends a foreign Origin and a foreign Host, which is exactly
// what these two checks catch.
func newAuth(token, host string) func(http.Handler) http.Handler {
	expectedOrigin := "http://" + host

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != host {
				forbid(w)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && origin != expectedOrigin {
				forbid(w)
				return
			}
			supplied := r.Header.Get("X-Mailctl-Token")
			if supplied == "" {
				supplied = r.URL.Query().Get("token")
			}
			// Constant time so the comparison cannot be used as a timing oracle.
			// The length check is fine to short-circuit on: it leaks nothing an
			// attacker doesn't already know (the token length is not a secret
			// worth protecting), and ConstantTimeCompare itself requires equal
			// lengths to be meaningful.
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
