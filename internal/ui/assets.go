// Package ui embeds the built frontend bundle and serves it, including the
// single-page-app fallback for client-side routes.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// The bundle is committed so that `mailctl ui` behaves the same however the
// binary was installed: `go install` cannot run npm. CI rebuilds it and fails if
// the committed output differs from source.
//
//go:embed all:dist
var assets embed.FS

func assetHandler() (http.Handler, error) {
	sub, err := fs.Sub(assets, "dist")
	if err != nil {
		return nil, err
	}
	assetExts, err := collectExtensions(sub)
	if err != nil {
		return nil, err
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if clean == "" || clean == "." {
			clean = "index.html"
		}
		if _, err := fs.Stat(sub, clean); err == nil {
			files.ServeHTTP(w, r)
			return
		}
		// A request for something that looks like a real asset (an extension the
		// bundle actually serves, e.g. .js) is a genuine 404. Serving the HTML
		// shell for a missing .js would reach the browser as a script and fail
		// with an unrelated parse error. A route segment that merely contains a
		// dot — e.g. a domain name in /domains/example.com — is not an asset
		// extension we recognize, so it falls through to the SPA shell below.
		if assetExts[strings.ToLower(path.Ext(clean))] {
			http.NotFound(w, r)
			return
		}
		// Otherwise it is a client-side route: return the shell.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		files.ServeHTTP(w, r2)
	}), nil
}

// collectExtensions walks the embedded bundle once at startup and records the
// distinct file extensions it actually contains, so the handler can tell a
// missing real asset (404) apart from a client-side route that happens to
// contain a dot, such as a domain name.
func collectExtensions(sub fs.FS) (map[string]bool, error) {
	exts := make(map[string]bool)
	err := fs.WalkDir(sub, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if ext := path.Ext(p); ext != "" {
				exts[strings.ToLower(ext)] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return exts, nil
}
