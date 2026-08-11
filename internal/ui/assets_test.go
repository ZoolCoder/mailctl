package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAssetHandlerServesTheIndex(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("body does not look like the app shell: %s", rec.Body.String())
	}
}

// A single-page app owns its routes, so an unknown non-API path must return the
// shell rather than a 404 the user would see as a broken page.
func TestUnknownPathFallsBackToTheIndex(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/domains/example.com", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 with the app shell", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("body does not look like the app shell: %s", rec.Body.String())
	}
}

// Every browser requests /favicon.ico on first paint, shaped as a subresource
// fetch that explicitly does not accept HTML. It must 404, not receive the
// app shell — the bundle doesn't ship an .ico, so the extension-set check
// alone can't classify it; this exercises the Accept-based fallback.
func TestFaviconMissIsNotGivenTheHTMLShell(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	req.Header.Set("Accept", "image/avif,image/webp,*/*")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for a missing favicon, want 404", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<div id=\"app\"") {
		t.Errorf("favicon miss was served the app shell: %s", rec.Body.String())
	}
}

// A missing asset under a path that looks like a real file should 404 rather
// than silently returning HTML, which would otherwise reach the browser as a
// script and fail with a confusing parse error.
func TestMissingAssetIsNotGivenTheHTMLShell(t *testing.T) {
	handler, err := assetHandler()
	if err != nil {
		t.Fatalf("assetHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/absent.js", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d for a missing .js asset, want 404", rec.Code)
	}
}
