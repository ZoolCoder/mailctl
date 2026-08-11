package cfapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type zone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestDoSendsBearerTokenAndDecodesResult(t *testing.T) {
	var gotAuth, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"z1","name":"a.com"}}`)
	}))
	defer server.Close()

	var got zone
	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones",
		map[string]any{"name": "a.com"}, &got)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want Bearer tok", gotAuth)
	}
	if !strings.Contains(gotBody, `"name":"a.com"`) {
		t.Errorf("body = %q, want the marshalled payload", gotBody)
	}
	if got.ID != "z1" {
		t.Errorf("result id = %q, want z1", got.ID)
	}
}

func TestDoSurfacesCloudflareErrorMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":81057,"message":"Record already exists."}]}`)
	}))
	defer server.Close()

	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones/z1/dns_records", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Record already exists.") || !strings.Contains(err.Error(), "81057") {
		t.Errorf("error should carry Cloudflare's own text and code; got %q", err)
	}
}

func TestListFollowsPagination(t *testing.T) {
	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		body := map[string]any{
			"success":     true,
			"errors":      []any{},
			"result":      []zone{{ID: "z" + page, Name: page + ".com"}},
			"result_info": map[string]int{"page": len(pages), "total_pages": 3},
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()

	got, err := List[zone](context.Background(), New(server.URL, "tok"), "/zones")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d zones across pages, want 3", len(got))
	}
	if len(pages) != 3 || pages[0] != "1" || pages[2] != "3" {
		t.Errorf("requested pages = %v, want 1,2,3", pages)
	}
}

func TestListPreservesExistingQueryString(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	if _, err := List[zone](context.Background(), New(server.URL, "tok"), "/zones?name=a.com"); err != nil {
		t.Fatalf("List: %v", err)
	}
	if !strings.Contains(gotQuery, "name=a.com") || !strings.Contains(gotQuery, "page=1") {
		t.Errorf("query = %q, want both the caller filter and the page parameter", gotQuery)
	}
}

func TestDoDetectsNonSuccessStatusDespiteSuccessTrue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":null}`)
	}))
	defer server.Close()

	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones", nil, nil)
	if err == nil {
		t.Fatal("expected an error for non-2xx status despite success: true")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "502") || !strings.Contains(errMsg, "despite reporting success") {
		t.Errorf("error should contain status and indicate unexpected status despite success; got %q", errMsg)
	}
}

func TestDoSurfacesUnparseableBodyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `<html>502 Bad Gateway</html>`)
	}))
	defer server.Close()

	err := New(server.URL, "tok").Do(context.Background(), http.MethodPost, "/zones", nil, nil)
	if err == nil {
		t.Fatal("expected an error for non-2xx status with unparseable body")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "502") || !strings.Contains(errMsg, "Bad Gateway") {
		t.Errorf("error should contain status and body; got %q", errMsg)
	}
}

func TestMultipartSendsPartsCorrectly(t *testing.T) {
	var gotContentType string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		var err error
		gotBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		fmt.Fprint(w, `{"success":true,"errors":[],"result":null}`)
	}))
	defer server.Close()

	parts := []Part{
		{Name: "metadata", ContentType: "application/json", Data: []byte(`{"version":"1.0"}`)},
		{Name: "script", Filename: "main.js", ContentType: "application/javascript", Data: []byte(`console.log("hello");`)},
	}
	err := New(server.URL, "tok").Multipart(context.Background(), http.MethodPost, "/workers", parts, nil)
	if err != nil {
		t.Fatalf("Multipart: %v", err)
	}

	if !strings.HasPrefix(gotContentType, "multipart/form-data") {
		t.Errorf("Content-Type = %q, want multipart/form-data", gotContentType)
	}

	_, params, err := mime.ParseMediaType(gotContentType)
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		t.Fatal("no boundary in Content-Type")
	}

	reader := multipart.NewReader(strings.NewReader(string(gotBody)), boundary)
	found := make(map[string]struct{})
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		name := part.FormName()
		found[name] = struct{}{}

		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part data: %v", err)
		}

		if name == "metadata" {
			if part.FileName() != "" {
				t.Errorf("metadata part should not have filename")
			}
			if part.Header.Get("Content-Type") != "application/json" {
				t.Errorf("metadata Content-Type = %q, want application/json", part.Header.Get("Content-Type"))
			}
			if string(data) != `{"version":"1.0"}` {
				t.Errorf("metadata data = %q, want {\"version\":\"1.0\"}", string(data))
			}
		} else if name == "script" {
			if part.FileName() != "main.js" {
				t.Errorf("script filename = %q, want main.js", part.FileName())
			}
			if part.Header.Get("Content-Type") != "application/javascript" {
				t.Errorf("script Content-Type = %q, want application/javascript", part.Header.Get("Content-Type"))
			}
			if string(data) != `console.log("hello");` {
				t.Errorf("script data = %q, want console.log(\"hello\");", string(data))
			}
		}
	}

	if len(found) != 2 {
		t.Errorf("found %d parts, want 2", len(found))
	}
}

func TestStringRedactsToken(t *testing.T) {
	client := New("https://api.cloudflare.com", "super-secret-token")
	str := fmt.Sprintf("%v", client)
	if strings.Contains(str, "super-secret-token") {
		t.Errorf("String() leaked token: %q", str)
	}
	if !strings.Contains(str, "[redacted]") {
		t.Errorf("String() should contain [redacted], got: %q", str)
	}
}

func TestRawReturnsBodyVerbatimOn200(t *testing.T) {
	responseBody := "export default { fetch() {} };\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript+module")
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()

	body, contentType, found, err := New(server.URL, "tok").Raw(context.Background(), "/accounts/acc/workers/scripts/s1")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if !found {
		t.Error("found = false, want true for 200 response")
	}
	if string(body) != responseBody {
		t.Errorf("body = %q, want %q (exact byte match including trailing newline)", string(body), responseBody)
	}
	if contentType != "application/javascript+module" {
		t.Errorf("contentType = %q, want the response's Content-Type header", contentType)
	}
}

func TestRawTreats404AsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10007,"message":"workers.api.error.script_not_found"}]}`)
	}))
	defer server.Close()

	body, contentType, found, err := New(server.URL, "tok").Raw(context.Background(), "/accounts/acc/workers/scripts/missing")
	if err != nil {
		t.Fatalf("Raw on 404 should not error (normal first-run state): %v", err)
	}
	if found {
		t.Error("found = true, want false for 404 response")
	}
	if body != nil {
		t.Errorf("body should be nil on 404, got %q", body)
	}
	if contentType != "" {
		t.Errorf("contentType = %q, want empty on 404", contentType)
	}
}

func TestRawReturnsErrorOn500WithBody(t *testing.T) {
	responseBody := "Internal Server Error"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, responseBody)
	}))
	defer server.Close()

	body, contentType, found, err := New(server.URL, "tok").Raw(context.Background(), "/accounts/acc/workers/scripts/bad")
	if err == nil {
		t.Fatal("expected an error for 500 response")
	}
	if found {
		t.Error("found = true, want false when error occurred")
	}
	if body != nil {
		t.Errorf("body should be nil when error occurred, got %q", body)
	}
	if contentType != "" {
		t.Errorf("contentType should be empty when error occurred, got %q", contentType)
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "500") {
		t.Errorf("error should contain status, got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "Internal Server Error") {
		t.Errorf("error should contain response body, got: %q", errMsg)
	}
	if !strings.Contains(errMsg, "/accounts/acc/workers/scripts/bad") {
		t.Errorf("error should contain path, got: %q", errMsg)
	}
}

func TestRawSetsAuthorizationHeader(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, "script source")
	}))
	defer server.Close()

	_, _, _, err := New(server.URL, "secret-token").Raw(context.Background(), "/accounts/acc/workers/scripts/s1")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("Authorization = %q, want Bearer secret-token", gotAuth)
	}
}
