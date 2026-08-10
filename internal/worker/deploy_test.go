package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

func TestUploadSendsMultipartModule(t *testing.T) {
	var gotMetadata, gotModule, gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path

		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse content type: %v", err)
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err != nil {
				break
			}
			body, _ := io.ReadAll(part)
			switch part.FormName() {
			case "metadata":
				gotMetadata = string(body)
			case "worker.mjs":
				gotModule = string(body)
			}
		}
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"s1"}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")
	if err := deployer.Upload(context.Background(), "mailctl-mta-sts-a-com", "export default {};"); err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotPath != "/accounts/acc-1/workers/scripts/mailctl-mta-sts-a-com" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotMetadata, `"main_module":"worker.mjs"`) {
		t.Errorf("metadata = %q, want main_module worker.mjs", gotMetadata)
	}
	if !strings.Contains(gotMetadata, CompatibilityDate) {
		t.Errorf("metadata = %q, want the pinned compatibility date", gotMetadata)
	}
	if gotModule != "export default {};" {
		t.Errorf("module = %q", gotModule)
	}
}

func TestScriptMatchesComparesLiveSource(t *testing.T) {
	const source = "export default { fetch() {} };"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript+module")
		fmt.Fprint(w, source)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	same, err := deployer.ScriptMatches(context.Background(), "s", source)
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if !same {
		t.Error("identical source should report a match, so an unchanged policy does not redeploy")
	}

	different, err := deployer.ScriptMatches(context.Background(), "s", "export default { fetch() { return 1; } };")
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if different {
		t.Error("changed source must report a mismatch")
	}
}

func TestScriptMatchesHandlesMultipartResponse(t *testing.T) {
	const source = "export default { fetch() {} };"

	writeMultipart := func(w http.ResponseWriter, moduleBody string) {
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		metaPart, _ := writer.CreatePart(map[string][]string{
			"Content-Disposition": {`form-data; name="metadata"`},
			"Content-Type":        {"application/json"},
		})
		fmt.Fprint(metaPart, `{"main_module":"worker.mjs"}`)
		modPart, _ := writer.CreatePart(map[string][]string{
			"Content-Disposition": {`form-data; name="worker.mjs"; filename="worker.mjs"`},
			"Content-Type":        {"application/javascript+module"},
		})
		fmt.Fprint(modPart, moduleBody)
		writer.Close()

		w.Header().Set("Content-Type", writer.FormDataContentType())
		w.Write(buf.Bytes())
	}

	matchServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeMultipart(w, source)
	}))
	defer matchServer.Close()

	same, err := New(cfapi.New(matchServer.URL, "tok"), "acc-1").ScriptMatches(context.Background(), "s", source)
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if !same {
		t.Error("a multipart response whose module part matches source should report a match")
	}

	mismatchServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeMultipart(w, "export default { fetch() { return 1; } };")
	}))
	defer mismatchServer.Close()

	different, err := New(cfapi.New(mismatchServer.URL, "tok"), "acc-1").ScriptMatches(context.Background(), "s", source)
	if err != nil {
		t.Fatalf("ScriptMatches: %v", err)
	}
	if different {
		t.Error("a multipart response whose module part differs from source must report a mismatch")
	}
}

func TestScriptMatchesTreatsMissingScriptAsMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10007,"message":"workers.api.error.script_not_found"}]}`)
	}))
	defer server.Close()

	same, err := New(cfapi.New(server.URL, "tok"), "acc-1").ScriptMatches(context.Background(), "s", "anything")
	if err != nil {
		t.Fatalf("a missing script is a normal first-run state, not an error: %v", err)
	}
	if same {
		t.Error("a missing script must report a mismatch so it gets uploaded")
	}
}

func TestAttachDomainSendsHostnameAndZone(t *testing.T) {
	var gotBody map[string]any
	var gotMethod, gotPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		body, _ := io.ReadAll(r.Body)
		decodeJSON(t, body, &gotBody)
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"d1"}}`)
	}))
	defer server.Close()

	err := New(cfapi.New(server.URL, "tok"), "acc-1").
		AttachDomain(context.Background(), "mta-sts.a.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("AttachDomain: %v", err)
	}

	if gotMethod != http.MethodPut || gotPath != "/accounts/acc-1/workers/domains" {
		t.Errorf("%s %s, want PUT /accounts/acc-1/workers/domains", gotMethod, gotPath)
	}
	for key, want := range map[string]any{
		"hostname":    "mta-sts.a.com",
		"zone_id":     "z1",
		"service":     "mailctl-mta-sts-a-com",
		"environment": "production",
	} {
		if gotBody[key] != want {
			t.Errorf("body[%q] = %v, want %v", key, gotBody[key], want)
		}
	}
}

func TestDomainAttachedFiltersByHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"d1","hostname":"mta-sts.a.com","zone_id":"z1","service":"mailctl-mta-sts-a-com"}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	attached, err := deployer.DomainAttached(context.Background(), "mta-sts.a.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if !attached {
		t.Error("the listed hostname should report as attached")
	}

	missing, err := deployer.DomainAttached(context.Background(), "mta-sts.b.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if missing {
		t.Error("an unlisted hostname must report as not attached")
	}
}

func TestDomainAttachedRequiresServiceMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"d1","hostname":"mta-sts.a.com","zone_id":"z1","service":"some-other-worker"}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	attached, err := deployer.DomainAttached(context.Background(), "mta-sts.a.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if attached {
		t.Error("a hostname bound to a different Worker service must report as not attached, or mailctl never rebinds it")
	}
}

func TestDomainAttachedRequiresZoneIdMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"d1","hostname":"mta-sts.a.com","zone_id":"z1","service":"mailctl-mta-sts-a-com"}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	attached, err := deployer.DomainAttached(context.Background(), "mta-sts.a.com", "z2", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if attached {
		t.Error("same hostname in different zone must report as not attached")
	}
}

func TestDomainAttachedMatchesCaseInsensitively(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"d1","hostname":"MTA-STS.A.COM","zone_id":"z1","service":"mailctl-mta-sts-a-com"}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	deployer := New(cfapi.New(server.URL, "tok"), "acc-1")

	attached, err := deployer.DomainAttached(context.Background(), "mta-sts.a.com", "z1", "mailctl-mta-sts-a-com")
	if err != nil {
		t.Fatalf("DomainAttached: %v", err)
	}
	if !attached {
		t.Error("hostname match should be case-insensitive")
	}
}

func decodeJSON(t *testing.T, data []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("decode body %q: %v", data, err)
	}
}
