package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestZoneLooksUpByName(t *testing.T) {
	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("name")
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[{"id":"z1","name":"a.com"}],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	zone, err := New(cfapi.New(server.URL, "tok"), 1).Zone(context.Background(), "a.com")
	if err != nil {
		t.Fatalf("Zone: %v", err)
	}
	if gotQuery != "a.com" {
		t.Errorf("name filter = %q, want a.com", gotQuery)
	}
	if zone.ID != "z1" {
		t.Errorf("zone id = %q, want z1", zone.ID)
	}
}

func TestZoneNotFoundNamesTheZone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	_, err := New(cfapi.New(server.URL, "tok"), 1).Zone(context.Background(), "missing.com")
	if err == nil || !strings.Contains(err.Error(), "missing.com") {
		t.Fatalf("err = %v, want an error naming the zone", err)
	}
}

func TestCreateSendsTTLAndPriority(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"r1"}}`)
	}))
	defer server.Close()

	record := dns.Record{Type: "MX", Name: "a.com", Content: "mailserver.purelymail.com", Priority: 50, Kind: dns.KindMX}
	if err := New(cfapi.New(server.URL, "tok"), 1).Create(context.Background(), "z1", record); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if payload["type"] != "MX" || payload["content"] != "mailserver.purelymail.com" {
		t.Errorf("payload = %v, want the record fields", payload)
	}
	if payload["priority"].(float64) != 50 {
		t.Errorf("priority = %v, want 50", payload["priority"])
	}
	if payload["ttl"].(float64) != 1 {
		t.Errorf("ttl = %v, want the provider default 1", payload["ttl"])
	}
	if _, present := payload["proxied"]; present {
		t.Error("proxied must be omitted unless the record sets it")
	}
}

func TestCreateSendsProxiedWhenSet(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"r1"}}`)
	}))
	defer server.Close()

	off := false
	record := dns.Record{Type: "CNAME", Name: "x.a.com", Content: "y.com", TTL: 300, Proxied: &off, Kind: dns.KindDKIM}
	if err := New(cfapi.New(server.URL, "tok"), 1).Create(context.Background(), "z1", record); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if payload["proxied"] != false {
		t.Errorf("proxied = %v, want false", payload["proxied"])
	}
	if payload["ttl"].(float64) != 300 {
		t.Errorf("ttl = %v, want the record's own 300", payload["ttl"])
	}
}

func TestRecordsMapsPriorityAndID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"errors":[],"result":[
			{"id":"r1","type":"MX","name":"a.com","content":"mx.a.com","ttl":1,"priority":10,"proxied":false}
		],"result_info":{"page":1,"total_pages":1}}`)
	}))
	defer server.Close()

	got, err := New(cfapi.New(server.URL, "tok"), 1).Records(context.Background(), "z1")
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].ID != "r1" || got[0].Priority != 10 || got[0].Type != "MX" {
		t.Errorf("record = %+v, want the mapped fields", got[0])
	}
}

// Delete is the one call here that destroys something, and it had no test. The
// record id is what makes it specific: a wrong path deletes another record, and
// a wrong method silently does nothing while reporting success.
func TestDeleteTargetsTheRecordIDWithDELETE(t *testing.T) {
	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		fmt.Fprint(w, `{"success":true,"errors":[],"result":{"id":"r1"}}`)
	}))
	defer server.Close()

	if err := New(cfapi.New(server.URL, "tok"), 1).Delete(context.Background(), "z1", "r1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if gotPath != "/zones/z1/dns_records/r1" {
		t.Errorf("path = %q, want the zone and record id", gotPath)
	}
}

func TestDeleteSurfacesCloudflaresRefusal(t *testing.T) {
	// A failed delete must be an error: reporting success would leave the plan
	// believing a record is gone when it is still published.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`)
	}))
	defer server.Close()

	err := New(cfapi.New(server.URL, "tok"), 1).Delete(context.Background(), "z1", "r1")
	if err == nil {
		t.Fatal("expected an error when Cloudflare refuses the delete")
	}
	if !strings.Contains(err.Error(), "r1") {
		t.Errorf("error should name the record it failed to delete; got %q", err)
	}
}
