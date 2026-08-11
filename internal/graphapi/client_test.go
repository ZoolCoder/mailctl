package graphapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tokenServer serves the OAuth2 token endpoint and counts how often it is hit.
func tokenServer(t *testing.T, hits *atomic.Int64, expiresIn int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			t.Errorf("token endpoint path = %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}
		if got := r.PostForm.Get("grant_type"); got != "client_credentials" {
			t.Errorf("grant_type = %q, want client_credentials", got)
		}
		if got := r.PostForm.Get("scope"); !strings.HasSuffix(got, "/.default") {
			t.Errorf("scope = %q, want a /.default suffix", got)
		}
		n := hits.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "tok-" + string(rune('0'+n)),
			"expires_in":   expiresIn,
		})
	}))
}

func newTestClient(t *testing.T, graphURL, loginURL string) *Client {
	t.Helper()
	c, err := New(Config{
		TenantID:     "tenant-1",
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		GraphBaseURL: graphURL,
		LoginBaseURL: loginURL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewRequiresEveryCredential(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no tenant", Config{ClientID: "c", ClientSecret: "s"}, "MS365_TENANT_ID"},
		{"no client id", Config{TenantID: "t", ClientSecret: "s"}, "MS365_CLIENT_ID"},
		{"no secret", Config{TenantID: "t", ClientID: "c"}, "MS365_CLIENT_SECRET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one naming %s", err, tc.want)
			}
		})
	}
}

func TestTokenIsFetchedOnceAndReused(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var seen []string
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"id":"example.com"}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	for i := 0; i < 3; i++ {
		if err := c.Do(context.Background(), http.MethodGet, "/domains/example.com", nil, nil); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1", got)
	}
	for i, auth := range seen {
		if auth != "Bearer tok-1" {
			t.Errorf("request %d Authorization = %q, want Bearer tok-1", i, auth)
		}
	}
}

func TestUnauthorizedRefreshesTokenExactlyOnce(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var requests atomic.Int64
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"example.com"}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	if err := c.Do(context.Background(), http.MethodGet, "/domains/example.com", nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("token hits = %d, want 2 (initial plus one refresh)", got)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("graph requests = %d, want 2", got)
	}
}

func TestPersistentUnauthorizedFailsWithoutLooping(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var requests atomic.Int64
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"still expired"}}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	err := c.Do(context.Background(), http.MethodGet, "/domains", nil, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("graph requests = %d, want 2; a loop would send more", got)
	}
}

func TestErrorEnvelopeReachesCaller(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	err := c.Do(context.Background(), http.MethodPost, "/domains", map[string]string{"id": "x.com"}, nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want an *APIError", err)
	}
	if apiErr.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want 403", apiErr.Status)
	}
	if apiErr.Code != "Authorization_RequestDenied" {
		t.Errorf("Code = %q", apiErr.Code)
	}
	if !strings.Contains(apiErr.Error(), "Insufficient privileges") {
		t.Errorf("Error() = %q, want the message included", apiErr.Error())
	}
}

func TestTokenEndpointFailureNeverEchoesTheBody(t *testing.T) {
	login := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// A real token endpoint echoes the request, secret included.
		_, _ = w.Write([]byte(`{"error":"invalid_client","error_description":"secret-1 is wrong"}`))
	}))
	defer login.Close()

	c := newTestClient(t, "https://graph.invalid/v1.0", login.URL)
	err := c.Do(context.Background(), http.MethodGet, "/domains", nil, nil)
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "secret-1") {
		t.Fatalf("error leaked the client secret: %q", err)
	}
	for _, want := range []string{"MS365_CLIENT_SECRET", "400"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %s", err, want)
		}
	}
}

func TestStringRedactsTheSecret(t *testing.T) {
	c := newTestClient(t, "https://graph.invalid/v1.0", "https://login.invalid")
	got := c.String()
	if strings.Contains(got, "secret-1") {
		t.Fatalf("String() leaked the secret: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("String() = %q, want REDACTED", got)
	}
}

func TestRequestBodyIsSentAsJSON(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var gotBody, gotType string
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotType = strings.TrimSpace(string(b)), r.Header.Get("Content-Type")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	if err := c.Do(context.Background(), http.MethodPost, "/domains", map[string]string{"id": "x.com"}, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gotBody != `{"id":"x.com"}` {
		t.Errorf("body = %q", gotBody)
	}
	if gotType != "application/json" {
		t.Errorf("Content-Type = %q", gotType)
	}
}

func TestResultIsDecoded(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":"example.com","isVerified":true}`))
	}))
	defer graph.Close()

	var out struct {
		ID         string `json:"id"`
		IsVerified bool   `json:"isVerified"`
	}
	c := newTestClient(t, graph.URL, login.URL)
	if err := c.Do(context.Background(), http.MethodGet, "/domains/example.com", nil, &out); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if out.ID != "example.com" || !out.IsVerified {
		t.Fatalf("out = %+v", out)
	}
}

func TestRetryAfterIsHonouredThenSucceeds(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var attempts atomic.Int64
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"throttled"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"example.com"}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	if err := c.Do(context.Background(), http.MethodGet, "/domains/example.com", nil, nil); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (two throttled, one success)", got)
	}
}

func TestRetriesAreBounded(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var attempts atomic.Int64
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"throttled"}}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	err := c.Do(context.Background(), http.MethodGet, "/domains", nil, nil)
	if err == nil {
		t.Fatal("want an error once retries are exhausted")
	}
	if got := attempts.Load(); got != int64(maxRetries+1) {
		t.Fatalf("attempts = %d, want %d", got, maxRetries+1)
	}
	if !strings.Contains(err.Error(), "throttl") {
		t.Errorf("error = %q, want it to mention throttling", err)
	}
}

func TestRetryAfterRespectsContextCancellation(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// served fires after the response is fully written, so cancelling on it
	// lands while the client is inside wait(), not mid-request.
	served := make(chan struct{}, 1)
	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		select {
		case served <- struct{}{}:
		default:
		}
	}))
	defer graph.Close()

	go func() {
		<-served
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	c := newTestClient(t, graph.URL, login.URL)
	start := time.Now()
	err := c.Do(ctx, http.MethodGet, "/domains", nil, nil)

	if err == nil {
		t.Fatal("want an error from the cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want it to wrap context.Canceled", err)
	}
	// The point of the test: a cancelled context must abort the 30s wait
	// rather than sleeping it out.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Do took %v; cancellation did not abort the Retry-After wait", elapsed)
	}
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", defaultRetryDelay},
		{"0", 0},
		{"5", 5 * time.Second},
		{"not a number", defaultRetryDelay},
		{"-3", 0},
		{"99999", maxRetryDelay},
	}
	for _, tc := range cases {
		t.Run(tc.header, func(t *testing.T) {
			if got := parseRetryAfter(tc.header); got != tc.want {
				t.Fatalf("parseRetryAfter(%q) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
