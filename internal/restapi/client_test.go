package restapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDoRetriesThrottleThenDecodes(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer k" {
			t.Errorf("auth = %q", r.Header.Get("Authorization"))
		}
		if calls == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"id":"d1"}`)
	}))
	defer server.Close()

	var out struct{ ID string }
	if err := New("Test", server.URL, Bearer("k")).Do(context.Background(), http.MethodGet, "/x", nil, &out); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || out.ID != "d1" {
		t.Errorf("calls = %d, out = %+v", calls, out)
	}
}

func TestDoReturnsAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"nope"}`)
	}))
	defer server.Close()

	err := New("Test", server.URL, nil).Do(context.Background(), http.MethodDelete, "/y", nil, nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Body != `{"message":"nope"}` {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRetryAfterCaps(t *testing.T) {
	if got := parseRetryAfter("999"); got != maxRetryDelay {
		t.Errorf("got %v", got)
	}
	if got := parseRetryAfter(""); got != defaultRetryDelay {
		t.Errorf("got %v", got)
	}
}
