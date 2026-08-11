package graphapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type sku struct {
	SkuPartNumber string `json:"skuPartNumber"`
}

func TestListFollowsNextLink(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var graph *httptest.Server
	graph = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "":
			fmt.Fprintf(w, `{"value":[{"skuPartNumber":"A"}],"@odata.nextLink":%q}`,
				graph.URL+"/subscribedSkus?page=2")
		case "2":
			fmt.Fprintf(w, `{"value":[{"skuPartNumber":"B"}],"@odata.nextLink":%q}`,
				graph.URL+"/subscribedSkus?page=3")
		default:
			_, _ = w.Write([]byte(`{"value":[{"skuPartNumber":"C"}]}`))
		}
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	got, err := List[sku](context.Background(), c, "/subscribedSkus")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 || got[0].SkuPartNumber != "A" || got[2].SkuPartNumber != "C" {
		t.Fatalf("got %+v, want A B C in order", got)
	}
}

func TestListStopsAtThePageCap(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	var graph *httptest.Server
	graph = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always advertises another page: a server bug must not hang mailctl.
		fmt.Fprintf(w, `{"value":[{"skuPartNumber":"X"}],"@odata.nextLink":%q}`,
			graph.URL+"/subscribedSkus?page=next")
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	_, err := List[sku](context.Background(), c, "/subscribedSkus")
	if err == nil {
		t.Fatal("want an error when the page cap is reached")
	}
	if !strings.Contains(err.Error(), "pages") {
		t.Errorf("error = %q, want it to mention the page limit", err)
	}
}

func TestListRejectsANextLinkToAnotherHost(t *testing.T) {
	var hits atomic.Int64
	login := tokenServer(t, &hits, 3600)
	defer login.Close()

	graph := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":[],"@odata.nextLink":"https://attacker.example/steal"}`))
	}))
	defer graph.Close()

	c := newTestClient(t, graph.URL, login.URL)
	_, err := List[sku](context.Background(), c, "/subscribedSkus")
	if err == nil {
		t.Fatal("want an error: a nextLink to another host must not receive the token")
	}
}
