package ms365

import (
	"strings"
	"testing"
)

func testSkus() []graphSku {
	basic := graphSku{SkuID: "sku-basic", SkuPartNumber: "BUSINESS_BASIC", ConsumedUnits: 3}
	basic.PrepaidUnits.Enabled = 5
	standard := graphSku{SkuID: "sku-standard", SkuPartNumber: "BUSINESS_STANDARD", ConsumedUnits: 1}
	standard.PrepaidUnits.Enabled = 1
	return []graphSku{basic, standard}
}

func TestIndexSkus(t *testing.T) {
	index, err := indexSkus(testSkus())
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}
	if got := index["BUSINESS_BASIC"]; got.SkuID != "sku-basic" || got.Available != 2 {
		t.Fatalf("BUSINESS_BASIC = %+v, want sku-basic with 2 available", got)
	}
	if got := index["BUSINESS_STANDARD"]; got.Available != 0 {
		t.Fatalf("BUSINESS_STANDARD available = %d, want 0", got.Available)
	}
}

func TestIndexSkusNeverReportsNegativeSeats(t *testing.T) {
	// A tenant can consume more than it prepaid during a licence change.
	over := graphSku{SkuID: "sku-x", SkuPartNumber: "X", ConsumedUnits: 7}
	over.PrepaidUnits.Enabled = 5
	index, err := indexSkus([]graphSku{over})
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}
	if got := index["X"].Available; got != 0 {
		t.Fatalf("Available = %d, want 0 rather than a negative count", got)
	}
}

func TestIndexSkusSingleEntryIsUnaffected(t *testing.T) {
	single := graphSku{SkuID: "sku-basic", SkuPartNumber: "BUSINESS_BASIC", ConsumedUnits: 3}
	single.PrepaidUnits.Enabled = 5
	index, err := indexSkus([]graphSku{single})
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}
	if got := index["BUSINESS_BASIC"]; got.SkuID != "sku-basic" || got.Available != 2 {
		t.Fatalf("BUSINESS_BASIC = %+v, want sku-basic with 2 available", got)
	}
}

func TestIndexSkusDifferentPartNumbersIndexNormally(t *testing.T) {
	index, err := indexSkus(testSkus())
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}
	if len(index) != 2 {
		t.Fatalf("index has %d entries, want 2", len(index))
	}
}

func TestIndexSkusErrorsOnDuplicatePartNumber(t *testing.T) {
	a := graphSku{SkuID: "sku-legacy", SkuPartNumber: "BUSINESS_BASIC", ConsumedUnits: 1}
	a.PrepaidUnits.Enabled = 5
	b := graphSku{SkuID: "sku-nce", SkuPartNumber: "BUSINESS_BASIC", ConsumedUnits: 1}
	b.PrepaidUnits.Enabled = 5

	_, err := indexSkus([]graphSku{a, b})
	if err == nil {
		t.Fatal("want an error for a duplicate part number")
	}
	for _, want := range []string{"BUSINESS_BASIC", "sku-legacy", "sku-nce"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err, want)
		}
	}
}

func TestCheckSeats(t *testing.T) {
	index, err := indexSkus(testSkus())
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}

	cases := []struct {
		name    string
		wanted  map[string]int
		wantErr []string
	}{
		{"within budget", map[string]int{"BUSINESS_BASIC": 1}, nil},
		{"exact fit", map[string]int{"BUSINESS_BASIC": 2}, nil},
		{"one too many", map[string]int{"BUSINESS_BASIC": 3}, []string{"BUSINESS_BASIC", "3", "2"}},
		{"none available", map[string]int{"BUSINESS_STANDARD": 1}, []string{"BUSINESS_STANDARD", "0"}},
		{"unknown sku", map[string]int{"ENTERPRISE_E5": 1}, []string{"ENTERPRISE_E5", "BUSINESS_BASIC"}},
		{"nothing wanted", nil, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSeats(index, tc.wanted)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("checkSeats: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("want an error")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to mention %q", err, want)
				}
			}
		})
	}
}

// TestCheckSeatsShortfallDisclosesItIsPerDomain is the Finding 2 regression
// test. checkSeats runs against one domain's own /subscribedSkus read, so it
// cannot see another domain on the same tenant also about to consume seats
// this run; the shortfall message must say so rather than reading as a
// tenant-wide guarantee it cannot make.
func TestCheckSeatsShortfallDisclosesItIsPerDomain(t *testing.T) {
	index, err := indexSkus(testSkus())
	if err != nil {
		t.Fatalf("indexSkus: %v", err)
	}
	err = checkSeats(index, map[string]int{"BUSINESS_BASIC": 3})
	if err == nil {
		t.Fatal("want an error: BUSINESS_BASIC only has 2 seats free")
	}
	for _, want := range []string{"domain", "other domain"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q so the operator knows the count is per domain", err, want)
		}
	}
}

// TestCheckSeatsEmptyInventorySaysNoSubscribedSKUs covers a tenant subscribed
// to nothing: the message must state that fact plainly rather than trailing
// off after "available part numbers are " with nothing following.
func TestCheckSeatsEmptyInventorySaysNoSubscribedSKUs(t *testing.T) {
	err := checkSeats(map[string]licenceInfo{}, map[string]int{"BUSINESS_BASIC": 1})
	if err == nil {
		t.Fatal("want an error: the tenant has no subscriptions at all")
	}
	if strings.Contains(err.Error(), "available part numbers are ") {
		t.Errorf("error = %q, want no dangling \"available part numbers are\" phrase", err)
	}
	if !strings.Contains(err.Error(), "no subscribed SKUs") {
		t.Errorf("error = %q, want it to say plainly the tenant has no subscribed SKUs", err)
	}
}
