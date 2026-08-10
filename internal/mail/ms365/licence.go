package ms365

import (
	"fmt"
	"sort"
	"strings"
)

// licenceInfo is one subscribed SKU: its GUID, and how many seats are free.
type licenceInfo struct {
	SkuID     string
	Available int
}

// indexSkus maps skuPartNumber to its id and free seat count. Consumed can
// exceed prepaid during a licence change, so the count is floored at zero
// rather than going negative.
//
// Two entries can share a part number for a tenant mid-transition between
// legacy and New Commerce Experience licensing. That makes the skuId Plan
// should assign genuinely ambiguous, so it is an error rather than a
// last-wins overwrite: guessing risks a create that fails after the user
// already exists, which is worse than refusing up front.
func indexSkus(skus []graphSku) (map[string]licenceInfo, error) {
	index := make(map[string]licenceInfo, len(skus))
	for _, sku := range skus {
		if existing, ok := index[sku.SkuPartNumber]; ok {
			return nil, fmt.Errorf(
				"licence part number %q is ambiguous: subscribedSkus lists it under both skuId %s and skuId %s; the tenant may be mid-transition between legacy and New Commerce Experience licensing, so pick one skuId explicitly",
				sku.SkuPartNumber, existing.SkuID, sku.SkuID)
		}
		available := sku.PrepaidUnits.Enabled - sku.ConsumedUnits
		if available < 0 {
			available = 0
		}
		index[sku.SkuPartNumber] = licenceInfo{SkuID: sku.SkuID, Available: available}
	}
	return index, nil
}

// checkSeats reports whether the tenant has room for the requested mailboxes.
// Plan calls it so a shortfall is known before anything is created; finding out
// during apply leaves some mailboxes made and others not.
//
// The count is per domain, not per tenant. Each ms365 domain gets its own
// Provider from a fresh mail.Open call (internal/engine.planDomain), so its
// own /subscribedSkus read and its own index — this function has no way to
// see seats another domain on the same tenant is about to consume in the
// same run. Two domains sharing a tenant can each pass this check
// independently and, between them, still exceed the tenant's free seats; the
// messages below say so rather than implying a tenant-wide guarantee this
// function cannot make.
func checkSeats(index map[string]licenceInfo, wanted map[string]int) error {
	parts := make([]string, 0, len(wanted))
	for part := range wanted {
		parts = append(parts, part)
	}
	sort.Strings(parts)

	for _, part := range parts {
		needed := wanted[part]
		info, ok := index[part]
		if !ok {
			available := sortedKeys(index)
			if len(available) == 0 {
				return fmt.Errorf(
					"licence %q is not one of this tenant's subscriptions; the tenant has no subscribed SKUs",
					part)
			}
			return fmt.Errorf(
				"licence %q is not one of this tenant's subscriptions; available part numbers are %s",
				part, strings.Join(available, ", "))
		}
		if needed > info.Available {
			return fmt.Errorf(
				"creating mailboxes needs %d %s seat(s) but only %d are free in this domain's read of the tenant "+
					"(this count does not include any other domain on the same tenant also planning to consume %s seats "+
					"this run); buy more seats, free some, or apply the other domain first, then rerun",
				needed, part, info.Available, part)
		}
	}
	return nil
}

func sortedKeys(index map[string]licenceInfo) []string {
	out := make([]string, 0, len(index))
	for key := range index {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
