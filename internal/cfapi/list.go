package cfapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

const listPageSize = 100
const maxListPages = 100

// List fetches every page of a paginated collection endpoint. path may already
// carry a query string; page and per_page are appended to it.
//
// If pagination does not terminate within maxListPages, List returns an error.
// We return an error rather than silently truncating because a partial result
// would cause the diff engine to think records were deleted when we merely
// failed to fetch all pages.
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	separator := "?"
	if strings.Contains(path, "?") {
		separator = "&"
	}

	for page := 1; page <= maxListPages; page++ {
		var chunk []T
		paged := fmt.Sprintf("%s%spage=%d&per_page=%d", path, separator, page, listPageSize)
		info, err := c.send(ctx, http.MethodGet, paged, nil, "", &chunk)
		if err != nil {
			return nil, err
		}
		all = append(all, chunk...)
		if info.TotalPages <= 1 || page >= info.TotalPages {
			return all, nil
		}
	}
	return nil, fmt.Errorf("Cloudflare GET %s: pagination did not terminate within %d pages", path, maxListPages)
}
