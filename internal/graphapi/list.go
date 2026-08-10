package graphapi

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// maxListPages bounds paging. A server that always advertises another page
// must not hang mailctl, matching internal/cfapi's cap.
const maxListPages = 100

type page[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// List reads every page of a Graph collection, following @odata.nextLink.
func List[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	base, err := url.Parse(c.graphBase)
	if err != nil {
		return nil, fmt.Errorf("parsing the Graph base URL %q: %w", c.graphBase, err)
	}

	var out []T
	next := path

	for pages := 0; ; pages++ {
		if pages >= maxListPages {
			return nil, fmt.Errorf(
				"Microsoft Graph returned more than %d pages for %s; refusing to keep paging, which indicates a Graph or mailctl bug worth reporting rather than something an operator can fix",
				maxListPages, path)
		}

		var current page[T]
		if err := c.Do(ctx, "GET", next, nil, &current); err != nil {
			return nil, err
		}
		out = append(out, current.Value...)

		if current.NextLink == "" {
			return out, nil
		}

		link, err := url.Parse(current.NextLink)
		if err != nil {
			return nil, fmt.Errorf("parsing @odata.nextLink %q: %w", current.NextLink, err)
		}
		// A nextLink pointing elsewhere would send the access token to
		// another host. Refuse rather than follow.
		if link.Host != base.Host {
			return nil, fmt.Errorf(
				"@odata.nextLink points at %q, not the Graph host %q; mailctl refused to send the access token to %s, so rerun the command",
				link.Host, base.Host, link.Host)
		}
		next = link.Path
		if link.RawQuery != "" {
			next += "?" + link.RawQuery
		}
		next = strings.TrimPrefix(next, basePathOf(base))
	}
}

// basePathOf returns the path component of the Graph base URL, e.g. "/v1.0",
// so a nextLink's absolute path can be made relative to it.
func basePathOf(base *url.URL) string {
	return strings.TrimSuffix(base.Path, "/")
}
