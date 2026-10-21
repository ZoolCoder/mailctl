package resend

import (
	"context"
	"net/http"
	"net/url"

	"github.com/zoolcoder/mailctl/internal/restapi"
)

// DefaultBaseURL is the public API host.
const DefaultBaseURL = "https://api.resend.com"

type Client struct{ api *restapi.Client }

func NewClient(baseURL, key string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{api: restapi.New("Resend", baseURL, restapi.Bearer(key))}
}

type Domain struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Status  string   `json:"status"`
	Region  string   `json:"region"`
	Records []Record `json:"records"`
}

// Record is one DNS record Resend asks for. Name may be relative ("send") or
// a full name; TTL is a string ("Auto") and is not carried over.
type Record struct {
	Record   string `json:"record"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Status   string `json:"status"`
	Value    string `json:"value"`
	Priority int    `json:"priority"`
}

// Domains lists every domain on the team. Without a limit Resend answers
// with all of them in one page.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	var out struct {
		Data []Domain `json:"data"`
	}
	err := c.api.Do(ctx, http.MethodGet, "/domains", nil, &out)
	return out.Data, err
}

func (c *Client) Domain(ctx context.Context, id string) (Domain, error) {
	var out Domain
	err := c.api.Do(ctx, http.MethodGet, "/domains/"+url.PathEscape(id), nil, &out)
	return out, err
}

func (c *Client) Create(ctx context.Context, name, region string) (Domain, error) {
	body := map[string]string{"name": name}
	if region != "" {
		body["region"] = region
	}
	var out Domain
	err := c.api.Do(ctx, http.MethodPost, "/domains", body, &out)
	return out, err
}

// Verify asks Resend to check the records now instead of on its own schedule.
func (c *Client) Verify(ctx context.Context, id string) error {
	return c.api.Do(ctx, http.MethodPost, "/domains/"+url.PathEscape(id)+"/verify", nil, nil)
}
