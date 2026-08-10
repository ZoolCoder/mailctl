// Package graphapi is a minimal Microsoft Graph client. It is shaped after
// internal/cfapi and differs only where Graph forces it to: OAuth2 client
// credentials instead of a static token, and real HTTP status codes instead of
// Purelymail's HTTP 200 with an error body.
package graphapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	DefaultGraphBaseURL = "https://graph.microsoft.com/v1.0"
	DefaultLoginBaseURL = "https://login.microsoftonline.com"

	// tokenSkew renews early so a token cannot expire between the check and
	// the request that uses it.
	tokenSkew = 60 * time.Second

	// maxBodyBytes bounds how much of a response is read. Graph responses are
	// small; an unbounded read is a denial-of-service waiting to happen.
	maxBodyBytes = 8 << 20
)

type Config struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// GraphBaseURL and LoginBaseURL default to the public endpoints. Tests
	// point them at httptest servers.
	GraphBaseURL string
	LoginBaseURL string
	HTTP         *http.Client
}

type Client struct {
	graphBase string
	loginBase string
	tenantID  string
	clientID  string
	secret    string
	http      *http.Client

	mu          sync.Mutex
	accessToken string
	expiresAt   time.Time
}

func New(cfg Config) (*Client, error) {
	var missing []string
	if cfg.TenantID == "" {
		missing = append(missing, "MS365_TENANT_ID")
	}
	if cfg.ClientID == "" {
		missing = append(missing, "MS365_CLIENT_ID")
	}
	if cfg.ClientSecret == "" {
		missing = append(missing, "MS365_CLIENT_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"microsoft 365 credentials are not set: %s; export them or add them to your secrets file",
			strings.Join(missing, ", "))
	}

	client := &Client{
		graphBase: strings.TrimSuffix(orDefault(cfg.GraphBaseURL, DefaultGraphBaseURL), "/"),
		loginBase: strings.TrimSuffix(orDefault(cfg.LoginBaseURL, DefaultLoginBaseURL), "/"),
		tenantID:  cfg.TenantID,
		clientID:  cfg.ClientID,
		secret:    cfg.ClientSecret,
		http:      cfg.HTTP,
	}
	if client.http == nil {
		client.http = &http.Client{Timeout: 30 * time.Second}
	}
	return client, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// String is safe to include in an error. It never contains the secret.
func (c *Client) String() string {
	return fmt.Sprintf("graphapi.Client{graph:%s tenant:%s clientId:%s secret:REDACTED}",
		c.graphBase, c.tenantID, c.clientID)
}

// APIError is a Graph error response.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("Microsoft Graph returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("Microsoft Graph %s: %s (HTTP %d)", e.Code, e.Message, e.Status)
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// scope derives the token scope from the Graph base URL so a test server gets
// a scope pointing at itself rather than at the public endpoint.
func (c *Client) scope() string {
	parsed, err := url.Parse(c.graphBase)
	if err != nil || parsed.Host == "" {
		return "https://graph.microsoft.com/.default"
	}
	return parsed.Scheme + "://" + parsed.Host + "/.default"
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// token returns a cached access token, fetching one when absent, near expiry,
// or when force is set after a 401.
func (c *Client) token(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !force && c.accessToken != "" && time.Now().Before(c.expiresAt) {
		return c.accessToken, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.clientID},
		"client_secret": {c.secret},
		"scope":         {c.scope()},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token", c.loginBase, url.PathEscape(c.tenantID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("building the Microsoft 365 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting a Microsoft 365 access token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return "", fmt.Errorf("reading the Microsoft 365 token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Deliberately not included: the response body. The token endpoint
		// echoes the request on failure, client secret and all.
		return "", fmt.Errorf(
			"Microsoft 365 token request failed with HTTP %d; check MS365_TENANT_ID, MS365_CLIENT_ID and MS365_CLIENT_SECRET",
			resp.StatusCode)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decoding the Microsoft 365 token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("the Microsoft 365 token response contained no access_token")
	}

	lifetime := time.Duration(parsed.ExpiresIn) * time.Second
	if lifetime > tokenSkew {
		lifetime -= tokenSkew
	}
	c.accessToken = parsed.AccessToken
	c.expiresAt = time.Now().Add(lifetime)
	return c.accessToken, nil
}

// Do performs one Graph request. path is relative to the Graph base URL and
// starts with "/". A nil body sends none; a nil result discards the
// response. Do retries transparently on throttling, honouring Retry-After,
// up to maxRetries times.
func (c *Client) Do(ctx context.Context, method, path string, body, result any) error {
	return c.do(ctx, method, path, body, result, false)
}

func (c *Client) do(ctx context.Context, method, path string, body, result any, refreshed bool) error {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		token, err := c.token(ctx, false)
		if err != nil {
			return err
		}

		status, raw, header, err := c.send(ctx, method, c.graphBase+path, body, token)
		if err != nil {
			return err
		}

		if status == http.StatusUnauthorized && !refreshed {
			if _, err := c.token(ctx, true); err != nil {
				return err
			}
			return c.do(ctx, method, path, body, result, true)
		}

		if throttled(status) {
			lastErr = apiError(status, raw)
			if attempt == maxRetries {
				break
			}
			if err := wait(ctx, parseRetryAfter(header.Get("Retry-After"))); err != nil {
				return err
			}
			continue
		}

		if status < 200 || status > 299 {
			return apiError(status, raw)
		}
		if result == nil || len(raw) == 0 {
			return nil
		}
		if err := json.Unmarshal(raw, result); err != nil {
			return fmt.Errorf("decoding the Microsoft Graph response for %s %s: %w", method, path, err)
		}
		return nil
	}

	return fmt.Errorf("Microsoft Graph kept throttling %s %s after %d attempts; the tenant is rate-limiting mailctl, so simply rerun: %w",
		method, path, maxRetries+1, lastErr)
}

// send performs one HTTP round trip and returns the status, body and
// response header. It does not interpret the status; callers decide.
func (c *Client) send(ctx context.Context, method, endpoint string, body any, token string) (int, []byte, http.Header, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("encoding the Microsoft Graph request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("building the Microsoft Graph %s %s request: %w", method, endpoint, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("Microsoft Graph %s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("reading the Microsoft Graph response: %w", err)
	}
	return resp.StatusCode, raw, resp.Header, nil
}

func apiError(status int, raw []byte) error {
	var envelope errorEnvelope
	// An unparseable body is not itself an error worth reporting; the status
	// code still is.
	_ = json.Unmarshal(raw, &envelope)
	return &APIError{
		Status:  status,
		Code:    envelope.Error.Code,
		Message: envelope.Error.Message,
	}
}
