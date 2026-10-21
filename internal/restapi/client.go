// Package restapi is the small JSON-over-HTTP client the Zoho, Google
// Workspace and Resend providers share: one request helper, bounded retries
// on throttling, and an error type that keeps the status and body.
package restapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// maxRetries bounds throttle retries per request, as graphapi does.
	maxRetries = 4

	// defaultRetryDelay applies when Retry-After is absent or unparseable.
	defaultRetryDelay = 2 * time.Second

	// maxRetryDelay caps an absurd Retry-After.
	maxRetryDelay = 30 * time.Second

	// maxBodyBytes caps how much of a response is read.
	maxBodyBytes = 8 << 20
)

// Authorizer returns the Authorization header value for one request. A token
// source caches; a static key returns the same value every time.
type Authorizer func(ctx context.Context) (string, error)

// Bearer is an Authorizer for a fixed API key.
func Bearer(key string) Authorizer {
	return func(context.Context) (string, error) { return "Bearer " + key, nil }
}

type Client struct {
	// Service names the API in errors, e.g. "Resend".
	Service string
	BaseURL string
	Auth    Authorizer
	HTTP    *http.Client
}

func New(service, baseURL string, auth Authorizer) *Client {
	return &Client{
		Service: service,
		BaseURL: strings.TrimRight(baseURL, "/"),
		Auth:    auth,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// APIError is a non-2xx answer. Body is the raw response, trimmed.
type APIError struct {
	Service string
	Method  string
	Path    string
	Status  int
	Body    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s %s: HTTP %d: %s", e.Service, e.Method, e.Path, e.Status, e.Body)
}

// Do sends body as JSON (when not nil) and decodes a 2xx answer into out
// (when not nil). 429 and 503 are retried after Retry-After.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("marshal %s %s request: %w", c.Service, path, err)
		}
	}

	for attempt := 0; ; attempt++ {
		status, data, retryAfter, err := c.once(ctx, method, path, payload)
		if err != nil {
			return err
		}
		if (status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable) && attempt < maxRetries {
			if err := wait(ctx, parseRetryAfter(retryAfter)); err != nil {
				return err
			}
			continue
		}
		if status < 200 || status > 299 {
			return &APIError{Service: c.Service, Method: method, Path: path, Status: status,
				Body: strings.TrimSpace(string(data))}
		}
		if out == nil || len(bytes.TrimSpace(data)) == 0 {
			return nil
		}
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode %s %s %s response: %w", c.Service, method, path, err)
		}
		return nil
	}
}

func (c *Client) once(ctx context.Context, method, path string, payload []byte) (int, []byte, string, error) {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return 0, nil, "", fmt.Errorf("build %s %s request: %w", c.Service, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Auth != nil {
		header, err := c.Auth(ctx)
		if err != nil {
			return 0, nil, "", err
		}
		req.Header.Set("Authorization", header)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, "", fmt.Errorf("%s %s %s: %w", c.Service, method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return 0, nil, "", fmt.Errorf("read %s %s response: %w", c.Service, path, err)
	}
	return resp.StatusCode, data, resp.Header.Get("Retry-After"), nil
}

func parseRetryAfter(header string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil {
		return defaultRetryDelay
	}
	delay := time.Duration(max(seconds, 0)) * time.Second
	return min(delay, maxRetryDelay)
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
