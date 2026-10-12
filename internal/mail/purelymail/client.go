// Package purelymail talks to the Purelymail /api/v0 JSON API and implements
// mail.Provider on top of it.
package purelymail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the public API host.
const DefaultBaseURL = "https://purelymail.com"

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

type envelope struct {
	Type    string          `json:"type"`
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Result  json.RawMessage `json:"result"`
}

// post calls one endpoint. Purelymail answers HTTP 200 even for failures, with
// type "error" in the body, so the body is always what decides success.
func (c *Client) post(ctx context.Context, endpoint string, body, result any) error {
	if body == nil {
		body = map[string]any{}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal Purelymail %s request: %w", endpoint, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v0/"+endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build Purelymail %s request: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Purelymail-Api-Token", c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Purelymail %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read Purelymail %s response: %w", endpoint, err)
	}

	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("Purelymail %s returned %s with an unparseable body: %s",
			endpoint, resp.Status, strings.TrimSpace(string(data)))
	}

	if env.Type == "error" || env.Code != "" {
		return fmt.Errorf("Purelymail %s failed: %s %s", endpoint, env.Code, env.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Purelymail %s returned %s: %s",
			endpoint, resp.Status, strings.TrimSpace(string(data)))
	}

	if result == nil {
		return nil
	}
	if len(env.Result) == 0 || string(env.Result) == "null" {
		return fmt.Errorf("Purelymail %s returned no result", endpoint)
	}
	if err := json.Unmarshal(env.Result, result); err != nil {
		return fmt.Errorf("parse Purelymail %s result: %w", endpoint, err)
	}
	return nil
}
