// Package cfapi is the shared transport for every Cloudflare v4 API call
// mailctl makes: DNS, Email Routing, Email Sending, and Workers.
package cfapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

// String redacts the token so that printing a Client cannot leak it.
func (c *Client) String() string {
	return fmt.Sprintf("cfapi.Client{baseURL: %s, token: [redacted]}", c.baseURL)
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiMessage    `json:"errors"`
	Messages   []apiMessage    `json:"messages"`
	Result     json.RawMessage `json:"result"`
	ResultInfo resultInfo      `json:"result_info"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

// Do performs one request. body is JSON-marshalled when non-nil; result is
// JSON-unmarshalled from the envelope's result field when non-nil.
func (c *Client) Do(ctx context.Context, method, path string, body, result any) error {
	var reader io.Reader
	var contentType string
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal Cloudflare %s %s request: %w", method, path, err)
		}
		reader = bytes.NewReader(payload)
		contentType = "application/json"
	}
	_, err := c.send(ctx, method, path, reader, contentType, result)
	return err
}

// Part is one section of a multipart upload, used for Worker script uploads.
type Part struct {
	Name        string
	Filename    string
	ContentType string
	Data        []byte
}

// Multipart performs a multipart/form-data request.
func (c *Client) Multipart(ctx context.Context, method, path string, parts []Part, result any) error {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for _, part := range parts {
		header := make(textproto.MIMEHeader)
		if part.Filename != "" {
			header.Set("Content-Disposition",
				fmt.Sprintf(`form-data; name=%q; filename=%q`, part.Name, part.Filename))
		} else {
			header.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q`, part.Name))
		}
		if part.ContentType != "" {
			header.Set("Content-Type", part.ContentType)
		}
		field, err := writer.CreatePart(header)
		if err != nil {
			return fmt.Errorf("build Cloudflare multipart part %s: %w", part.Name, err)
		}
		if _, err := field.Write(part.Data); err != nil {
			return fmt.Errorf("write Cloudflare multipart part %s: %w", part.Name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close Cloudflare multipart body: %w", err)
	}

	_, err := c.send(ctx, method, path, &buf, writer.FormDataContentType(), result)
	return err
}

func (c *Client) send(ctx context.Context, method, path string, body io.Reader, contentType string, result any) (resultInfo, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return resultInfo{}, fmt.Errorf("build Cloudflare %s %s request: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return resultInfo{}, fmt.Errorf("Cloudflare %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resultInfo{}, fmt.Errorf("read Cloudflare %s %s response: %w", method, path, err)
	}

	var env envelope
	decodeErr := json.Unmarshal(data, &env)

	// A non-2xx status with a parseable envelope still yields Cloudflare's own
	// message, which is more useful than the status line.
	if decodeErr != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return resultInfo{}, fmt.Errorf("Cloudflare %s %s returned %s: %s",
				method, path, resp.Status, strings.TrimSpace(string(data)))
		}
		return resultInfo{}, fmt.Errorf("parse Cloudflare %s %s response: %w", method, path, decodeErr)
	}

	if !env.Success {
		return env.ResultInfo, fmt.Errorf("Cloudflare %s %s failed: %w", method, path, messagesError(env.Errors))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return env.ResultInfo, fmt.Errorf("Cloudflare %s %s returned %s despite reporting success: %s",
			method, path, resp.Status, strings.TrimSpace(string(data)))
	}

	if result != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, result); err != nil {
			return env.ResultInfo, fmt.Errorf("parse Cloudflare %s %s result: %w", method, path, err)
		}
	}
	return env.ResultInfo, nil
}

// Raw performs a GET and returns the response body unparsed, for endpoints that
// answer with something other than the JSON envelope. found is false when the
// resource does not exist, which is a normal state rather than an error.
// contentType is the response's Content-Type header, since some of those
// endpoints answer with a shape (e.g. multipart/form-data) that callers must
// detect before they can parse the body.
func (c *Client) Raw(ctx context.Context, path string) (body []byte, contentType string, found bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, "", false, fmt.Errorf("build Cloudflare GET %s request: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", false, fmt.Errorf("Cloudflare GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("read Cloudflare GET %s response: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, "", false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", false, fmt.Errorf("Cloudflare GET %s returned %s: %s",
			path, resp.Status, strings.TrimSpace(string(data)))
	}
	return data, resp.Header.Get("Content-Type"), true, nil
}

func messagesError(messages []apiMessage) error {
	if len(messages) == 0 {
		return errors.New("no error detail returned")
	}
	parts := make([]string, 0, len(messages))
	for _, m := range messages {
		parts = append(parts, fmt.Sprintf("%d: %s", m.Code, m.Message))
	}
	return errors.New(strings.Join(parts, "; "))
}
