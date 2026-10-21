package gworkspace

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zoolcoder/mailctl/internal/restapi"
)

const (
	DefaultBaseURL  = "https://admin.googleapis.com/admin/directory/v1"
	DefaultTokenURL = "https://oauth2.googleapis.com/token"
	// SiteVerificationURL is the Site Verification API, which issues and
	// checks the domain ownership TXT.
	SiteVerificationURL = "https://www.googleapis.com/siteVerification/v1"
)

var scopes = []string{
	"https://www.googleapis.com/auth/admin.directory.domain",
	"https://www.googleapis.com/auth/admin.directory.user",
	"https://www.googleapis.com/auth/siteverification",
}

// ServiceAccount is the part of a service-account JSON key mailctl reads.
type ServiceAccount struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
}

// LoadServiceAccount reads a key from the JSON itself or from a file path.
func LoadServiceAccount(value string) (ServiceAccount, error) {
	data := []byte(value)
	if !strings.HasPrefix(strings.TrimSpace(value), "{") {
		var err error
		if data, err = os.ReadFile(value); err != nil {
			return ServiceAccount{}, fmt.Errorf("read GOOGLE_SERVICE_ACCOUNT_KEY file: %w", err)
		}
	}
	var account ServiceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return ServiceAccount{}, fmt.Errorf("GOOGLE_SERVICE_ACCOUNT_KEY is not a service-account JSON key: %w", err)
	}
	if account.ClientEmail == "" || account.PrivateKey == "" {
		return ServiceAccount{}, errors.New("GOOGLE_SERVICE_ACCOUNT_KEY lacks client_email or private_key")
	}
	return account, nil
}

// tokenSource signs a JWT as the service account, acting for the admin
// through domain-wide delegation, and caches the access token it buys.
type tokenSource struct {
	tokenURL string
	account  ServiceAccount
	admin    string
	key      *rsa.PrivateKey
	http     *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newTokenSource(tokenURL string, account ServiceAccount, admin string) (*tokenSource, error) {
	block, _ := pem.Decode([]byte(account.PrivateKey))
	if block == nil {
		return nil, errors.New("service-account private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse service-account private_key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service-account private_key is not an RSA key")
	}
	return &tokenSource{tokenURL: tokenURL, account: account, admin: admin, key: key,
		http: &http.Client{Timeout: 60 * time.Second}}, nil
}

func (t *tokenSource) assertion(now time.Time) (string, error) {
	encode := func(v any) (string, error) {
		data, err := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data), err
	}
	header, err := encode(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := encode(map[string]any{
		"iss": t.account.ClientEmail, "sub": t.admin, "aud": t.tokenURL,
		"scope": strings.Join(scopes, " "), "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	signed := header + "." + claims
	digest := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(nil, t.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign service-account JWT: %w", err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (t *tokenSource) authorize(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Now().Before(t.expires) {
		return "Bearer " + t.token, nil
	}
	assertion, err := t.assertion(time.Now())
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build Google token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request a Google token: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode the Google token response (%s): %w", resp.Status, err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("get a Google token (%s): %s %s; check domain-wide delegation for the service account and GOOGLE_ADMIN_EMAIL",
			resp.Status, body.Error, body.Description)
	}
	t.token = body.AccessToken
	t.expires = time.Now().Add(time.Duration(max(body.ExpiresIn, 120))*time.Second - time.Minute)
	return "Bearer " + t.token, nil
}

type Client struct {
	directory *restapi.Client
	sites     *restapi.Client
}

// NewClient signs in as account acting for admin. siteURL may be empty for
// the public Site Verification API.
func NewClient(baseURL, siteURL, tokenURL string, account ServiceAccount, admin string) (*Client, error) {
	tokens, err := newTokenSource(tokenURL, account, admin)
	if err != nil {
		return nil, err
	}
	return &Client{
		directory: restapi.New("Google Directory", baseURL, tokens.authorize),
		sites:     restapi.New("Google Site Verification", siteURL, tokens.authorize),
	}, nil
}

type Domain struct {
	Name     string `json:"domainName"`
	Verified bool   `json:"verified"`
}

// Domain returns the domain, or nil when the customer does not have it.
func (c *Client) Domain(ctx context.Context, name string) (*Domain, error) {
	var out Domain
	err := c.directory.Do(ctx, http.MethodGet, "/customer/my_customer/domains/"+url.PathEscape(name), nil, &out)
	var apiErr *restapi.APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AddDomain(ctx context.Context, name string) error {
	return c.directory.Do(ctx, http.MethodPost, "/customer/my_customer/domains",
		map[string]string{"domainName": name}, nil)
}

func site(name string) map[string]string {
	return map[string]string{"type": "INET_DOMAIN", "identifier": name}
}

// VerificationToken is the TXT value that proves the domain is ours.
func (c *Client) VerificationToken(ctx context.Context, name string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	err := c.sites.Do(ctx, http.MethodPost, "/token",
		map[string]any{"site": site(name), "verificationMethod": "DNS_TXT"}, &out)
	return out.Token, err
}

func (c *Client) Verify(ctx context.Context, name string) error {
	return c.sites.Do(ctx, http.MethodPost, "/webResource?verificationMethod=DNS_TXT",
		map[string]any{"site": site(name)}, nil)
}

type UserName struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type User struct {
	ID           string   `json:"id,omitempty"`
	PrimaryEmail string   `json:"primaryEmail"`
	Aliases      []string `json:"aliases,omitempty"`
	Name         UserName `json:"name"`
	Password     string   `json:"password,omitempty"`
	// ChangePasswordAtNextLogin makes a handed-over credential single-use.
	ChangePasswordAtNextLogin bool `json:"changePasswordAtNextLogin,omitempty"`
}

// Users lists every user on the domain, page by page.
func (c *Client) Users(ctx context.Context, domain string) ([]User, error) {
	var all []User
	token := ""
	for {
		query := url.Values{"domain": {domain}, "maxResults": {"500"}}
		if token != "" {
			query.Set("pageToken", token)
		}
		var page struct {
			Users         []User `json:"users"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.directory.Do(ctx, http.MethodGet, "/users?"+query.Encode(), nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Users...)
		if token = page.NextPageToken; token == "" {
			return all, nil
		}
	}
}

func (c *Client) AddUser(ctx context.Context, user User) error {
	return c.directory.Do(ctx, http.MethodPost, "/users", user, nil)
}

func (c *Client) DeleteUser(ctx context.Context, key string) error {
	return c.directory.Do(ctx, http.MethodDelete, "/users/"+url.PathEscape(key), nil, nil)
}

func (c *Client) AddAlias(ctx context.Context, user, alias string) error {
	return c.directory.Do(ctx, http.MethodPost, "/users/"+url.PathEscape(user)+"/aliases",
		map[string]string{"alias": alias}, nil)
}

func (c *Client) DeleteAlias(ctx context.Context, user, alias string) error {
	return c.directory.Do(ctx, http.MethodDelete,
		"/users/"+url.PathEscape(user)+"/aliases/"+url.PathEscape(alias), nil, nil)
}
