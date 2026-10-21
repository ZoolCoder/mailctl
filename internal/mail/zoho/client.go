package zoho

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zoolcoder/mailctl/internal/restapi"
)

// Region is one Zoho data centre: its Mail API host, its accounts (OAuth)
// host and the domain its MX and verification hosts live under.
type Region struct {
	API      string
	Accounts string
	Mail     string
}

// Regions maps mail.zoho.region to its hosts. Zoho documents the com hosts;
// the others follow the same pattern on each data centre's domain.
var Regions = map[string]Region{
	"com":    {"https://mail.zoho.com", "https://accounts.zoho.com", "zoho.com"},
	"eu":     {"https://mail.zoho.eu", "https://accounts.zoho.eu", "zoho.eu"},
	"in":     {"https://mail.zoho.in", "https://accounts.zoho.in", "zoho.in"},
	"com.au": {"https://mail.zoho.com.au", "https://accounts.zoho.com.au", "zoho.com.au"},
	"jp":     {"https://mail.zoho.jp", "https://accounts.zoho.jp", "zoho.jp"},
	"ca":     {"https://mail.zohocloud.ca", "https://accounts.zohocloud.ca", "zohocloud.ca"},
	"sa":     {"https://mail.zoho.sa", "https://accounts.zoho.sa", "zoho.sa"},
	"uk":     {"https://mail.zoho.uk", "https://accounts.zoho.uk", "zoho.uk"},
}

// Credentials are the OAuth self-client values. OrgID (zoid) is optional:
// when empty it is read from the API once.
type Credentials struct {
	ClientID     string
	ClientSecret string
	RefreshToken string
	OrgID        string
}

type Client struct {
	api   *restapi.Client
	orgID string
}

func NewClient(apiURL, accountsURL string, creds Credentials) *Client {
	tokens := &tokenSource{accountsURL: strings.TrimRight(accountsURL, "/"), creds: creds,
		http: &http.Client{Timeout: 60 * time.Second}}
	return &Client{api: restapi.New("Zoho Mail", apiURL, tokens.authorize), orgID: creds.OrgID}
}

// tokenSource trades the refresh token for an access token and caches it
// until a minute before it expires.
type tokenSource struct {
	accountsURL string
	creds       Credentials
	http        *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

func (t *tokenSource) authorize(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && time.Now().Before(t.expires) {
		return "Zoho-oauthtoken " + t.token, nil
	}

	query := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {t.creds.RefreshToken},
		"client_id":     {t.creds.ClientID},
		"client_secret": {t.creds.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		t.accountsURL+"/oauth/v2/token?"+query.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("build Zoho token request: %w", err)
	}
	resp, err := t.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("request a Zoho token: %w", err)
	}
	defer resp.Body.Close()

	// Zoho answers a bad refresh token with HTTP 200 and an error field.
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode the Zoho token response (%s): %w", resp.Status, err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("get a Zoho token (%s): %s; check ZOHO_CLIENT_ID, ZOHO_CLIENT_SECRET, ZOHO_REFRESH_TOKEN and mail.zoho.region",
			resp.Status, body.Error)
	}
	t.token = body.AccessToken
	t.expires = time.Now().Add(time.Duration(max(body.ExpiresIn, 120))*time.Second - time.Minute)
	return "Zoho-oauthtoken " + t.token, nil
}

// envelope is Zoho's answer shape: a status block and the payload in data.
type envelope struct {
	Status struct {
		Code        int    `json:"code"`
		Description string `json:"description"`
	} `json:"status"`
	Data json.RawMessage `json:"data"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var env envelope
	if err := c.api.Do(ctx, method, path, body, &env); err != nil {
		return err
	}
	if env.Status.Code >= 400 {
		return fmt.Errorf("%s %s at Zoho Mail: %d %s: %s", method, path, env.Status.Code,
			env.Status.Description, strings.TrimSpace(string(env.Data)))
	}
	if out == nil || len(env.Data) == 0 {
		return nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("decode Zoho Mail %s %s data: %w", method, path, err)
	}
	return nil
}

func (c *Client) org(ctx context.Context) (string, error) {
	if c.orgID != "" {
		return c.orgID, nil
	}
	var org struct {
		ZOID ID `json:"zoid"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/organization", nil, &org); err != nil {
		return "", err
	}
	if org.ZOID == "" {
		return "", errors.New("no organization id from Zoho Mail; set ZOHO_ORG_ID")
	}
	c.orgID = string(org.ZOID)
	return c.orgID, nil
}

func (c *Client) path(ctx context.Context, format string, args ...any) (string, error) {
	org, err := c.org(ctx)
	if err != nil {
		return "", err
	}
	return "/api/organization/" + url.PathEscape(org) + fmt.Sprintf(format, args...), nil
}

// ID is a Zoho identifier; the API sends some as numbers, some as strings.
type ID string

func (id *ID) UnmarshalJSON(data []byte) error {
	*id = ID(strings.Trim(string(data), `"`))
	if *id == "null" {
		*id = ""
	}
	return nil
}

// Flag is a boolean the API sometimes sends as a string.
type Flag bool

func (f *Flag) UnmarshalJSON(data []byte) error {
	value, err := strconv.ParseBool(strings.Trim(string(data), `"`))
	*f = Flag(err == nil && value)
	return nil
}

type DKIM struct {
	ID         ID     `json:"dkimId"`
	Selector   string `json:"selector"`
	PublicKey  string `json:"publicKey"`
	IsVerified Flag   `json:"isVerified"`
}

type Domain struct {
	Name               string `json:"domainName"`
	Verified           Flag   `json:"verificationStatus"`
	CNAMEVerification  string `json:"CNAMEVerificationCode"`
	MXStatus           Flag   `json:"mxstatus"`
	SPFStatus          Flag   `json:"spfstatus"`
	MailHostingEnabled Flag   `json:"mailHostingEnabled"`
	// CatchAllAddress is not in Zoho's documented domain fields; it is read
	// when present so an unchanged catch-all is not re-sent every run.
	CatchAllAddress string `json:"catchAllAddress"`
	DKIM            []DKIM `json:"dkimDetailList"`
}

func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	path, err := c.path(ctx, "/domains")
	if err != nil {
		return nil, err
	}
	var out struct {
		Domains []Domain `json:"domainVO"`
	}
	err = c.do(ctx, http.MethodGet, path, nil, &out)
	return out.Domains, err
}

func (c *Client) Domain(ctx context.Context, name string) (Domain, error) {
	path, err := c.path(ctx, "/domains/%s", url.PathEscape(name))
	if err != nil {
		return Domain{}, err
	}
	var out Domain
	err = c.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func (c *Client) AddDomain(ctx context.Context, name string) error {
	path, err := c.path(ctx, "/domains")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, map[string]string{"domainName": name}, nil)
}

// domainMode runs one PUT /domains/{name} mode. The verify modes answer HTTP
// 200 with data.status false on failure, so that is checked too.
func (c *Client) domainMode(ctx context.Context, name string, body map[string]any) (map[string]any, error) {
	path, err := c.path(ctx, "/domains/%s", url.PathEscape(name))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := c.do(ctx, http.MethodPut, path, body, &out); err != nil {
		return nil, err
	}
	if status, ok := out["status"].(bool); ok && !status {
		return out, fmt.Errorf("%s for %s at Zoho Mail failed: %v", body["mode"], name, out["error"])
	}
	return out, nil
}

func (c *Client) VerifyDomain(ctx context.Context, name string) error {
	_, err := c.domainMode(ctx, name, map[string]any{"mode": "verifyDomainByTXT"})
	return err
}

func (c *Client) EnableHosting(ctx context.Context, name string) error {
	_, err := c.domainMode(ctx, name, map[string]any{"mode": "enableMailHosting"})
	return err
}

func (c *Client) AddDKIM(ctx context.Context, name, selector string) error {
	_, err := c.domainMode(ctx, name, map[string]any{
		"mode": "addDkimDetail", "selector": selector, "isDefault": true, "keySize": 2048})
	return err
}

func (c *Client) VerifyDKIM(ctx context.Context, name string, id ID) error {
	out, err := c.domainMode(ctx, name, map[string]any{"mode": "verifyDkimKey", "dkimId": json.Number(id)})
	if err != nil {
		return err
	}
	if ok, found := out["dkimstatus"].(bool); found && !ok {
		return fmt.Errorf("the DKIM key for %s is not verified at Zoho Mail yet; the TXT record may not have propagated, rerun later", name)
	}
	return nil
}

func (c *Client) SetCatchAll(ctx context.Context, name, address string) error {
	_, err := c.domainMode(ctx, name, map[string]any{"mode": "addCatchAllAddress", "catchAllAddress": address})
	return err
}

type EmailAddress struct {
	MailID  string `json:"mailId"`
	IsAlias Flag   `json:"isAlias"`
}

type Account struct {
	ZUID         ID             `json:"zuid"`
	Primary      string         `json:"primaryEmailAddress"`
	DisplayName  string         `json:"displayName"`
	EmailAddress []EmailAddress `json:"emailAddress"`
}

// pageSize is how many accounts one list call asks for.
const pageSize = 100

// Accounts lists every account in the organisation, page by page.
func (c *Client) Accounts(ctx context.Context) ([]Account, error) {
	var all []Account
	for start := 0; ; start += pageSize {
		path, err := c.path(ctx, "/accounts?start=%d&limit=%d", start, pageSize)
		if err != nil {
			return nil, err
		}
		var page []Account
		if err := c.do(ctx, http.MethodGet, path, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < pageSize {
			return all, nil
		}
	}
}

type NewAccount struct {
	Address     string `json:"primaryEmailAddress"`
	Password    string `json:"password"`
	DisplayName string `json:"displayName,omitempty"`
	FirstName   string `json:"firstName,omitempty"`
	Role        string `json:"role"`
}

func (c *Client) AddAccount(ctx context.Context, account NewAccount) error {
	path, err := c.path(ctx, "/accounts")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, account, nil)
}

func (c *Client) DeleteAccount(ctx context.Context, address string) error {
	path, err := c.path(ctx, "/accounts")
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodDelete, path, map[string][]string{"emailList": {address}}, nil)
}

func (c *Client) alias(ctx context.Context, mode string, zuid ID, address string) error {
	path, err := c.path(ctx, "/accounts/%s", url.PathEscape(string(zuid)))
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPut, path, map[string]any{
		"zuid": string(zuid), "mode": mode, "emailAlias": []string{address}}, nil)
}

func (c *Client) AddAlias(ctx context.Context, zuid ID, address string) error {
	return c.alias(ctx, "addEmailAlias", zuid, address)
}

func (c *Client) DeleteAlias(ctx context.Context, zuid ID, address string) error {
	return c.alias(ctx, "deleteEmailAlias", zuid, address)
}
