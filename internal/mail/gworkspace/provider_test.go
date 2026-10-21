package gworkspace

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

func testAccount(t *testing.T) (ServiceAccount, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return ServiceAccount{ClientEmail: "bot@p.iam.gserviceaccount.com", PrivateKey: string(pemKey)}, &key.PublicKey
}

// serve fakes the token endpoint, the Directory API and Site Verification.
// It checks every JWT's signature and claims before handing out a token.
func serve(t *testing.T, responses map[string]string) (*Provider, *[]string) {
	t.Helper()
	account, public := testAccount(t)
	var calls []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			checkAssertion(t, r, public, server.URL+"/token")
			fmt.Fprint(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		calls = append(calls, strings.TrimSpace(key+" "+string(body)))
		response, ok := responses[key]
		if !ok {
			response = `{}`
		}
		if response == "404" {
			w.WriteHeader(http.StatusNotFound)
			response = `{"error":{"code":404,"message":"Domain not found."}}`
		}
		fmt.Fprint(w, response)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, server.URL+"/siteVerification", server.URL+"/token", account, "admin@a.com")
	if err != nil {
		t.Fatal(err)
	}
	return &Provider{client: client}, &calls
}

func checkAssertion(t *testing.T, r *http.Request, public *rsa.PublicKey, audience string) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
	}
	parts := strings.Split(r.Form.Get("assertion"), ".")
	if len(parts) != 3 {
		t.Fatalf("assertion has %d parts", len(parts))
	}
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature); err != nil {
		t.Errorf("JWT signature: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(raw, &claims)
	if claims["sub"] != "admin@a.com" || claims["aud"] != audience || !strings.Contains(claims["scope"].(string), "admin.directory.user") {
		t.Errorf("claims = %v", claims)
	}
}

const (
	tokenPath  = "POST /siteVerification/token"
	domainPath = "GET /customer/my_customer/domains/a.com"
	usersPath  = "GET /users"
)

func domainConfig() config.Domain {
	return config.Domain{
		Name:      "a.com",
		Mail:      config.Mail{Providers: []string{"gworkspace"}},
		Mailboxes: []config.Mailbox{{Address: "jane@a.com", DisplayName: "Jane van Dam"}},
		Aliases:   []config.Alias{{Match: "info", To: []string{"jane@a.com"}}},
	}
}

func TestDesiredDNSPublishesOwnershipBeforeTheDomainExists(t *testing.T) {
	provider, _ := serve(t, map[string]string{
		tokenPath:  `{"method":"DNS_TXT","token":"google-site-verification=abc"}`,
		domainPath: "404",
	})
	records, err := provider.DesiredDNS(context.Background(), domainConfig())
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	if len(records) != 1 || records[0].Kind != dns.KindOwnership || records[0].Content != "google-site-verification=abc" {
		t.Fatalf("records = %+v, want only the ownership TXT", records)
	}
}

func TestDesiredDNSPublishesMailRecordsOnceVerified(t *testing.T) {
	provider, _ := serve(t, map[string]string{
		tokenPath:  `{"token":"google-site-verification=abc"}`,
		domainPath: `{"domainName":"a.com","verified":true}`,
	})
	d := domainConfig()
	d.Mail.GWorkspace = &config.GWorkspace{DKIM: "v=DKIM1; k=rsa; p=KEY"}

	records, err := provider.DesiredDNS(context.Background(), d)
	if err != nil {
		t.Fatalf("DesiredDNS: %v", err)
	}
	got := map[string]dns.Kind{}
	for _, r := range records {
		got[fmt.Sprintf("%s %s %s %d", r.Type, r.Name, r.Content, r.Priority)] = r.Kind
	}
	for want, kind := range map[string]dns.Kind{
		"TXT a.com google-site-verification=abc 0":            dns.KindOwnership,
		"MX a.com smtp.google.com 1":                          dns.KindMX,
		"TXT a.com v=spf1 include:_spf.google.com ~all 0":     dns.KindSPF,
		"TXT google._domainkey.a.com v=DKIM1; k=rsa; p=KEY 0": dns.KindDKIM,
	} {
		if got[want] != kind {
			t.Errorf("record %q kind = %v, want %v (all: %v)", want, got[want], kind, got)
		}
	}
}

func TestPlanAddsThenVerifiesTheDomain(t *testing.T) {
	provider, calls := serve(t, map[string]string{domainPath: "404"})
	d := domainConfig()
	ctx := context.Background()
	opts := mail.Options{Secrets: secret.NewResolver(nil)}

	actual, err := provider.Actual(ctx, d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, opts)
	if err != nil || len(actions) != 1 || actions[0].Op != plan.OpCreate {
		t.Fatalf("Plan = %+v, %v; want one domain create", actions, err)
	}
	if err := actions[0].Do(ctx); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; last != `POST /customer/my_customer/domains {"domainName":"a.com"}` {
		t.Errorf("create call = %q", last)
	}

	actions, _ = provider.Plan(d, mail.State{DomainExists: true}, opts)
	if len(actions) != 1 || actions[0].Op != plan.OpUpdate {
		t.Fatalf("actions = %+v, want one verify", actions)
	}
	if err := actions[0].Do(ctx); err != nil {
		t.Fatal(err)
	}
	if last := (*calls)[len(*calls)-1]; !strings.HasPrefix(last, "POST /siteVerification/webResource") ||
		!strings.Contains(last, `"identifier":"a.com"`) {
		t.Errorf("verify call = %q", last)
	}
}

func TestPlanCreatesUsersWithNamesAndAliases(t *testing.T) {
	provider, calls := serve(t, map[string]string{
		domainPath: `{"domainName":"a.com","verified":true}`,
		usersPath:  `{"users":[]}`,
	})
	d := domainConfig()
	ctx := context.Background()
	actual, err := provider.Actual(ctx, d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	actions, err := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(func(string) string { return "pw-12345" })})
	if err != nil || len(actions) != 2 {
		t.Fatalf("Plan = %+v, %v; want a user and an alias", actions, err)
	}
	for _, a := range actions {
		if strings.Contains(a.Detail, "pw-12345") {
			t.Fatalf("detail leaked the credential: %q", a.Detail)
		}
		if err := a.Do(ctx); err != nil {
			t.Fatal(err)
		}
	}
	user, alias := (*calls)[len(*calls)-2], (*calls)[len(*calls)-1]
	if !strings.Contains(user, `"givenName":"Jane","familyName":"van Dam"`) ||
		!strings.Contains(user, `"changePasswordAtNextLogin":true`) {
		t.Errorf("user call = %q", user)
	}
	if alias != `POST /users/jane@a.com/aliases {"alias":"info@a.com"}` {
		t.Errorf("alias call = %q", alias)
	}
}

func TestPlanIsEmptyWhenConvergedAndPrunesWhenAsked(t *testing.T) {
	provider, _ := serve(t, map[string]string{
		domainPath: `{"domainName":"a.com","verified":true}`,
		usersPath: `{"users":[{"id":"1","primaryEmail":"jane@a.com","aliases":["info@a.com","old@a.com"]},
			{"id":"2","primaryEmail":"gone@a.com"}]}`,
	})
	d := domainConfig()
	actual, err := provider.Actual(context.Background(), d)
	if err != nil {
		t.Fatalf("Actual: %v", err)
	}
	if actions, _ := provider.Plan(d, actual, mail.Options{Secrets: secret.NewResolver(nil)}); len(actions) != 0 {
		t.Errorf("converged plan = %+v", actions)
	}
	actions, _ := provider.Plan(d, actual, mail.Options{Prune: true, Secrets: secret.NewResolver(nil)})
	if len(actions) != 1 || !strings.Contains(actions[0].Detail, "old@a.com") {
		t.Errorf("prune = %+v, want only old@a.com (users need -prune-mailboxes)", actions)
	}
	actions, _ = provider.Plan(d, actual, mail.Options{Prune: true, PruneMailboxes: true, Secrets: secret.NewResolver(nil)})
	if len(actions) != 2 || !strings.Contains(actions[0].Detail, "gone@a.com") {
		t.Errorf("prune mailboxes = %+v", actions)
	}
}

func TestUserNameFallsBackToTheLocalPart(t *testing.T) {
	if got := userName(config.Mailbox{Address: "ops@a.com"}); got != (UserName{"ops", "ops"}) {
		t.Errorf("userName = %+v", got)
	}
}

func TestLoadServiceAccountReadsJSONOrAFile(t *testing.T) {
	content := `{"client_email":"bot@p","private_key":"KEY"}`
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{content, path} {
		account, err := LoadServiceAccount(value)
		if err != nil || account.ClientEmail != "bot@p" {
			t.Errorf("LoadServiceAccount(%q) = %+v, %v", value, account, err)
		}
	}
	if _, err := LoadServiceAccount(`{"client_email":"bot@p"}`); err == nil {
		t.Error("a key without private_key was accepted")
	}
}
