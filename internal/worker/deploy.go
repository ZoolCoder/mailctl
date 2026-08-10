package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/zoolcoder/mailctl/internal/cfapi"
)

// moduleFilename is both the uploaded part name and the main_module value.
const moduleFilename = "worker.mjs"

type Deployer struct {
	api       *cfapi.Client
	accountID string
}

func New(api *cfapi.Client, accountID string) *Deployer {
	return &Deployer{api: api, accountID: accountID}
}

func (d *Deployer) scriptPath(name string) string {
	return "/accounts/" + d.accountID + "/workers/scripts/" + name
}

// ScriptMatches reports whether the deployed script is byte-identical to
// source. A script that does not exist reports false, not an error.
func (d *Deployer) ScriptMatches(ctx context.Context, name, source string) (bool, error) {
	body, contentType, found, err := d.api.Raw(ctx, d.scriptPath(name))
	if err != nil {
		return false, fmt.Errorf("read Worker script %s: %w", name, err)
	}
	if !found {
		return false, nil
	}

	live, err := extractModule(contentType, body)
	if err != nil {
		return false, fmt.Errorf("read Worker script %s: %w", name, err)
	}
	return strings.TrimSpace(live) == strings.TrimSpace(source), nil
}

// extractModule returns the JavaScript module source to compare against a
// generated one. Cloudflare is very likely to return a main_module Worker's
// script as multipart/form-data rather than raw JavaScript, so the module
// part must be located and read; any other content type is compared as
// plain text, as before.
func extractModule(contentType string, body []byte) (string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return string(body), nil
	}

	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("parse multipart Worker script response: %w", err)
		}
		if part.FormName() == moduleFilename || part.FileName() == moduleFilename {
			data, err := io.ReadAll(part)
			if err != nil {
				return "", fmt.Errorf("read multipart Worker module part: %w", err)
			}
			return string(data), nil
		}
	}
	return "", fmt.Errorf("multipart Worker script response has no part named %s", moduleFilename)
}

// Upload replaces the script. The upload is a multipart form with a JSON
// metadata part naming the entry module, plus the module itself.
func (d *Deployer) Upload(ctx context.Context, name, source string) error {
	metadata := fmt.Sprintf(`{"main_module":%q,"compatibility_date":%q}`, moduleFilename, CompatibilityDate)

	parts := []cfapi.Part{
		{Name: "metadata", ContentType: "application/json", Data: []byte(metadata)},
		{
			Name:        moduleFilename,
			Filename:    moduleFilename,
			ContentType: "application/javascript+module",
			Data:        []byte(source),
		},
	}
	if err := d.api.Multipart(ctx, http.MethodPut, d.scriptPath(name), parts, nil); err != nil {
		return fmt.Errorf("upload Worker script %s: %w", name, err)
	}
	return nil
}

type attachedDomain struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	ZoneID   string `json:"zone_id"`
	Service  string `json:"service"`
}

// DomainAttached reports whether a custom domain is already bound to the
// given Worker service. Matching on hostname and zone alone would report a
// hostname bound to a different Worker as attached, and mailctl would never
// rebind it to the one it actually manages.
func (d *Deployer) DomainAttached(ctx context.Context, hostname, zoneID, service string) (bool, error) {
	domains, err := cfapi.List[attachedDomain](ctx, d.api, "/accounts/"+d.accountID+"/workers/domains")
	if err != nil {
		return false, fmt.Errorf("list Worker custom domains: %w", err)
	}
	for _, domain := range domains {
		if strings.EqualFold(domain.Hostname, hostname) && domain.ZoneID == zoneID &&
			domain.Service == service {
			return true, nil
		}
	}
	return false, nil
}

// AttachDomain binds hostname to a script. Cloudflare provisions the DNS record
// and the certificate, which is why mailctl publishes no record for this name.
func (d *Deployer) AttachDomain(ctx context.Context, hostname, zoneID, scriptName string) error {
	payload := map[string]any{
		"environment": "production",
		"hostname":    hostname,
		"service":     scriptName,
		"zone_id":     zoneID,
	}
	if err := d.api.Do(ctx, http.MethodPut, "/accounts/"+d.accountID+"/workers/domains", payload, nil); err != nil {
		return fmt.Errorf("bind %s to Worker %s: %w", hostname, scriptName, err)
	}
	return nil
}
