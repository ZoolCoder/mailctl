package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Load reads path, expands ${VAR} references using getenv, applies defaults,
// and validates the result. getenv may be nil, in which case os.Getenv is used.
func Load(path string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	expanded, err := expandEnv(data, getenv)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	decoder := yaml.NewDecoder(strings.NewReader(string(expanded)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.Version != SchemaVersion {
		return Config{}, fmt.Errorf(
			"config %s declares version %d; this build understands version %d only",
			path, cfg.Version, SchemaVersion)
	}

	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s:\n%w", path, err)
	}
	return cfg, nil
}

// expandEnv replaces every ${VAR} with its value, except inside a YAML
// comment. An unset or empty variable referenced outside a comment is an
// error, never a silent empty string; the same reference inside a comment is
// left untouched and never reported as missing.
//
// Byte offsets outside comments are unaffected by this scan (only matched
// ${VAR} spans are rewritten, exactly as before), so line numbers reported
// from the later YAML decode stay correct.
func expandEnv(data []byte, getenv func(string) string) ([]byte, error) {
	mask := commentMask(data)
	var missing []error
	seen := map[string]bool{}

	var out bytes.Buffer
	last := 0
	for _, m := range envRef.FindAllSubmatchIndex(data, -1) {
		start, end := m[0], m[1]
		if mask[start] {
			// Inside a comment: not a real reference, leave it untouched.
			continue
		}
		out.Write(data[last:start])
		name := string(data[m[2]:m[3]])
		value := getenv(name)
		if value == "" {
			if !seen[name] {
				seen[name] = true
				missing = append(missing,
					fmt.Errorf("environment variable %s is referenced in the config but is not set", name))
			}
			out.Write(data[start:end])
		} else {
			out.WriteString(value)
		}
		last = end
	}
	out.Write(data[last:])

	return out.Bytes(), errors.Join(missing...)
}

// commentMask reports, for each byte in data, whether that byte lies inside a
// YAML comment. A '#' starts a comment only when it is not inside a
// single- or double-quoted scalar and is at the start of a line or preceded
// by whitespace.
func commentMask(data []byte) []bool {
	mask := make([]bool, len(data))
	const (
		none = iota
		single
		double
	)
	quote := none
	inComment := false
	prev := byte('\n') // start of file behaves like start of line

	for i := 0; i < len(data); i++ {
		b := data[i]

		if inComment {
			mask[i] = true
			if b == '\n' {
				inComment = false
			}
			prev = b
			continue
		}

		switch quote {
		case single:
			if b == '\'' {
				if i+1 < len(data) && data[i+1] == '\'' {
					// Doubled '' is an escaped literal quote.
					i++
					prev = data[i]
					continue
				}
				quote = none
			}
		case double:
			if b == '\\' && i+1 < len(data) {
				i++
				prev = data[i]
				continue
			}
			if b == '"' {
				quote = none
			}
		default:
			switch b {
			case '\'':
				quote = single
			case '"':
				quote = double
			case '#':
				if prev == '\n' || prev == ' ' || prev == '\t' {
					inComment = true
					mask[i] = true
				}
			}
		}
		prev = b
	}
	return mask
}

// ApplyDefaults sets default values for configuration fields that are not explicitly set.
func (c *Config) ApplyDefaults() {
	if c.Cloudflare.BaseURL == "" {
		c.Cloudflare.BaseURL = DefaultCloudflareBaseURL
	}
	if c.Cloudflare.TTL == 0 {
		c.Cloudflare.TTL = DefaultTTL
	}
	if c.Purelymail.BaseURL == "" {
		c.Purelymail.BaseURL = DefaultPurelymailBaseURL
	}

	for i := range c.Domains {
		d := &c.Domains[i]
		d.Name = strings.ToLower(strings.TrimSpace(d.Name))
		d.ZoneName = strings.ToLower(strings.TrimSpace(d.ZoneName))
		if d.ZoneName == "" {
			d.ZoneName = d.Name
		}
		for j := range d.Mailboxes {
			m := &d.Mailboxes[j]
			m.Address = strings.ToLower(strings.TrimSpace(m.Address))
			m.PasswordEnv = strings.TrimSpace(m.PasswordEnv)
			for k := range m.Recovery {
				m.Recovery[k].Type = strings.ToLower(strings.TrimSpace(m.Recovery[k].Type))
				m.Recovery[k].Target = strings.TrimSpace(m.Recovery[k].Target)
			}
		}
		for j := range d.Aliases {
			d.Aliases[j].Match = strings.ToLower(strings.TrimSpace(d.Aliases[j].Match))
			for k := range d.Aliases[j].To {
				d.Aliases[j].To[k] = strings.ToLower(strings.TrimSpace(d.Aliases[j].To[k]))
			}
		}
		if d.CatchAll != nil {
			for k := range d.CatchAll.To {
				d.CatchAll.To[k] = strings.ToLower(strings.TrimSpace(d.CatchAll.To[k]))
			}
		}
		if d.Deliverability.DMARC != nil && d.Deliverability.DMARC.Pct == 0 {
			d.Deliverability.DMARC.Pct = DefaultDMARCPct
		}
	}
}
