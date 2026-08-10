package config

import (
	"strings"
	"testing"
)

func TestValidateCollectsEveryError(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "user@other.com"}, {Address: "not-an-email"}},
			Aliases:   []Alias{{Match: "info", To: nil}},
		}},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"user@other.com", "not-an-email", "info"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q; got:\n%s", want, err)
		}
	}
}

func TestValidateRejectsDuplicateMailbox(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "a@example.com"}, {Address: "a@example.com"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v, want a duplicate-mailbox error", err)
	}
}

func TestValidateRejectsMailboxesOnRoutingOnlyProvider(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"cfrouting"}},
			Mailboxes: []Mailbox{{Address: "a@example.com"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "cfrouting") {
		t.Fatalf("err = %v, want an error naming cfrouting", err)
	}
}

// TestValidateRejectsTwoInboundProviders is the regression guard for the seam
// the singleton-kind guard narrowing opened: purelymail and cfrouting both
// publish MX and both create alias routing rules, so pairing them means split
// or duplicate inbound delivery. The old collision guard rejected this
// combination for the wrong reason (a DKIM/MX key collision); now that it is
// narrowed to singleton kinds, config.Validate must reject it explicitly.
func TestValidateRejectsTwoInboundProviders(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{"purelymail", "cfrouting"}},
		}},
	}

	err := cfg.Validate()
	if err == nil ||
		!strings.Contains(err.Error(), "purelymail") ||
		!strings.Contains(err.Error(), "cfrouting") ||
		!strings.Contains(err.Error(), "example.com") ||
		!strings.Contains(err.Error(), "one inbound provider") {
		t.Fatalf("err = %v, want an error naming purelymail, cfrouting, example.com, and the one-inbound-provider rule", err)
	}
}

// TestValidateAllowsPurelymailWithCfsending guards against the inbound-provider
// guard overreaching: cfsending is outbound-only, so it may still pair with
// purelymail.
func TestValidateAllowsPurelymailWithCfsending(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail", "cfsending"}},
			Mailboxes: []Mailbox{{Address: "a@example.com"}},
		}},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v, want purelymail+cfsending to be accepted", err)
	}
}

// TestValidateAllowsCfroutingWithCfsending mirrors
// TestValidateAllowsPurelymailWithCfsending for cfrouting.
func TestValidateAllowsCfroutingWithCfsending(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{"cfrouting", "cfsending"}},
		}},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v, want cfrouting+cfsending to be accepted", err)
	}
}

func TestValidateDMARC(t *testing.T) {
	tests := []struct {
		name    string
		dmarc   DMARC
		wantErr string
	}{
		{"bad policy", DMARC{Policy: "drop", Pct: 100}, "policy"},
		{"pct too high", DMARC{Policy: "reject", Pct: 101}, "pct"},
		{"pct too low", DMARC{Policy: "reject", Pct: -1}, "pct"},
		{"valid", DMARC{Policy: "quarantine", Pct: 100, SubdomainPolicy: "reject"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dmarc := tt.dmarc
			cfg := Config{
				Version: SchemaVersion,
				Domains: []Domain{{
					Name:           "example.com",
					ZoneName:       "example.com",
					Mail:           Mail{Providers: []string{"purelymail"}},
					Mailboxes:      []Mailbox{{Address: "a@example.com"}},
					Deliverability: Deliverability{DMARC: &dmarc},
				}},
			}
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want mention of %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsUnknownProvider(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{"gmail"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "gmail") {
		t.Fatalf("err = %v, want an error naming the unknown provider", err)
	}
}

// TestValidateAcceptsNoDomains guards against reintroducing the "at least one
// domain" rule at the Validate layer: that precondition belongs to the
// reconciling commands (plan, apply, audit, mailbox, alias), not to the
// config document itself, since import legitimately loads a config with no
// domains yet.
func TestValidateAcceptsNoDomains(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v, want an empty domains list to be accepted", err)
	}
}

func TestValidateRejectsDuplicateDomain(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{
			{
				Name:     "example.com",
				ZoneName: "example.com",
				Mail:     Mail{Providers: []string{"purelymail"}},
			},
			{
				Name:     "example.com",
				ZoneName: "example.com",
				Mail:     Mail{Providers: []string{"purelymail"}},
			},
		},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("err = %v, want duplicate domain error naming example.com", err)
	}
}

func TestValidateRequiresMailProvider(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mail.provider") {
		t.Fatalf("err = %v, want error requiring mail.provider", err)
	}
}

func TestValidateRejectsDuplicateAlias(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "admin@example.com"}},
			Aliases: []Alias{
				{Match: "info", To: []string{"admin@example.com"}},
				{Match: "info", To: []string{"admin@example.com"}},
			},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate alias") || !strings.Contains(err.Error(), "info") {
		t.Fatalf("err = %v, want duplicate alias error naming info", err)
	}
}

func TestValidateRejectsAliasMatchWithAt(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "admin@example.com"}},
			Aliases: []Alias{
				{Match: "info@example.com", To: []string{"admin@example.com"}},
			},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "info@example.com") || !strings.Contains(err.Error(), "local part") {
		t.Fatalf("err = %v, want error about alias match being local part", err)
	}
}

func TestValidateRejectsAliasTargetWithoutAt(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "admin@example.com"}},
			Aliases: []Alias{
				{Match: "info", To: []string{"not-an-email"}},
			},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not-an-email") || !strings.Contains(err.Error(), "email address") {
		t.Fatalf("err = %v, want error about alias target being email address", err)
	}
}

func TestValidateCatchAllRequiresTargets(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail:     Mail{Providers: []string{"purelymail"}},
			CatchAll: &CatchAll{To: []string{}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "catchAll") || !strings.Contains(err.Error(), "at least one") {
		t.Fatalf("err = %v, want error about catchAll requiring targets", err)
	}
}

func TestValidateRejectsCatchAllTargetWithoutAt(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:      "example.com",
			ZoneName:  "example.com",
			Mail:      Mail{Providers: []string{"purelymail"}},
			Mailboxes: []Mailbox{{Address: "admin@example.com"}},
			CatchAll:  &CatchAll{To: []string{"not-an-email"}},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "not-an-email") || !strings.Contains(err.Error(), "email address") {
		t.Fatalf("err = %v, want error about catchAll target being an email address", err)
	}
}

func TestValidateMailboxRecovery(t *testing.T) {
	tests := []struct {
		name       string
		recovery   []Recovery
		wantErrMsg string
	}{
		{"bad type", []Recovery{{Type: "sms", Target: "1234567890"}}, "must be email or phone"},
		{"email missing @", []Recovery{{Type: "email", Target: "invalid"}}, "not an email address"},
		{"phone missing target", []Recovery{{Type: "phone", Target: ""}}, "needs a target"},
		{"valid email", []Recovery{{Type: "email", Target: "recovery@example.com"}}, ""},
		{"valid phone", []Recovery{{Type: "phone", Target: "1234567890"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Version: SchemaVersion,
				Domains: []Domain{{
					Name:      "example.com",
					ZoneName:  "example.com",
					Mail:      Mail{Providers: []string{"purelymail"}},
					Mailboxes: []Mailbox{{Address: "user@example.com", Recovery: tt.recovery}},
				}},
			}
			err := cfg.Validate()
			switch {
			case tt.wantErrMsg == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErrMsg != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErrMsg)):
				t.Fatalf("err = %v, want mention of %q", err, tt.wantErrMsg)
			}
		})
	}
}

func TestValidateDMARCSubdomainPolicy(t *testing.T) {
	dmarc := DMARC{Policy: "reject", Pct: 100, SubdomainPolicy: "drop"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{DMARC: &dmarc},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "subdomainPolicy") || !strings.Contains(err.Error(), "drop") {
		t.Fatalf("err = %v, want error about invalid subdomainPolicy", err)
	}
}

func TestValidateMTAStsModeInvalid(t *testing.T) {
	mtaSts := MTASts{Mode: "paranoid"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "mtaSts.mode") || !strings.Contains(err.Error(), "paranoid") {
		t.Fatalf("err = %v, want error about invalid mtaSts.mode", err)
	}
}

func TestValidateMTAStsModeEnforceRequiresMX(t *testing.T) {
	mtaSts := MTASts{Mode: "enforce"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"cfsending"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "enforce") || !strings.Contains(err.Error(), "MX") {
		t.Fatalf("err = %v, want error about enforce requiring MX", err)
	}
}

func TestValidateMTAStsModeTestingRequiresMX(t *testing.T) {
	mtaSts := MTASts{Mode: "testing"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"cfsending"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "testing") || !strings.Contains(err.Error(), "MX") {
		t.Fatalf("err = %v, want error about testing requiring MX", err)
	}
}

func TestValidateMTAStsRejectsNegativeMaxAge(t *testing.T) {
	mtaSts := MTASts{Mode: "enforce", MaxAge: -5}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "maxAge") || !strings.Contains(err.Error(), "-5") {
		t.Fatalf("err = %v, want error about negative maxAge", err)
	}
}

func TestValidateBIMIRequiresLogo(t *testing.T) {
	bimi := BIMI{Logo: ""}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{BIMI: &bimi},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "bimi.logo") {
		t.Fatalf("err = %v, want error about bimi.logo being required", err)
	}
}

func TestValidateAccumulatesAcrossCategories(t *testing.T) {
	dmarc := DMARC{Policy: "drop", Pct: 100}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{
			{Name: "dup.com", ZoneName: "dup.com", Mail: Mail{Providers: []string{"purelymail"}}},
			{Name: "dup.com", ZoneName: "dup.com", Mail: Mail{Providers: []string{"purelymail"}}},
			{
				Name:           "example.com",
				ZoneName:       "example.com",
				Mail:           Mail{Providers: []string{"purelymail"}},
				Aliases:        []Alias{{Match: "info", To: nil}},
				Deliverability: Deliverability{DMARC: &dmarc},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation errors across categories")
	}
	// Check that errors from multiple categories are all present
	errStr := err.Error()
	if !strings.Contains(errStr, "dup.com") || !strings.Contains(errStr, "twice") {
		t.Errorf("error should mention duplicate domain; got: %s", errStr)
	}
	if !strings.Contains(errStr, "info") || !strings.Contains(errStr, "at least one") {
		t.Errorf("error should mention alias with no targets; got: %s", errStr)
	}
	if !strings.Contains(errStr, "policy") || !strings.Contains(errStr, "dmarc") {
		t.Errorf("error should mention invalid DMARC policy; got: %s", errStr)
	}
}

func TestValidateDMARCRUARejectsSemicolon(t *testing.T) {
	dmarc := DMARC{Policy: "reject", Pct: 100, RUA: "mailto:a@x.com; p=none"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{DMARC: &dmarc},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "dmarc.rua") || !strings.Contains(err.Error(), "semicolon") {
		t.Fatalf("err = %v, want error about semicolon in dmarc.rua", err)
	}
}

func TestValidateDMARCRUFRejectsSemicolon(t *testing.T) {
	dmarc := DMARC{Policy: "reject", Pct: 100, RUF: "mailto:f@x.com; sp=quarantine"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{DMARC: &dmarc},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "dmarc.ruf") || !strings.Contains(err.Error(), "semicolon") {
		t.Fatalf("err = %v, want error about semicolon in dmarc.ruf", err)
	}
}

func TestValidateDMARCRUARejectsWhitespace(t *testing.T) {
	dmarc := DMARC{Policy: "reject", Pct: 100, RUA: "mailto:a@x.com\tmailto:b@x.com"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{DMARC: &dmarc},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "dmarc.rua") || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("err = %v, want error about whitespace in dmarc.rua", err)
	}
}

func TestValidateTLSRptRejectsSemicolon(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{TLSRpt: "mailto:tls@x.com; p=testing"},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tlsRpt") || !strings.Contains(err.Error(), "semicolon") {
		t.Fatalf("err = %v, want error about semicolon in tlsRpt", err)
	}
}

func TestValidateTLSRptRejectsWhitespace(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{TLSRpt: "mailto:tls@x.com\nmailto:tls2@x.com"},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tlsRpt") || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("err = %v, want error about whitespace in tlsRpt", err)
	}
}

func TestValidateBIMILogoRejectsSemicolon(t *testing.T) {
	bimi := BIMI{Logo: "https://x.com/logo.svg; a="}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{BIMI: &bimi},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "bimi.logo") || !strings.Contains(err.Error(), "semicolon") {
		t.Fatalf("err = %v, want error about semicolon in bimi.logo", err)
	}
}

func TestValidateBIMILogoRejectsWhitespace(t *testing.T) {
	bimi := BIMI{Logo: "https://x.com/logo.svg \nhttps://y.com/logo.svg"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{BIMI: &bimi},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "bimi.logo") || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("err = %v, want error about whitespace in bimi.logo", err)
	}
}

func TestValidateBIMIVMCRejectsSemicolon(t *testing.T) {
	bimi := BIMI{Logo: "https://x.com/logo.svg", VMC: "https://x.com/vmc.pem; a="}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{BIMI: &bimi},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "bimi.vmc") || !strings.Contains(err.Error(), "semicolon") {
		t.Fatalf("err = %v, want error about semicolon in bimi.vmc", err)
	}
}

func TestValidateBIMIVMCRejectsWhitespace(t *testing.T) {
	bimi := BIMI{Logo: "https://x.com/logo.svg", VMC: "https://x.com/vmc.pem \r https://y.com/vmc.pem"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{BIMI: &bimi},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "bimi.vmc") || !strings.Contains(err.Error(), "whitespace") {
		t.Fatalf("err = %v, want error about whitespace in bimi.vmc", err)
	}
}

func TestValidateSPFIncludes(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr string
	}{
		{"empty entry", "", "empty"},
		{"whitespace only entry", "   ", "empty"},
		{"entry with whitespace", "include:a.com include:b.com", "whitespace"},
		{"bare all", "all", "all qualifier"},
		{"plus all", "+all", "all qualifier"},
		{"neutral all", "?all", "all qualifier"},
		{"softfail all", "~all", "all qualifier"},
		{"hardfail all", "-all", "all qualifier"},
		{"redirect", "redirect=attacker.example", "redirect"},
		{"normal include passes", "include:servers.mailgun.org", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Version: SchemaVersion,
				Domains: []Domain{{
					Name:           "example.com",
					ZoneName:       "example.com",
					Mail:           Mail{Providers: []string{"purelymail"}},
					Mailboxes:      []Mailbox{{Address: "a@example.com"}},
					Deliverability: Deliverability{SPFIncludes: []string{tt.entry}},
				}},
			}
			err := cfg.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("err = %v, want mention of %q", err, tt.wantErr)
			case tt.wantErr != "" && !strings.Contains(err.Error(), "example.com"):
				t.Fatalf("err = %v, want it to name the domain", err)
			}
		})
	}
}

func TestValidateMTAStsMaxAgeUpperBound(t *testing.T) {
	mtaSts := MTASts{Mode: "enforce", MaxAge: 31557601}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "maxAge") || !strings.Contains(err.Error(), "31557601") {
		t.Fatalf("err = %v, want error about maxAge exceeding RFC 8461's cap", err)
	}
}

// TestValidateMTAStsAllowsDeployWithModeNone guards against reintroducing the
// withdrawal bug: mode: none with deploy: true is the correct and necessary
// way to withdraw MTA-STS, because RFC 8461 requires the policy file itself
// to say mode: none. Rejecting this combination forces deploy: false, which
// rotates the _mta-sts id while the Worker keeps serving the old enforce
// policy and re-pins receivers instead of releasing them.
func TestValidateMTAStsAllowsDeployWithModeNone(t *testing.T) {
	mtaSts := MTASts{Mode: "none", Deploy: true}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v, want deploy: true with mode: none to be accepted", err)
	}
}

func TestValidateMTAStsRejectsNegativeMaxAgeWithModeNone(t *testing.T) {
	mtaSts := MTASts{Mode: "none", MaxAge: -5, Deploy: true}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "maxAge") || !strings.Contains(err.Error(), "-5") {
		t.Fatalf("err = %v, want error about negative maxAge even under mode: none", err)
	}
}

func TestValidateMTAStsMaxAgeUpperBoundWithModeNone(t *testing.T) {
	mtaSts := MTASts{Mode: "none", MaxAge: 31557601, Deploy: true}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{MTASts: &mtaSts},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "maxAge") || !strings.Contains(err.Error(), "31557601") {
		t.Fatalf("err = %v, want error about maxAge exceeding RFC 8461's cap even under mode: none", err)
	}
}

func TestValidateTLSRptRejectsAddressWithoutMailtoOrHttpsPrefix(t *testing.T) {
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{TLSRpt: "reports@example.com"},
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "tlsRpt") || !strings.Contains(err.Error(), "mailto:") {
		t.Fatalf("err = %v, want error about tlsRpt needing a mailto: or https: prefix", err)
	}
}

func TestValidateDMARCRUAAcceptsCommaSeparatedAddresses(t *testing.T) {
	dmarc := DMARC{Policy: "reject", Pct: 100, RUA: "mailto:dmarc1@x.com,mailto:dmarc2@x.com"}
	cfg := Config{
		Version: SchemaVersion,
		Domains: []Domain{{
			Name:           "example.com",
			ZoneName:       "example.com",
			Mail:           Mail{Providers: []string{"purelymail"}},
			Mailboxes:      []Mailbox{{Address: "a@example.com"}},
			Deliverability: Deliverability{DMARC: &dmarc},
		}},
	}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error for valid comma-separated rua: %v", err)
	}
}

func TestMS365Validation(t *testing.T) {
	base := func(mutate func(*Domain)) Domain {
		d := Domain{
			Name:     "example.com",
			ZoneName: "example.com",
			Mail: Mail{
				Providers: []string{"ms365"},
				MS365:     &MS365{License: "BUSINESS_BASIC", UsageLocation: "DE"},
			},
		}
		if mutate != nil {
			mutate(&d)
		}
		return d
	}

	cases := []struct {
		name string
		d    Domain
		want string
	}{
		{
			name: "aliases rejected",
			d:    base(func(d *Domain) { d.Aliases = []Alias{{Match: "info", To: []string{"a@example.com"}}} }),
			want: "admin center",
		},
		{
			name: "catchAll rejected",
			d:    base(func(d *Domain) { d.CatchAll = &CatchAll{To: []string{"a@example.com"}} }),
			want: "admin center",
		},
		{
			name: "missing ms365 block",
			d:    base(func(d *Domain) { d.Mail.MS365 = nil }),
			want: "requires an ms365 block",
		},
		{
			name: "ms365 block without the provider",
			d: Domain{Name: "example.com", ZoneName: "example.com", Mail: Mail{
				Providers: []string{"purelymail"},
				MS365:     &MS365{License: "X", UsageLocation: "DE"},
			}},
			want: "provider ms365",
		},
		{
			name: "license required",
			d:    base(func(d *Domain) { d.Mail.MS365.License = "" }),
			want: "license",
		},
		{
			name: "usageLocation required",
			d:    base(func(d *Domain) { d.Mail.MS365.UsageLocation = "" }),
			want: "usageLocation",
		},
		{
			name: "usageLocation must be two letters",
			d:    base(func(d *Domain) { d.Mail.MS365.UsageLocation = "DEU" }),
			want: "two-letter",
		},
		{
			name: "dkimCnames must be exactly two",
			d:    base(func(d *Domain) { d.Mail.MS365.DKIMCnames = []string{"only-one.example"} }),
			want: "exactly two",
		},
		{
			name: "dkimCnames must be targets not labels",
			d: base(func(d *Domain) {
				d.Mail.MS365.DKIMCnames = []string{
					"selector1._domainkey.example.com",
					"selector2._domainkey.example.com",
				}
			}),
			want: "target",
		},
		{
			name: "purelymail-only mailbox field rejected",
			d: base(func(d *Domain) {
				yes := true
				d.Mailboxes = []Mailbox{{Address: "a@example.com", RequireTwoFactorAuthentication: &yes}}
			}),
			want: "requireTwoFactorAuthentication",
		},
		{
			name: "recovery rejected",
			d: base(func(d *Domain) {
				d.Mailboxes = []Mailbox{{
					Address:  "a@example.com",
					Recovery: []Recovery{{Type: "email", Target: "b@example.org"}},
				}}
			}),
			want: "recovery",
		},
		{
			name: "enablePasswordReset rejected",
			d: base(func(d *Domain) {
				yes := true
				d.Mailboxes = []Mailbox{{Address: "a@example.com", EnablePasswordReset: &yes}}
			}),
			want: "enablePasswordReset",
		},
		{
			name: "enableSearchIndexing rejected",
			d: base(func(d *Domain) {
				yes := true
				d.Mailboxes = []Mailbox{{Address: "a@example.com", EnableSearchIndexing: &yes}}
			}),
			want: "enableSearchIndexing",
		},
		{
			name: "sendWelcomeEmail rejected",
			d: base(func(d *Domain) {
				no := false
				d.Mailboxes = []Mailbox{{Address: "a@example.com", SendWelcomeEmail: &no}}
			}),
			want: "sendWelcomeEmail",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Config{Version: 1, Cloudflare: CloudflareConfig{AccountID: "acc"},
				Domains: []Domain{tc.d}}.Validate()
			if err == nil {
				t.Fatal("want a validation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestMS365ValidConfigPasses(t *testing.T) {
	d := Domain{
		Name:     "example.com",
		ZoneName: "example.com",
		Mail: Mail{
			Providers: []string{"ms365"},
			MS365: &MS365{
				License:       "BUSINESS_BASIC",
				UsageLocation: "de",
				DKIMCnames: []string{
					"selector1-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft",
					"selector2-example-com._domainkey.contoso.n-v1.dkim.mail.microsoft",
				},
			},
		},
		Mailboxes: []Mailbox{{Address: "a@example.com", DisplayName: "A", License: "BUSINESS_STANDARD"}},
	}
	if err := (Config{Version: 1, Cloudflare: CloudflareConfig{AccountID: "acc"},
		Domains: []Domain{d}}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestMS365OnlyMailboxFieldsRejectedForOtherProviders(t *testing.T) {
	cases := []struct {
		name string
		box  Mailbox
		want string
	}{
		{"displayName", Mailbox{Address: "a@example.com", DisplayName: "A"}, "displayName"},
		{"license", Mailbox{Address: "a@example.com", License: "X"}, "license"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Domain{Name: "example.com", ZoneName: "example.com",
				Mail: Mail{Providers: []string{"purelymail"}}, Mailboxes: []Mailbox{tc.box}}
			err := Config{Version: 1, Cloudflare: CloudflareConfig{AccountID: "acc"},
				Domains: []Domain{d}}.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one naming %s", err, tc.want)
			}
		})
	}
}

func TestMS365CannotPairWithAnotherInboundProvider(t *testing.T) {
	d := Domain{Name: "example.com", ZoneName: "example.com",
		Mail: Mail{Providers: []string{"ms365", "purelymail"},
			MS365: &MS365{License: "X", UsageLocation: "DE"}}}
	err := Config{Version: 1, Cloudflare: CloudflareConfig{AccountID: "acc"},
		Domains: []Domain{d}}.Validate()
	if err == nil || !strings.Contains(err.Error(), "inbound") {
		t.Fatalf("error = %v, want the existing inbound-provider rule to fire", err)
	}
}
