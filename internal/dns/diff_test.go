package dns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/plan"
)

// fakeProvider records the calls Diff's action closures make.
type fakeProvider struct {
	created   []Record
	deleted   []string
	deleteErr error
	createErr error
}

func (f *fakeProvider) Zone(context.Context, string) (Zone, error) { return Zone{}, nil }
func (f *fakeProvider) Records(context.Context, string) ([]Existing, error) {
	return nil, nil
}
func (f *fakeProvider) Create(_ context.Context, _ string, r Record) error {
	f.created = append(f.created, r)
	if f.createErr != nil {
		return f.createErr
	}
	return nil
}
func (f *fakeProvider) Delete(_ context.Context, _, id string) error {
	f.deleted = append(f.deleted, id)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return nil
}

func mx(content string, priority int) Record {
	return Record{Type: "MX", Name: "a.com", Content: content, Priority: priority, TTL: 1, Kind: KindMX}
}

func TestDiffCreatesMissingRecord(t *testing.T) {
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", nil, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want one create", actions)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(provider.created) != 1 || provider.created[0].Content != "mailserver.purelymail.com" {
		t.Errorf("created = %+v, want the desired record", provider.created)
	}
}

func TestDiffIsSilentWhenConverged(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: mx("mailserver.purelymail.com", 50)}}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none", actions)
	}
}

func TestDiffIgnoresTrailingDotAndCase(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: Record{
		Type: "CNAME", Name: "PurelyMail1._domainkey.A.com", Content: "key1.dkimroot.purelymail.com.", TTL: 1,
	}}}
	desired := []Record{{
		Type: "CNAME", Name: "purelymail1._domainkey.a.com", Content: "key1.dkimroot.purelymail.com", TTL: 1, Kind: KindDKIM,
	}}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; comparison must ignore case and a trailing dot", actions)
	}
}

func TestDiffRefusesConflictWithoutReplaceFlag(t *testing.T) {
	// Unsatisfied case: desired record is not published
	actual := []Existing{{ID: "r1", Record: mx("mail.oldhost.com", 10)}}

	_, err := Diff(&fakeProvider{}, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err == nil {
		t.Fatal("expected a conflict error")
	}
	errMsg := err.Error()
	// Pin unique phrases: unsatisfied case says "does not match"
	if !strings.Contains(errMsg, "does not match") {
		t.Errorf("unsatisfied conflict error should say 'does not match'; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "-replace-dns") || !strings.Contains(errMsg, "mail.oldhost.com") {
		t.Errorf("error should name the conflict and the flag; got %q", errMsg)
	}
}

func TestDiffReplacesConflictWhenAllowed(t *testing.T) {
	actual := []Existing{{ID: "r1", Record: mx("mail.oldhost.com", 10)}}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)},
		DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete then create", actions)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if len(provider.deleted) != 1 || provider.deleted[0] != "r1" {
		t.Errorf("deleted = %v, want [r1]", provider.deleted)
	}
	if len(provider.created) != 1 {
		t.Errorf("created = %+v, want the replacement", provider.created)
	}
}

func TestConflictRules(t *testing.T) {
	tests := []struct {
		name     string
		existing Record
		desired  Record
		conflict bool
	}{
		{"mx conflicts with any mx",
			Record{Type: "MX", Name: "a.com", Content: "other"},
			Record{Type: "MX", Name: "a.com", Kind: KindMX}, true},
		{"spf conflicts with another spf txt",
			Record{Type: "TXT", Name: "a.com", Content: "v=spf1 include:other ~all"},
			Record{Type: "TXT", Name: "a.com", Kind: KindSPF}, true},
		{"spf does not conflict with an unrelated txt",
			Record{Type: "TXT", Name: "a.com", Content: "google-site-verification=xyz"},
			Record{Type: "TXT", Name: "a.com", Kind: KindSPF}, false},
		{"ownership conflicts with nothing",
			Record{Type: "TXT", Name: "a.com", Content: "anything"},
			Record{Type: "TXT", Name: "a.com", Kind: KindOwnership}, false},
		{"dkim conflicts with anything on its own name",
			Record{Type: "A", Name: "purelymail1._domainkey.a.com", Content: "1.2.3.4"},
			Record{Type: "CNAME", Name: "purelymail1._domainkey.a.com", Kind: KindDKIM}, true},
		{"dmarc conflicts with anything on its own name",
			Record{Type: "A", Name: "_dmarc.a.com", Content: "1.2.3.4"},
			Record{Type: "TXT", Name: "_dmarc.a.com", Kind: KindDMARC}, true},
		{"mta-sts txt conflicts with another sts policy id",
			Record{Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=old"},
			Record{Type: "TXT", Name: "_mta-sts.a.com", Kind: KindMTASts}, true},
		{"mta-sts does not conflict with an unrelated txt",
			Record{Type: "TXT", Name: "_mta-sts.a.com", Content: "google-site-verification=xyz"},
			Record{Type: "TXT", Name: "_mta-sts.a.com", Kind: KindMTASts}, false},
		{"tls-rpt conflicts with another tls-rpt",
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Content: "v=TLSRPTv1; rua=mailto:x@a.com"},
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Kind: KindTLSRpt}, true},
		{"tls-rpt does not conflict with an unrelated txt",
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Content: "google-site-verification=xyz"},
			Record{Type: "TXT", Name: "_smtp._tls.a.com", Kind: KindTLSRpt}, false},
		{"bimi conflicts with another bimi",
			Record{Type: "TXT", Name: "default._bimi.a.com", Content: "v=BIMI1; l=https://old"},
			Record{Type: "TXT", Name: "default._bimi.a.com", Kind: KindBIMI}, true},
		{"bimi does not conflict with an unrelated txt",
			Record{Type: "TXT", Name: "default._bimi.a.com", Content: "google-site-verification=xyz"},
			Record{Type: "TXT", Name: "default._bimi.a.com", Kind: KindBIMI}, false},
		{"unrelated name never conflicts",
			Record{Type: "MX", Name: "other.com", Content: "x"},
			Record{Type: "MX", Name: "a.com", Kind: KindMX}, false},
		{"spf conflicts with a quoted existing spf txt",
			Record{Type: "TXT", Name: "a.com", Content: `"v=spf1 include:other ~all"`},
			Record{Type: "TXT", Name: "a.com", Kind: KindSPF}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := conflicts(tt.existing, tt.desired); got != tt.conflict {
				t.Errorf("conflicts() = %v, want %v", got, tt.conflict)
			}
		})
	}
}

func TestDiffDeletesBlockingRecordWhenSatisfied(t *testing.T) {
	// Zone has the correct MX plus a stale MX from a previous provider
	actual := []Existing{
		{ID: "r1", Record: mx("mailserver.purelymail.com", 50)},
		{ID: "r2", Record: mx("mail.oldhost.com", 10)},
	}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)},
		DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpDelete {
		t.Fatalf("actions = %+v, want one delete", actions)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(provider.deleted) != 1 || provider.deleted[0] != "r2" {
		t.Errorf("deleted = %v, want [r2]", provider.deleted)
	}
	if len(provider.created) != 0 {
		t.Errorf("created = %+v, want none (record already exists)", provider.created)
	}
}

func TestDiffRefusesBlockingWhenSatisfiedWithoutReplace(t *testing.T) {
	// Satisfied case: desired record IS published, but blocking record exists
	actual := []Existing{
		{ID: "r1", Record: mx("mailserver.purelymail.com", 50)},
		{ID: "r2", Record: mx("mail.oldhost.com", 10)},
	}

	_, err := Diff(&fakeProvider{}, "z1", "a.com", actual, []Record{mx("mailserver.purelymail.com", 50)}, DiffOptions{})
	if err == nil {
		t.Fatal("expected a conflict error")
	}
	errMsg := err.Error()
	// Pin unique phrases: satisfied case says "conflicts with"
	if !strings.Contains(errMsg, "conflicts with") {
		t.Errorf("satisfied conflict error should say 'conflicts with'; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "-replace-dns") || !strings.Contains(errMsg, "mail.oldhost.com") {
		t.Errorf("error should name the conflict and the flag; got %q", errMsg)
	}
}

func TestDiffDeletesMultipleConflictingRecords(t *testing.T) {
	// Zone has the correct SPF TXT plus a second v=spf1 TXT plus an unrelated site-verification TXT
	actual := []Existing{
		{ID: "r1", Record: Record{Type: "TXT", Name: "a.com", Content: "v=spf1 include:mailprovider.com ~all", TTL: 1}},
		{ID: "r2", Record: Record{Type: "TXT", Name: "a.com", Content: "v=spf1 include:oldprovider.com ~all", TTL: 1}},
		{ID: "r3", Record: Record{Type: "TXT", Name: "a.com", Content: "google-site-verification=xyz", TTL: 1}},
	}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual,
		[]Record{{Type: "TXT", Name: "a.com", Content: "v=spf1 include:mailprovider.com ~all", TTL: 1, Kind: KindSPF}},
		DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpDelete {
		t.Fatalf("actions = %+v, want one delete", actions)
	}
	if err := actions[0].Do(context.Background()); err != nil {
		t.Fatalf("Do: %v", err)
	}
	if len(provider.deleted) != 1 || provider.deleted[0] != "r2" {
		t.Errorf("deleted = %v, want [r2]", provider.deleted)
	}
	if len(provider.created) != 0 {
		t.Errorf("created = %+v, want none", provider.created)
	}
}

func TestDiffReplacesMTAStsIDRotationWithoutFlag(t *testing.T) {
	// Rotating the MTA-STS policy id is the designed, routine lifecycle of
	// the feature (F1/F3): it must not require -replace-dns.
	actual := []Existing{{ID: "r1", Record: Record{
		Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=old123456789abc", Kind: KindMTASts,
	}}}
	desired := []Record{{
		Type: "TXT", Name: "_mta-sts.a.com", Content: "v=STSv1; id=new123456789abc", Kind: KindMTASts,
	}}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v, want no error for an owned-outright kind without -replace-dns", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete-then-create with no flag", actions)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if len(provider.deleted) != 1 || provider.deleted[0] != "r1" {
		t.Errorf("deleted = %v, want [r1]", provider.deleted)
	}
	if len(provider.created) != 1 {
		t.Errorf("created = %+v, want the new policy id", provider.created)
	}
}

func TestDiffSPFContentChangeStillRequiresFlag(t *testing.T) {
	// SPF is deliberately excluded from ownedOutright (F3): a pre-existing
	// apex TXT record may belong to another provider entirely.
	actual := []Existing{{ID: "r1", Record: Record{
		Type: "TXT", Name: "a.com", Content: "v=spf1 include:old.com ~all",
	}}}
	desired := []Record{{
		Type: "TXT", Name: "a.com", Content: "v=spf1 include:new.com ~all", Kind: KindSPF,
	}}

	_, err := Diff(&fakeProvider{}, "z1", "a.com", actual, desired, DiffOptions{})
	if err == nil || !strings.Contains(err.Error(), "-replace-dns") {
		t.Fatalf("err = %v, want an SPF content change to still require -replace-dns", err)
	}

	provider := &fakeProvider{}
	actions, err := Diff(provider, "z1", "a.com", actual, desired, DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v, want success with -replace-dns", err)
	}
	if len(actions) != 2 || actions[0].Op != plan.OpDelete || actions[1].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want delete-then-create with the flag", actions)
	}
}

func TestDiffTreatsQuotedExistingContentAsEqualToUnquoted(t *testing.T) {
	// A quoted existing record (F7) must still be recognised as already
	// satisfying the desired one, or mailctl would try to create a duplicate.
	actual := []Existing{{ID: "r1", Record: Record{
		Type: "TXT", Name: "a.com", Content: `"v=spf1 include:x.com ~all"`,
	}}}
	desired := []Record{{
		Type: "TXT", Name: "a.com", Content: "v=spf1 include:x.com ~all", Kind: KindSPF,
	}}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; a quoted existing record must be recognised as already satisfying the desired one", actions)
	}
}

func TestDiffTwoDesiredMXRecordsBothPresentIsConverged(t *testing.T) {
	// Cloudflare Email Routing publishes several MX records for one name, and
	// Purelymail always publishes at least one MX. Without Kind-aware
	// protection, each desired MX record blocks the other on the same name,
	// so a converged zone with two correct MX records is reported as
	// conflicting (F7).
	desired := []Record{mx("mx1.example.com", 10), mx("mx2.example.com", 20)}
	actual := []Existing{
		{ID: "r1", Record: mx("mx1.example.com", 10)},
		{ID: "r2", Record: mx("mx2.example.com", 20)},
	}

	actions, err := Diff(&fakeProvider{}, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v, want no error for two already-correct MX records", err)
	}
	if len(actions) != 0 {
		t.Errorf("actions = %+v, want none; both desired MX records already exist", actions)
	}
}

func TestDiffTwoDesiredMXRecordsOneMissingCreatesOnlyTheMissingOne(t *testing.T) {
	desired := []Record{mx("mx1.example.com", 10), mx("mx2.example.com", 20)}
	actual := []Existing{
		{ID: "r1", Record: mx("mx1.example.com", 10)},
	}
	provider := &fakeProvider{}

	actions, err := Diff(provider, "z1", "a.com", actual, desired, DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v, want no error; the existing MX record must not block its sibling", err)
	}
	if len(actions) != 1 || actions[0].Op != plan.OpCreate {
		t.Fatalf("actions = %+v, want exactly one create for the missing MX record", actions)
	}
	if !strings.Contains(actions[0].Detail, "mx2.example.com") {
		t.Errorf("create detail = %q, want it to name mx2.example.com", actions[0].Detail)
	}
	for _, a := range actions {
		if err := a.Do(context.Background()); err != nil {
			t.Fatalf("Do: %v", err)
		}
	}
	if len(provider.deleted) != 0 {
		t.Errorf("deleted = %v, want none; the existing correct MX record must survive", provider.deleted)
	}
}

func TestDiffDeleteErrorIncludesDomainAndRecord(t *testing.T) {
	// Test that delete action closures wrap errors with domain and record context
	sentinel := errors.New("api error")
	provider := &fakeProvider{deleteErr: sentinel}
	actual := []Existing{
		{ID: "r1", Record: mx("mail.oldhost.com", 10)},
	}

	actions, err := Diff(provider, "z1", "testdomain.com", actual, []Record{mx("mailserver.purelymail.com", 50)},
		DiffOptions{ReplaceConflicts: true})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Execute the delete action and capture its error
	delAction := actions[0]
	if delAction.Op != plan.OpDelete {
		t.Fatalf("expected delete action, got %v", delAction.Op)
	}
	doErr := delAction.Do(context.Background())
	if doErr == nil {
		t.Fatal("expected Delete error, got nil")
	}

	// Verify the error contains domain, record, and cloudflare
	errMsg := doErr.Error()
	if !strings.Contains(errMsg, "cloudflare") {
		t.Errorf("error should name provider; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "testdomain.com") {
		t.Errorf("error should name domain; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "mail.oldhost.com") {
		t.Errorf("error should describe blocking record; got %q", errMsg)
	}

	// Verify the error chain contains the sentinel (tests %w wrapping)
	if !errors.Is(doErr, sentinel) {
		t.Errorf("error chain should contain sentinel, got %v", doErr)
	}
}

func TestDiffCreateErrorIncludesDomainAndRecord(t *testing.T) {
	// Test that create action closures wrap errors with domain and record context
	sentinel := errors.New("api error")
	provider := &fakeProvider{createErr: sentinel}

	actions, err := Diff(provider, "z1", "testdomain.com", nil, []Record{mx("mailserver.purelymail.com", 50)},
		DiffOptions{})
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	// Execute the create action and capture its error
	createAction := actions[0]
	if createAction.Op != plan.OpCreate {
		t.Fatalf("expected create action, got %v", createAction.Op)
	}
	doErr := createAction.Do(context.Background())
	if doErr == nil {
		t.Fatal("expected Create error, got nil")
	}

	// Verify the error contains domain, record, and cloudflare
	errMsg := doErr.Error()
	if !strings.Contains(errMsg, "cloudflare") {
		t.Errorf("error should name provider; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "testdomain.com") {
		t.Errorf("error should name domain; got %q", errMsg)
	}
	if !strings.Contains(errMsg, "mailserver.purelymail.com") {
		t.Errorf("error should describe created record; got %q", errMsg)
	}

	// Verify the error chain contains the sentinel (tests %w wrapping)
	if !errors.Is(doErr, sentinel) {
		t.Errorf("error chain should contain sentinel, got %v", doErr)
	}
}
