package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
)

type fakeDNS struct {
	records []dns.Existing
	created []dns.Record
}

func (f *fakeDNS) Zone(_ context.Context, name string) (dns.Zone, error) {
	return dns.Zone{ID: "zone-" + name, Name: name}, nil
}
func (f *fakeDNS) Records(context.Context, string) ([]dns.Existing, error) { return f.records, nil }
func (f *fakeDNS) Create(_ context.Context, _ string, r dns.Record) error {
	f.created = append(f.created, r)
	return nil
}
func (f *fakeDNS) Delete(context.Context, string, string) error { return nil }

type fakeMail struct {
	name    string
	desired []dns.Record
	actions []plan.Action
	notes   []string
	// gotOpts records the mail.Options Plan was called with, so tests can
	// assert a value set on engine.Options actually reached the provider
	// layer, not just that Plan ran.
	gotOpts mail.Options
}

func (f *fakeMail) Name() string { return f.name }
func (f *fakeMail) DesiredDNS(context.Context, config.Domain) ([]dns.Record, error) {
	return f.desired, nil
}
func (f *fakeMail) Actual(context.Context, config.Domain) (mail.State, error) {
	notes := f.notes
	if notes == nil {
		notes = []string{f.name + " note"}
	}
	return mail.State{Notes: notes}, nil
}
func (f *fakeMail) Plan(_ config.Domain, _ mail.State, opts mail.Options) ([]plan.Action, error) {
	f.gotOpts = opts
	return f.actions, nil
}

func registerFake(t *testing.T, name string, provider *fakeMail) {
	t.Helper()
	mail.Register(name, func(mail.Deps) (mail.Provider, error) { return provider, nil })
	t.Cleanup(func() { mail.Unregister(name) })
}

func cfg(providers ...string) config.Config {
	return config.Config{
		Version: config.SchemaVersion,
		Domains: []config.Domain{{
			Name:     "a.com",
			ZoneName: "a.com",
			Mail:     config.Mail{Providers: providers},
		}},
	}
}

func TestPlanOrdersDNSBeforeMail(t *testing.T) {
	registerFake(t, "fake", &fakeMail{
		name:    "fake",
		desired: []dns.Record{{Type: "MX", Name: "a.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake",
			Detail: "add domain", Do: func(context.Context) error { return nil }}},
		notes: []string{},
	})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(got.Actions) != 2 {
		t.Fatalf("actions = %+v, want two", got.Actions)
	}
	if got.Actions[0].Resource != "dns" {
		t.Errorf("first action is %s; DNS must be applied before mail so the ownership proof resolves",
			got.Actions[0].Resource)
	}
	if got.Actions[1].Resource != "domain" {
		t.Errorf("second action = %s, want domain", got.Actions[1].Resource)
	}
}

// TestPlanPassesPruneOptionsToProvider guards the two-layer wiring of Prune
// and PruneMailboxes: engine.Options carries the CLI's intent, but a provider
// only ever sees mail.Options, built fresh in planDomain. Setting the
// engine.Options field alone would compile and silently do nothing, since
// nothing forces planDomain to copy it across — the same shape of bug as a
// CLI flag that never reaches engine.New.
func TestPlanPassesPruneOptionsToProvider(t *testing.T) {
	provider := &fakeMail{name: "fake", notes: []string{}}
	registerFake(t, "fake", provider)

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{
		Prune:          true,
		PruneMailboxes: true,
		Secrets:        secret.NewResolver(nil),
	})
	if _, err := e.Plan(context.Background()); err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if !provider.gotOpts.Prune {
		t.Error("mail.Options.Prune = false, want true: engine.Options.Prune did not reach the provider")
	}
	if !provider.gotOpts.PruneMailboxes {
		t.Error("mail.Options.PruneMailboxes = false, want true: engine.Options.PruneMailboxes did not reach the provider")
	}
}

func TestPlanUnionsDNSFromSeveralProviders(t *testing.T) {
	registerFake(t, "inbound", &fakeMail{name: "inbound",
		desired: []dns.Record{{Type: "MX", Name: "a.com", Content: "mx.in.com", Priority: 10, Kind: dns.KindMX}},
		notes:   []string{}})
	registerFake(t, "outbound", &fakeMail{name: "outbound",
		desired: []dns.Record{{Type: "TXT", Name: "x._domainkey.a.com", Content: "k=rsa", Kind: dns.KindDKIM}},
		notes:   []string{}})

	e := New(cfg("inbound", "outbound"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(got.Actions) != 2 {
		t.Fatalf("actions = %+v, want one per provider record", got.Actions)
	}
}

func TestPlanRejectsProvidersDemandingDifferentContentForOneRecord(t *testing.T) {
	// DMARC is a singleton kind (C1): it is one-per-name by specification, so
	// two providers wanting different policy text for _dmarc cannot both be
	// satisfied, unlike MX or SPF, which are legitimately multi-valued or
	// already reconciled elsewhere.
	registerFake(t, "one", &fakeMail{name: "one",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject", Kind: dns.KindDMARC}}})
	registerFake(t, "two", &fakeMail{name: "two",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=none", Kind: dns.KindDMARC}}})

	e := New(cfg("one", "two"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil {
		t.Fatal("expected an error when two providers demand different content for one record")
	}
	if !strings.Contains(err.Error(), "one") || !strings.Contains(err.Error(), "two") {
		t.Errorf("error should name both providers; got %q", err)
	}
}

func TestPlanMergesSPFAcrossProvidersInsteadOfRejecting(t *testing.T) {
	// SPF is exempt from the cross-provider collision guard (F1): a raw
	// apex SPF TXT from each provider necessarily differs by content, but
	// that is not a real conflict — deliver.Merge's MergeSPF folds every
	// provider's SPF contribution into one record. The classic pairing this
	// unblocks is [purelymail, cfsending]: inbound from one provider,
	// outbound from another.
	registerFake(t, "inbound", &fakeMail{name: "inbound",
		desired: []dns.Record{{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.inbound.com ~all", Kind: dns.KindSPF}}})
	registerFake(t, "outbound", &fakeMail{name: "outbound",
		desired: []dns.Record{{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.outbound.com ~all", Kind: dns.KindSPF}}})

	e := New(cfg("inbound", "outbound"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v, want the two providers' SPF records merged instead of rejected", err)
	}

	var spfActions []plan.Action
	for _, a := range got.Actions {
		if strings.Contains(a.Detail, "v=spf1") {
			spfActions = append(spfActions, a)
		}
	}
	if len(spfActions) != 1 {
		t.Fatalf("spf actions = %d, want exactly one merged SPF create:\n%+v", len(spfActions), got.Actions)
	}
	if !strings.Contains(spfActions[0].Detail, "include:_spf.inbound.com") ||
		!strings.Contains(spfActions[0].Detail, "include:_spf.outbound.com") {
		t.Errorf("merged SPF record must carry both providers' includes; got %q", spfActions[0].Detail)
	}
}

func TestPlanFiltersToSelectedDomains(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake"})

	c := cfg("fake")
	c.Domains = append(c.Domains, config.Domain{
		Name: "b.com", ZoneName: "b.com", Mail: config.Mail{Providers: []string{"fake"}}})

	e := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{Domains: []string{"b.com"}, Secrets: secret.NewResolver(nil)})
	if _, err := e.Plan(context.Background()); err != nil {
		t.Fatalf("Plan: %v", err)
	}
}

func TestPlanRejectsUnknownSelectedDomain(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake"})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Domains: []string{"nope.com"}, Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nope.com") {
		t.Fatalf("err = %v, want an error naming the unknown domain", err)
	}
}

func TestApplyRunsActionsInOrder(t *testing.T) {
	var order []string
	registerFake(t, "fake", &fakeMail{name: "fake", actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake", Detail: "one",
			Do: func(context.Context) error { order = append(order, "one"); return nil }},
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "fake", Detail: "two",
			Do: func(context.Context) error { order = append(order, "two"); return nil }},
	},
		notes: []string{}})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	p, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	var out strings.Builder
	if err := e.Apply(context.Background(), p, &out); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(order) != 2 || order[0] != "one" || order[1] != "two" {
		t.Errorf("order = %v, want [one two]", order)
	}
}

func TestApplyReportsProgressBeforeFailing(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake", actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "domain", Domain: "a.com", Provider: "fake", Detail: "ok",
			Do: func(context.Context) error { return nil }},
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "fake", Detail: "boom",
			Do: func(context.Context) error { return errors.New("api said no") }},
		{Op: plan.OpCreate, Resource: "alias", Domain: "a.com", Provider: "fake", Detail: "never",
			Do: func(context.Context) error { t.Fatal("must not run after a failure"); return nil }},
	},
		notes: []string{}})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	p, _ := e.Plan(context.Background())

	var out strings.Builder
	err := e.Apply(context.Background(), p, &out)
	if err == nil {
		t.Fatal("expected the failure to surface")
	}
	if !strings.Contains(err.Error(), "api said no") {
		t.Errorf("error should carry the provider message; got %q", err)
	}
	if !strings.Contains(err.Error(), "1 of 3") {
		t.Errorf("error should say how much succeeded; got %q", err)
	}
	if !strings.Contains(err.Error(), "rerun") {
		t.Errorf("error should tell the user to rerun; got %q", err)
	}
}

func TestApplyFailureNamesProviderAndDetail(t *testing.T) {
	registerFake(t, "fake", &fakeMail{name: "fake", actions: []plan.Action{
		{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "fake", Detail: "create box@a.com",
			Do: func(context.Context) error { return errors.New("api said no") }},
	},
		notes: []string{}})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	p, _ := e.Plan(context.Background())

	var out strings.Builder
	err := e.Apply(context.Background(), p, &out)
	if err == nil {
		t.Fatal("expected the failure to surface")
	}
	if !strings.Contains(err.Error(), "fake") {
		t.Errorf("error should name the provider; got %q", err)
	}
	if !strings.Contains(err.Error(), "create box@a.com") {
		t.Errorf("error should name the specific object via Detail; got %q", err)
	}
}

func TestPlanIncludesProviderNotesAsManualActions(t *testing.T) {
	registerFake(t, "fake", &fakeMail{
		name:  "fake",
		notes: []string{"note one", "note two"},
	})

	e := New(cfg("fake"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Should have exactly two note actions (one for each note).
	if len(got.Actions) != 2 {
		t.Fatalf("actions = %d, want 2", len(got.Actions))
	}
	for i, note := range []string{"note one", "note two"} {
		if got.Actions[i].Op != plan.OpManual {
			t.Errorf("action[%d].Op = %s, want OpManual", i, got.Actions[i].Op)
		}
		if got.Actions[i].Resource != "note" {
			t.Errorf("action[%d].Resource = %s, want note", i, got.Actions[i].Resource)
		}
		if got.Actions[i].Domain != "a.com" {
			t.Errorf("action[%d].Domain = %s, want a.com", i, got.Actions[i].Domain)
		}
		if got.Actions[i].Provider != "fake" {
			t.Errorf("action[%d].Provider = %s, want fake", i, got.Actions[i].Provider)
		}
		if got.Actions[i].Detail != note {
			t.Errorf("action[%d].Detail = %q, want %q", i, got.Actions[i].Detail, note)
		}
	}

	// Notes must not appear in Executable() actions.
	executable := got.Executable()
	if len(executable) != 0 {
		t.Errorf("Executable() = %d actions, want 0 (notes should be filtered out)", len(executable))
	}
}

func TestPlanDeduplicatesRepeatedDomainNames(t *testing.T) {
	registerFake(t, "fake", &fakeMail{
		name:    "fake",
		desired: []dns.Record{{Type: "MX", Name: "b.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "mailbox", Domain: "b.com", Provider: "fake",
			Detail: "add mailbox", Do: func(context.Context) error { return nil }}},
		notes: []string{},
	})

	c := cfg("fake")
	c.Domains = append(c.Domains, config.Domain{
		Name: "b.com", ZoneName: "b.com", Mail: config.Mail{Providers: []string{"fake"}}})

	// Plan with b.com twice; should be equivalent to planning b.com once.
	e := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{
		Domains: []string{"b.com", "b.com"},
		Secrets: secret.NewResolver(nil),
	})
	plan1, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Plan with b.com once.
	e2 := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{
		Domains: []string{"b.com"},
		Secrets: secret.NewResolver(nil),
	})
	plan2, err := e2.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(plan1.Actions) != len(plan2.Actions) {
		t.Errorf("repeated domain produces %d actions, single domain produces %d; should be equal",
			len(plan1.Actions), len(plan2.Actions))
	}

	// Verify no action Detail appears twice (would indicate duplicate execution).
	seen := make(map[string]int)
	for _, action := range plan1.Actions {
		seen[action.Detail]++
	}
	for detail, count := range seen {
		if count > 1 {
			t.Errorf("action detail %q appears %d times; dedupe must prevent this", detail, count)
		}
	}
}

func TestPlanDeduplicatesDomainNamesCaseInsensitive(t *testing.T) {
	registerFake(t, "fake", &fakeMail{
		name:    "fake",
		desired: []dns.Record{{Type: "MX", Name: "b.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "mailbox", Domain: "b.com", Provider: "fake",
			Detail: "add mailbox", Do: func(context.Context) error { return nil }}},
		notes: []string{},
	})

	c := cfg("fake")
	c.Domains = append(c.Domains, config.Domain{
		Name: "b.com", ZoneName: "b.com", Mail: config.Mail{Providers: []string{"fake"}}})

	// Plan with B.com and b.com; should deduplicate case-insensitively.
	e := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{
		Domains: []string{"B.com", "b.com"},
		Secrets: secret.NewResolver(nil),
	})
	plan1, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Plan with b.com once.
	e2 := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{
		Domains: []string{"b.com"},
		Secrets: secret.NewResolver(nil),
	})
	plan2, err := e2.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	if len(plan1.Actions) != len(plan2.Actions) {
		t.Errorf("case-insensitive duplicates produce %d actions, single domain produces %d; should be equal",
			len(plan1.Actions), len(plan2.Actions))
	}

	// Verify no action Detail appears twice (would indicate duplicate execution).
	seen := make(map[string]int)
	for _, action := range plan1.Actions {
		seen[action.Detail]++
	}
	for detail, count := range seen {
		if count > 1 {
			t.Errorf("action detail %q appears %d times; case-insensitive dedupe must prevent this", detail, count)
		}
	}
}

func TestPlanOrdersDNSBeforeMailWithMultipleProviders(t *testing.T) {
	// Both providers return DNS records and mail actions.
	registerFake(t, "inbound", &fakeMail{
		name:    "inbound",
		desired: []dns.Record{{Type: "MX", Name: "a.com", Content: "mx.in.com", Priority: 10, Kind: dns.KindMX}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "inbound",
			Detail: "add inbound mailbox", Do: func(context.Context) error { return nil }}},
		notes: []string{},
	})
	registerFake(t, "outbound", &fakeMail{
		name:    "outbound",
		desired: []dns.Record{{Type: "TXT", Name: "x._domainkey.a.com", Content: "k=rsa", Kind: dns.KindDKIM}},
		actions: []plan.Action{{Op: plan.OpCreate, Resource: "mailbox", Domain: "a.com", Provider: "outbound",
			Detail: "add outbound mailbox", Do: func(context.Context) error { return nil }}},
		notes: []string{},
	})

	e := New(cfg("inbound", "outbound"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	// Should have: MX DNS, DKIM DNS, inbound mailbox, outbound mailbox.
	if len(got.Actions) != 4 {
		t.Fatalf("actions = %d, want 4", len(got.Actions))
	}

	// All DNS actions must come before all mail actions.
	lastDNSIndex := -1
	firstMailIndex := -1
	for i, action := range got.Actions {
		if action.Resource == "dns" {
			lastDNSIndex = i
		} else if action.Resource == "mailbox" && firstMailIndex == -1 {
			firstMailIndex = i
		}
	}
	if firstMailIndex != -1 && lastDNSIndex > firstMailIndex {
		t.Errorf("last DNS action at index %d comes after first mail action at index %d; DNS must come first",
			lastDNSIndex, firstMailIndex)
	}
}

func TestPlanRejectsThreeProvidersWithThirdDisagreeing(t *testing.T) {
	// DMARC is a singleton kind (see the note on the guard's DMARC/MTA-STS/
	// TLS-RPT/BIMI scope above).
	registerFake(t, "one", &fakeMail{name: "one",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject", Kind: dns.KindDMARC}}})
	registerFake(t, "two", &fakeMail{name: "two",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject", Kind: dns.KindDMARC}}})
	registerFake(t, "three", &fakeMail{name: "three",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=none", Kind: dns.KindDMARC}}})

	e := New(cfg("one", "two", "three"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil {
		t.Fatal("expected an error when three providers have conflicting content")
	}
	// The error must name the two providers that actually disagree: one (or two) and three.
	// Provider two agrees with one, so it should not appear in the error.
	if !strings.Contains(err.Error(), "one") || !strings.Contains(err.Error(), "three") {
		t.Errorf("error should name providers one and three; got %q", err)
	}
	if strings.Contains(err.Error(), "two") {
		t.Errorf("error should not name provider two (it agrees with one); got %q", err)
	}
}

func TestPlanAllowsSameNameSPFAndOwnershipTXT(t *testing.T) {
	// Purelymail's DesiredDNS returns two apex TXT records on the same name:
	// SPF and the ownership proof. They necessarily carry different content,
	// so the union guard must key on Kind, not just Type+Name, or this looks
	// like self-contradiction and every plan fails (F1).
	registerFake(t, "purelymail-like", &fakeMail{name: "purelymail-like",
		desired: []dns.Record{
			{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.purelymail.com ~all", Kind: dns.KindSPF},
			{Type: "TXT", Name: "a.com", Content: "purelymail_ownership_proof=abc", Kind: dns.KindOwnership},
		},
		notes: []string{},
	})

	e := New(cfg("purelymail-like"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v, want no error for two same-name TXT records of different Kind", err)
	}

	var txtCount int
	for _, a := range got.Actions {
		if a.Resource == "dns" {
			txtCount++
		}
	}
	if txtCount != 2 {
		t.Fatalf("dns actions = %d, want 2 (both the SPF and ownership records desired)", txtCount)
	}
}

func TestPlanAllowsThreeApexMXFromOneProvider(t *testing.T) {
	// Cloudflare Email Routing returns three apex MX records for one
	// provider. MX is not a singleton kind (C1), so all three must pass
	// through uncontested instead of the second one tripping the
	// self-contradiction branch.
	registerFake(t, "cfrouting-like", &fakeMail{name: "cfrouting-like",
		desired: []dns.Record{
			{Type: "MX", Name: "a.com", Content: "route1.mx.cloudflare.net", Priority: 21, Kind: dns.KindMX},
			{Type: "MX", Name: "a.com", Content: "route2.mx.cloudflare.net", Priority: 51, Kind: dns.KindMX},
			{Type: "MX", Name: "a.com", Content: "route3.mx.cloudflare.net", Priority: 99, Kind: dns.KindMX},
		},
		notes: []string{},
	})

	e := New(cfg("cfrouting-like"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v, want three apex MX records from one provider to plan cleanly", err)
	}

	var mxActions int
	for _, a := range got.Actions {
		if a.Resource == "dns" && strings.Contains(a.Detail, "MX") {
			mxActions++
		}
	}
	if mxActions != 3 {
		t.Fatalf("mx actions = %d, want 3:\n%+v", mxActions, got.Actions)
	}
}

func TestAuditAgreesWithPlanOnAnIllegalConfig(t *testing.T) {
	// engine.Desired, which audit uses, used to skip the collision guard
	// planDomain applies, so a config plan rejected as self-contradictory
	// looked legal to audit (I3). Both now go through unionDesiredDNS, so
	// they cannot diverge.
	registerFake(t, "one", &fakeMail{name: "one",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject", Kind: dns.KindDMARC}}})
	registerFake(t, "two", &fakeMail{name: "two",
		desired: []dns.Record{{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=none", Kind: dns.KindDMARC}}})

	c := cfg("one", "two")
	e := New(c, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	_, planErr := e.Plan(context.Background())
	if planErr == nil {
		t.Fatal("Plan: expected an error for conflicting DMARC content")
	}

	_, auditErr := e.Desired(context.Background(), c.Domains[0])
	if auditErr == nil {
		t.Fatal("Desired: expected the same config plan rejects to also be rejected for audit")
	}
}

func TestPlanRejectsSelfConflict(t *testing.T) {
	// DMARC is a singleton kind (see the note on the guard's scope above).
	registerFake(t, "bad", &fakeMail{name: "bad",
		desired: []dns.Record{
			{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=reject", Kind: dns.KindDMARC},
			{Type: "TXT", Name: "_dmarc.a.com", Content: "v=DMARC1; p=none", Kind: dns.KindDMARC},
		}})

	e := New(cfg("bad"), &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	_, err := e.Plan(context.Background())
	if err == nil {
		t.Fatal("expected an error when a provider contradicts itself")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error should name provider bad; got %q", err)
	}
	if !strings.Contains(err.Error(), "contradicts") {
		t.Errorf("error should mention self-contradiction; got %q", err)
	}
}
