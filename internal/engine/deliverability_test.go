package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/mail"
	"github.com/zoolcoder/mailctl/internal/plan"
	"github.com/zoolcoder/mailctl/internal/secret"
	"github.com/zoolcoder/mailctl/internal/worker"
)

func mailProviderWithMX() *fakeMail {
	return &fakeMail{name: "fake", desired: []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.fake.com ~all", Kind: dns.KindSPF},
	}}
}

func deliverabilityConfig(v config.Deliverability) config.Config {
	return config.Config{
		Version: config.SchemaVersion,
		Domains: []config.Domain{{
			Name:           "a.com",
			ZoneName:       "a.com",
			Mail:           config.Mail{Providers: []string{"fake"}},
			Deliverability: v,
		}},
	}
}

func countDetail(p plan.Plan, needle string) int {
	n := 0
	for _, a := range p.Actions {
		if strings.Contains(a.Detail, needle) {
			n++
		}
	}
	return n
}

func TestPlanPublishesConfiguredDMARC(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		DMARC: &config.DMARC{Policy: "reject", Pct: 100, RUA: "mailto:d@a.com"},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=DMARC1; p=reject") != 1 {
		t.Errorf("plan should create the DMARC record exactly once:\n%+v", got.Actions)
	}
}

func TestPlanPublishesOneMergedSPFRecord(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{SPFIncludes: []string{"include:extra.com"}})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=spf1") != 1 {
		t.Fatalf("want exactly one SPF action; two SPF records on one name is a hard failure:\n%+v", got.Actions)
	}
	if countDetail(got, "include:extra.com") != 1 || countDetail(got, "include:_spf.fake.com") != 1 {
		t.Errorf("the merged record must carry both includes:\n%+v", got.Actions)
	}
}

// TestPlanDeploysTheWorkerWhenMTAStsAsksForIt exercises planWorker against a
// live httptest.Server rather than a dead address: planWorker performs live
// reads (ScriptMatches, DomainAttached) during Plan, and a dead address would
// make both reads fail before the test ever gets to assert on the plan. The
// server reports 404 for the script (not deployed) and an empty domains list
// (not attached), matching Task 5's fakes.
func TestPlanDeploysTheWorkerWhenMTAStsAsksForIt(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/workers/scripts/"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10007,"message":"workers.api.error.script_not_found"}]}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/workers/domains"):
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "enforce", MaxAge: 604800, Deploy: true},
	})
	deployer := worker.New(cfapi.New(server.URL, "tok"), "acc-1")
	e := New(cfg, &fakeDNS{}, deployer, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	scriptName, err := worker.ScriptName("a.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}

	if countDetail(got, "v=STSv1; id=") != 1 {
		t.Errorf("plan should create the _mta-sts TXT record:\n%+v", got.Actions)
	}
	if countDetail(got, scriptName) < 2 {
		t.Errorf("plan should both upload the script and bind the custom domain:\n%+v", got.Actions)
	}

	// Worker actions must precede the _mta-sts TXT action (F2): on a policy
	// update, publishing the new id before the Worker serves the new policy
	// pins a receiver to the stale policy under the new id until the policy
	// text changes again.
	lastWorkerIndex, mtaStsIndex := -1, -1
	for i, a := range got.Actions {
		if strings.Contains(a.Detail, scriptName) {
			lastWorkerIndex = i
		}
		if strings.Contains(a.Detail, "v=STSv1; id=") {
			mtaStsIndex = i
		}
	}
	if mtaStsIndex == -1 {
		t.Fatalf("no _mta-sts TXT action found:\n%+v", got.Actions)
	}
	if lastWorkerIndex == -1 || lastWorkerIndex > mtaStsIndex {
		t.Errorf("last worker action at %d, _mta-sts TXT action at %d; every worker action must come before it:\n%+v",
			lastWorkerIndex, mtaStsIndex, got.Actions)
	}
}

// mtaStsID extracts the id from a plan's _mta-sts TXT create action, or
// reports false if there is none.
func mtaStsID(p plan.Plan) (string, bool) {
	for _, a := range p.Actions {
		if idx := strings.Index(a.Detail, "v=STSv1; id="); idx != -1 {
			return a.Detail[idx+len("v=STSv1; id="):], true
		}
	}
	return "", false
}

// withdrawalTestConfig builds a single-domain config for the withdrawal test
// below, registered under the known provider name "cfrouting" so that
// cfg.Validate() exercises the real mail-provider check rather than
// rejecting the fixture outright the way the "fake" name used by
// deliverabilityConfig would.
func withdrawalTestConfig(mode string, maxAge int) config.Config {
	return config.Config{
		Version: config.SchemaVersion,
		Domains: []config.Domain{{
			Name:     "a.com",
			ZoneName: "a.com",
			Mail:     config.Mail{Providers: []string{"cfrouting"}},
			Deliverability: config.Deliverability{
				MTASts: &config.MTASts{Mode: mode, MaxAge: maxAge, Deploy: true},
			},
		}},
	}
}

// TestPlanWithdrawingMTAStsStillDeploysTheWorker guards the fix for the
// withdrawal bug: mtaSts.mode: none with deploy: true must still plan the
// Worker upload/bind, because RFC 8461 requires the policy file itself to say
// mode: none. Skipping the Worker (as the old validation rule forced) would
// publish a freshly rotated _mta-sts id while the Worker keeps serving the
// old enforce policy, which repins receivers instead of releasing them.
func TestPlanWithdrawingMTAStsStillDeploysTheWorker(t *testing.T) {
	registerFake(t, "cfrouting", &fakeMail{name: "cfrouting", desired: []dns.Record{
		{Type: "MX", Name: "a.com", Content: "mx.fake.com", Priority: 10, Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "v=spf1 include:_spf.fake.com ~all", Kind: dns.KindSPF},
	}})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/workers/scripts/"):
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"success":false,"errors":[{"code":10007,"message":"workers.api.error.script_not_found"}]}`)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/workers/domains"):
			fmt.Fprint(w, `{"success":true,"errors":[],"result":[],"result_info":{"page":1,"total_pages":1}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := withdrawalTestConfig("none", 604800)
	// This config must be valid: mailctl's real flow validates before it ever
	// builds an engine, so a withdrawal config that Validate rejects never
	// reaches Plan at all.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	deployer := worker.New(cfapi.New(server.URL, "tok"), "acc-1")
	e := New(cfg, &fakeDNS{}, deployer, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}

	scriptName, err := worker.ScriptName("a.com")
	if err != nil {
		t.Fatalf("ScriptName: %v", err)
	}

	if countDetail(got, scriptName) < 2 {
		t.Errorf("withdrawal must still upload the script and bind the custom domain:\n%+v", got.Actions)
	}

	noneID, ok := mtaStsID(got)
	if !ok {
		t.Fatalf("plan should create the _mta-sts TXT record:\n%+v", got.Actions)
	}

	enforceCfg := withdrawalTestConfig("enforce", 604800)
	if err := enforceCfg.Validate(); err != nil {
		t.Fatalf("Validate (enforce): %v", err)
	}
	enforceE := New(enforceCfg, &fakeDNS{}, deployer, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})
	enforceGot, err := enforceE.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan (enforce): %v", err)
	}
	enforceID, ok := mtaStsID(enforceGot)
	if !ok {
		t.Fatalf("enforce plan should create the _mta-sts TXT record:\n%+v", enforceGot.Actions)
	}

	if noneID == enforceID {
		t.Errorf("withdrawal id %s must differ from the enforce id; the rotation is what forces the refetch", noneID)
	}
}

func TestPlanSkipsTheWorkerWhenDeployIsFalse(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "testing", MaxAge: 86400, Deploy: false},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	got, err := e.Plan(context.Background())
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if countDetail(got, "v=STSv1; id=") != 1 {
		t.Errorf("the TXT record is still published when the policy is hosted elsewhere:\n%+v", got.Actions)
	}
	if countDetail(got, "Worker") != 0 {
		t.Errorf("deploy: false must not plan any Worker action:\n%+v", got.Actions)
	}
}

func TestPlanFailsWhenMTAStsDeployHasNoAccountID(t *testing.T) {
	registerFake(t, "fake", mailProviderWithMX())

	cfg := deliverabilityConfig(config.Deliverability{
		MTASts: &config.MTASts{Mode: "enforce", Deploy: true},
	})
	e := New(cfg, &fakeDNS{}, nil, mail.Deps{}, Options{Secrets: secret.NewResolver(nil)})

	_, err := e.Plan(context.Background())
	if err == nil || !strings.Contains(err.Error(), "accountId") {
		t.Fatalf("err = %v, want an error naming the missing accountId", err)
	}
}
