package deliver

import (
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
)

func TestPolicyTextShape(t *testing.T) {
	got := MTAStsPolicy("enforce", 604800, []string{"mailserver.purelymail.com"})

	want := "version: STSv1\nmode: enforce\nmx: mailserver.purelymail.com\nmax_age: 604800\n"
	if got != want {
		t.Errorf("policy =\n%q\nwant\n%q", got, want)
	}
}

func TestPolicyTextListsEveryMXOnItsOwnLine(t *testing.T) {
	got := MTAStsPolicy("testing", 86400, []string{"mx1.a.com", "mx2.a.com"})

	if strings.Count(got, "mx: ") != 2 {
		t.Errorf("policy should carry one mx line per host:\n%s", got)
	}
}

func TestPolicyIDChangesWithThePolicy(t *testing.T) {
	first := MTAStsPolicy("enforce", 604800, []string{"mx1.a.com"})
	second := MTAStsPolicy("enforce", 604800, []string{"mx1.a.com", "mx2.a.com"})
	third := MTAStsPolicy("testing", 604800, []string{"mx1.a.com"})

	if MTAStsID(first) == MTAStsID(second) {
		t.Error("adding an MX must change the id, or receivers never refetch")
	}
	if MTAStsID(first) == MTAStsID(third) {
		t.Error("changing the mode must change the id")
	}
	if MTAStsID(first) != MTAStsID(MTAStsPolicy("enforce", 604800, []string{"mx1.a.com"})) {
		t.Error("the same policy must produce the same id, or every run republishes")
	}
	if len(MTAStsID(first)) != 16 {
		t.Errorf("id length = %d, want 16", len(MTAStsID(first)))
	}
}

func TestMTAStsBuildsTXTAndPolicy(t *testing.T) {
	records, policy, err := MTASts("a.com",
		config.MTASts{Mode: "enforce", MaxAge: 604800, Deploy: true},
		[]string{"mailserver.purelymail.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("records = %+v, want just the _mta-sts TXT; the policy host record is created by the Worker binding", records)
	}
	got := records[0]
	if got.Name != "_mta-sts.a.com" || got.Kind != dns.KindMTASts {
		t.Errorf("record = %+v, want a TXT on _mta-sts.a.com", got)
	}
	if !strings.HasPrefix(got.Content, "v=STSv1; id=") {
		t.Errorf("content = %q, want the STSv1 prefix", got.Content)
	}
	if !strings.Contains(got.Content, MTAStsID(policy)) {
		t.Errorf("content = %q must carry the id of the returned policy", got.Content)
	}
}

func TestMTAStsRefusesEnforceWithNoMX(t *testing.T) {
	_, _, err := MTASts("a.com", config.MTASts{Mode: "enforce", MaxAge: 604800}, nil)
	if err == nil || !strings.Contains(err.Error(), "MX") {
		t.Fatalf("err = %v, want a refusal naming MX; an enforce policy with no mx line rejects all mail", err)
	}
}

func TestMTAStsModeNoneBuildsAWithdrawalPolicy(t *testing.T) {
	records, policy, err := MTASts("a.com", config.MTASts{Mode: "none"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %+v, want the _mta-sts TXT so enforcement can actually be withdrawn", records)
	}
	if !strings.Contains(policy, "mode: none") {
		t.Errorf("policy = %q, want mode: none published like any other mode", policy)
	}
}

func TestMTAStsModeNoneIDDiffersFromEnforce(t *testing.T) {
	_, nonePolicy, err := MTASts("a.com", config.MTASts{Mode: "none"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	_, enforcePolicy, err := MTASts("a.com", config.MTASts{Mode: "enforce"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if MTAStsID(nonePolicy) == MTAStsID(enforcePolicy) {
		t.Error("withdrawing (mode: none) must rotate the id, or receivers never refetch the withdrawal")
	}
}

func TestMTAStsModeNoneSucceedsWithNoMX(t *testing.T) {
	records, policy, err := MTASts("a.com", config.MTASts{Mode: "none"}, nil)
	if err != nil {
		t.Fatalf("MTASts: %v, want mode: none to succeed with no MX; a withdrawal authorises no hosts by design", err)
	}
	if len(records) != 1 || policy == "" {
		t.Errorf("records = %+v, policy = %q, want a withdrawal policy published even with no MX", records, policy)
	}
}

func TestMTAStsEmptyModeProducesNothing(t *testing.T) {
	records, policy, err := MTASts("a.com", config.MTASts{}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("records = %+v, want none when mode is unset (not configured)", records)
	}
	if policy != "" {
		t.Errorf("policy = %q, want empty string when mode is unset", policy)
	}
}

func TestMTAStsDefaultsMaxAge(t *testing.T) {
	_, policy, err := MTASts("a.com", config.MTASts{Mode: "testing"}, []string{"mx.a.com"})
	if err != nil {
		t.Fatalf("MTASts: %v", err)
	}
	if !strings.Contains(policy, "max_age: 604800") {
		t.Errorf("policy = %q, want the one-week default", policy)
	}
}

func TestMXHostsSortsAndStripsTrailingDots(t *testing.T) {
	got := MXHosts([]dns.Record{
		{Type: "MX", Name: "a.com", Content: "mx2.a.com.", Kind: dns.KindMX},
		{Type: "MX", Name: "a.com", Content: "mx1.a.com", Kind: dns.KindMX},
		{Type: "TXT", Name: "a.com", Content: "ignored", Kind: dns.KindSPF},
	})

	if len(got) != 2 || got[0] != "mx1.a.com" || got[1] != "mx2.a.com" {
		t.Errorf("hosts = %v, want [mx1.a.com mx2.a.com]; sorting keeps the policy id stable", got)
	}
}

func TestMXHostsDeduplicatesAfterNormalisation(t *testing.T) {
	got := MXHosts([]dns.Record{
		{Type: "MX", Name: "a.com", Content: "MX1.a.com.", Kind: dns.KindMX},
		{Type: "MX", Name: "a.com", Content: "mx1.a.com", Kind: dns.KindMX},
	})

	if len(got) != 1 || got[0] != "mx1.a.com" {
		t.Errorf("hosts = %v, want [mx1.a.com] after deduplication; normalization+dedup prevents policy churn", got)
	}
}
