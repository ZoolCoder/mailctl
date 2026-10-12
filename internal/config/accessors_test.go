package config

import (
	"strings"
	"testing"
)

func TestAliasPrefixAndMatchUserSplitTheTrailingStar(t *testing.T) {
	// The trailing * is the only thing distinguishing "team*" (a prefix alias
	// catching team-anything) from a literal address, and the star must never
	// reach a provider as part of the local part.
	prefix := Alias{Match: "team*"}
	if !prefix.Prefix() {
		t.Error("Prefix() = false for a match ending in *")
	}
	if got := prefix.MatchUser(); got != "team" {
		t.Errorf("MatchUser() = %q, want team with the star stripped", got)
	}

	exact := Alias{Match: "sales"}
	if exact.Prefix() {
		t.Error("Prefix() = true for a match with no star")
	}
	if got := exact.MatchUser(); got != "sales" {
		t.Errorf("MatchUser() = %q, want sales unchanged", got)
	}
}

func TestDomainLookupIgnoresCase(t *testing.T) {
	cfg := Config{Domains: []Domain{{Name: "Example.com"}, {Name: "other.com"}}}

	got, ok := cfg.Domain("EXAMPLE.COM")
	if !ok {
		t.Fatal("domain lookup must ignore case; DNS names are case-insensitive")
	}
	if got.Name != "Example.com" {
		t.Errorf("Name = %q, want the config's own spelling", got.Name)
	}

	if _, ok := cfg.Domain("absent.com"); ok {
		t.Error("ok = true for a domain not in the config")
	}
}

func TestBoolOrDistinguishesUnsetFromFalse(t *testing.T) {
	// This is the whole reason the YAML fields are *bool: an explicit false must
	// override a true default, which a plain bool cannot express.
	no, yes := false, true

	if BoolOr(nil, true) != true {
		t.Error("BoolOr(nil, true) = false; an omitted key must take the default")
	}
	if BoolOr(nil, false) != false {
		t.Error("BoolOr(nil, false) = true")
	}
	if BoolOr(&no, true) != false {
		t.Error("an explicit false must override a true default, or opting out silently does nothing")
	}
	if BoolOr(&yes, false) != true {
		t.Error("an explicit true must override a false default")
	}
}

func TestAllTargetsDeduplicatesAcrossAliasesAndCatchAll(t *testing.T) {
	// Every target has to be a verified destination at Cloudflare, so a
	// duplicate becomes a redundant verification request, and a missed one
	// becomes mail that silently does not route.
	domain := Domain{
		Aliases: []Alias{
			{Match: "sales", To: []string{"owner@example.net", "shared@example.net"}},
			{Match: "support", To: []string{"OWNER@example.net"}},
		},
		CatchAll: &CatchAll{To: []string{"shared@example.net", "catch@example.net"}},
	}

	got := domain.AllTargets()

	if len(got) != 3 {
		t.Fatalf("AllTargets() = %v, want 3 distinct addresses", got)
	}
	// First occurrence wins, in the order encountered.
	want := []string{"owner@example.net", "shared@example.net", "catch@example.net"}
	for i, address := range want {
		if got[i] != address {
			t.Errorf("AllTargets()[%d] = %q, want %q", i, got[i], address)
		}
	}
	for _, address := range got {
		if strings.EqualFold(address, "OWNER@example.net") && address != "owner@example.net" {
			t.Errorf("kept %q; the case variant should have been folded into the first spelling", address)
		}
	}
}

func TestAllTargetsHandlesNoCatchAll(t *testing.T) {
	domain := Domain{Aliases: []Alias{{Match: "sales", To: []string{"a@example.net"}}}}

	if got := domain.AllTargets(); len(got) != 1 || got[0] != "a@example.net" {
		t.Errorf("AllTargets() = %v, want just the alias target", got)
	}

	if got := (Domain{}).AllTargets(); len(got) != 0 {
		t.Errorf("AllTargets() on an empty domain = %v, want empty", got)
	}
}

func TestMailboxLocalPart(t *testing.T) {
	if got := (Mailbox{Address: "contact@example.com"}).LocalPart(); got != "contact" {
		t.Errorf("LocalPart() = %q, want contact", got)
	}
	// A malformed address must not panic; validation reports it elsewhere.
	if got := (Mailbox{Address: "contact"}).LocalPart(); got != "contact" {
		t.Errorf("LocalPart() with no @ = %q, want the whole string", got)
	}
}
