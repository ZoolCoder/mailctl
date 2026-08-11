package mail

import "testing"

// State.Mailbox and State.Alias are how every provider asks "does the thing
// config names already exist?", and the answer decides between CREATE, UPDATE
// and doing nothing. A false negative here creates a duplicate; a false
// positive silently skips work the operator asked for.

func TestMailboxLookupIgnoresAddressCase(t *testing.T) {
	state := State{Mailboxes: []Mailbox{{Address: "Contact@Example.com"}}}

	got, ok := state.Mailbox("contact@example.com")
	if !ok {
		t.Fatal("a mailbox differing only in case must be found, or the plan proposes creating a duplicate")
	}
	if got.Address != "Contact@Example.com" {
		t.Errorf("Address = %q, want the provider's own spelling preserved", got.Address)
	}
}

func TestMailboxLookupMatchesTheAlternateAddress(t *testing.T) {
	// Microsoft Graph keeps two identity attributes that an admin can change
	// independently. Config may name either one.
	state := State{Mailboxes: []Mailbox{{
		Address:          "contact@example.com",
		AlternateAddress: "contact@example.onmicrosoft.com",
	}}}

	got, ok := state.Mailbox("CONTACT@example.onmicrosoft.com")
	if !ok {
		t.Fatal("a match on AlternateAddress must count, or a diverged mailbox is created twice")
	}
	if got.Address != "contact@example.com" {
		t.Errorf("Address = %q, want the entry found by its alternate", got.Address)
	}
}

func TestMailboxLookupReportsMissing(t *testing.T) {
	state := State{Mailboxes: []Mailbox{{Address: "contact@example.com"}}}

	if got, ok := state.Mailbox("sales@example.com"); ok {
		t.Errorf("ok = true for an absent address, returning %+v", got)
	}
}

func TestMailboxLookupIgnoresAnEmptyAlternateAddress(t *testing.T) {
	// The zero value must not match the empty string, or every provider with a
	// single identity attribute matches any lookup for "".
	state := State{Mailboxes: []Mailbox{{Address: "contact@example.com"}}}

	if _, ok := state.Mailbox(""); ok {
		t.Error("an empty lookup matched an empty AlternateAddress")
	}
}

func TestAliasLookupRequiresThePrefixFlagToAgree(t *testing.T) {
	state := State{Aliases: []Alias{
		{Match: "sales", Prefix: false, To: []string{"a@example.com"}},
		{Match: "team", Prefix: true, To: []string{"b@example.com"}},
	}}

	if _, ok := state.Alias("sales", true); ok {
		t.Error("an exact alias matched a prefix lookup; a prefix alias catches addresses the exact one does not")
	}
	if _, ok := state.Alias("team", false); ok {
		t.Error("a prefix alias matched an exact lookup")
	}

	got, ok := state.Alias("SALES", false)
	if !ok {
		t.Fatal("alias lookup must ignore case")
	}
	if len(got.To) != 1 || got.To[0] != "a@example.com" {
		t.Errorf("To = %v, want the exact alias's targets", got.To)
	}
}
