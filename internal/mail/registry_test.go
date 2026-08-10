package mail

import (
	"context"
	"strings"
	"testing"

	"github.com/zoolcoder/mailctl/internal/config"
	"github.com/zoolcoder/mailctl/internal/dns"
	"github.com/zoolcoder/mailctl/internal/plan"
)

type stubProvider struct{ name string }

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) DesiredDNS(context.Context, config.Domain) ([]dns.Record, error) {
	return nil, nil
}
func (s stubProvider) Actual(context.Context, config.Domain) (State, error) { return State{}, nil }
func (s stubProvider) Plan(config.Domain, State, Options) ([]plan.Action, error) {
	return nil, nil
}

func TestOpenReturnsRegisteredProvider(t *testing.T) {
	Register("stub", func(Deps) (Provider, error) { return stubProvider{name: "stub"}, nil })
	t.Cleanup(func() { Unregister("stub") })

	got, err := Open("stub", Deps{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Name() != "stub" {
		t.Errorf("Name() = %q, want stub", got.Name())
	}
}

func TestOpenUnknownProviderListsWhatIsAvailable(t *testing.T) {
	Register("stub", func(Deps) (Provider, error) { return stubProvider{name: "stub"}, nil })
	t.Cleanup(func() { Unregister("stub") })

	_, err := Open("nope", Deps{})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "nope") || !strings.Contains(err.Error(), "stub") {
		t.Errorf("error should name the unknown provider and the known ones; got %q", err)
	}
}

func TestKnownProvidersMatchRegistry(t *testing.T) {
	// config.KnownProviders is a hand-maintained copy of the registry so that
	// config validation does not import this package. This test keeps them
	// honest. Every registered provider must appear in config.KnownProviders.
	for _, name := range Registered() {
		found := false
		for _, known := range config.KnownProviders {
			if known == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("provider %q is registered but missing from config.KnownProviders", name)
		}
	}
}
