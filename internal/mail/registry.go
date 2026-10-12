package mail

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/zoolcoder/mailctl/internal/cfapi"
	"github.com/zoolcoder/mailctl/internal/dns"
)

// Deps is everything a provider factory may need. A factory takes only what it
// uses; adding a field here does not change existing providers.
type Deps struct {
	Cloudflare        *cfapi.Client
	AccountID         string
	PurelymailBaseURL string
	// Zones resolves a zone name to a zone ID. Providers whose API is
	// zone-scoped need it; Purelymail ignores it.
	Zones  dns.Provider
	Getenv func(string) string
	// GraphBaseURL and LoginBaseURL override the Microsoft endpoints. Tests
	// point them at httptest servers; production leaves them empty.
	GraphBaseURL string
	LoginBaseURL string
}

type Factory func(Deps) (Provider, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register adds a provider factory. Providers call this from an init function
// and are pulled in by a blank import in cmd/mailctl, so the engine never
// imports a provider package directly.
func Register(name string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("mail: provider " + name + " registered twice")
	}
	registry[name] = f
}

// Unregister removes a provider. It exists so tests can register fakes without
// leaking them into other tests.
func Unregister(name string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	delete(registry, name)
}

// Open builds the named provider.
func Open(name string, deps Deps) (Provider, error) {
	registryMu.RLock()
	factory, ok := registry[name]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown mail provider %q; available providers are %s",
			name, strings.Join(Registered(), ", "))
	}
	provider, err := factory(deps)
	if err != nil {
		return nil, fmt.Errorf("open mail provider %s: %w", name, err)
	}
	return provider, nil
}

// Registered returns every registered provider name, sorted.
func Registered() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
