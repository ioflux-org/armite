package gateway

import (
	"net/http"
	"slices"
	"strings"

	"github.com/ioflux-org/provisio/internal/azerr"
)

// Registry is the pipeline's terminal: it hands a routed request to the
// provider that owns its namespace. Providers are plain http.Handlers,
// so an in-process provider and a reverse proxy to another emulator are
// interchangeable - the seam the standalone-gateway plan depends on.
type Registry struct {
	providers map[string]http.Handler // key: lowercase namespace
	names     []string                // namespaces as registered, for the catalogue
}

// NewRegistry returns an empty registry. Until a provider registers,
// every request is answered with InvalidResourceNamespace.
func NewRegistry() *Registry {
	return &Registry{providers: make(map[string]http.Handler)}
}

// Register binds a provider namespace such as "Microsoft.Resources" to
// its handler. Namespaces compare case-insensitively. Registering one
// twice panics, as http.ServeMux does for a duplicate pattern: it is a
// wiring bug in main, and boot is the time to hear about it. Register
// is for boot only - it is not safe to call once the registry serves.
func (reg *Registry) Register(namespace string, h http.Handler) {
	key := strings.ToLower(namespace)
	if _, dup := reg.providers[key]; dup {
		panic("gateway: provider registered twice for " + namespace)
	}
	reg.providers[key] = h
	reg.names = append(reg.names, namespace)
}

// ServeHTTP dispatches on the namespace RouteRequest parsed. Native
// routes (subscriptions, resource groups) carry the implicit
// Microsoft.Resources namespace, so they reach that provider with no
// special casing here.
func (reg *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := RouteFromContext(r.Context())
	if !ok {
		azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
			"The request was not routed before dispatch.")
		return
	}
	h, ok := reg.providers[strings.ToLower(rt.ID.Namespace)]
	if !ok {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeInvalidResourceNamespace,
			"The resource namespace '"+rt.ID.Namespace+"' is invalid.")
		return
	}
	h.ServeHTTP(w, r)
}

// A ResourceType is one type a provider serves, with the api-versions it
// answers: what ARM's provider catalogue lists per namespace.
type ResourceType struct {
	Type        string
	APIVersions []string
}

// Describer is implemented by providers that can list their resource
// types, each with at least one api-version. The catalogue
// (GET /subscriptions/{sub}/providers) is built from it; a provider
// without it is listed with no types.
type Describer interface {
	ResourceTypes() []ResourceType
}

// ProviderInfo is one catalogue entry: a namespace and its types.
type ProviderInfo struct {
	Namespace string
	Types     []ResourceType
}

// Catalog lists every registered namespace, sorted, with the types each
// provider describes. Namespaces keep the casing they were registered
// with, which is what ARM echoes.
func (reg *Registry) Catalog() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(reg.names))
	for _, ns := range reg.names {
		info := ProviderInfo{Namespace: ns}
		if d, ok := reg.providers[strings.ToLower(ns)].(Describer); ok {
			info.Types = d.ResourceTypes()
		}
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b ProviderInfo) int {
		return strings.Compare(a.Namespace, b.Namespace)
	})
	return out
}
