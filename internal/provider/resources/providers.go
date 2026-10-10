package resources

import (
	"net/http"
	"strings"

	"github.com/ioflux-org/armite/internal/arm"
	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/gateway"
)

// provider is the catalogue entry for one namespace: what Terraform reads
// at start-up to learn which providers are registered, and what az reads
// to pick an api-version for a resource type.
// Spec: resources mgmt 2024-11-01 resources.json#/definitions/Provider (subset)
type provider struct {
	ID                 string                 `json:"id"`
	Namespace          string                 `json:"namespace"`
	RegistrationState  string                 `json:"registrationState"`
	RegistrationPolicy string                 `json:"registrationPolicy"`
	ResourceTypes      []providerResourceType `json:"resourceTypes"`
}

// Spec: resources mgmt 2024-11-01 resources.json#/definitions/ProviderResourceType (subset)
type providerResourceType struct {
	ResourceType      string   `json:"resourceType"`
	Locations         []string `json:"locations"`
	APIVersions       []string `json:"apiVersions"`
	DefaultAPIVersion string   `json:"defaultApiVersion,omitempty"`
}

// serveProviders answers the catalogue: every registered namespace is
// "Registered" (nothing is ever unregistered here), listed or fetched
// by name. Locations are nominal - no provider checks them.
func (p *Provider) serveProviders(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on '"+r.URL.Path+"'.")
		return
	}
	all := p.catalog()
	if id.IsInstance() {
		want := id.Names[len(id.Names)-1]
		for _, info := range all {
			if strings.EqualFold(info.Namespace, want) {
				gateway.WriteJSON(w, http.StatusOK, p.toProvider(id, info))
				return
			}
		}
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeInvalidResourceNamespace,
			"The resource namespace '"+want+"' is invalid.")
		return
	}
	out := make([]provider, 0, len(all))
	for _, info := range all {
		out = append(out, p.toProvider(id, info))
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value    []provider `json:"value"`
		NextLink *string    `json:"nextLink"`
	}{out, nil})
}

// toProvider builds one entry; the ID hangs off the request's scope
// (a subscription, or the tenant for /providers).
func (p *Provider) toProvider(id arm.ResourceID, info gateway.ProviderInfo) provider {
	scope := ""
	if strings.EqualFold(id.Types[0], "subscriptions") {
		scope = "/subscriptions/" + id.Names[0]
	}
	types := make([]providerResourceType, 0, len(info.Types))
	for _, t := range info.Types {
		types = append(types, providerResourceType{
			ResourceType:      t.Type,
			Locations:         []string{"East US"},
			APIVersions:       t.APIVersions,
			DefaultAPIVersion: t.APIVersions[0],
		})
	}
	return provider{
		ID:                 scope + "/providers/" + info.Namespace,
		Namespace:          info.Namespace,
		RegistrationState:  "Registered",
		RegistrationPolicy: "RegistrationRequired",
		ResourceTypes:      types,
	}
}
