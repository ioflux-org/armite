// Package keyvault is the Microsoft.KeyVault provider's management
// plane: vaults as ARM resources in the shared resource store. The data
// plane - secrets under each vault's own hostname - is M4b.
package keyvault

import (
	"log"
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

// Provider serves the Microsoft.KeyVault namespace.
type Provider struct {
	cfg   config.Config
	store *store.Store
}

// New returns a provider storing vaults in st, the store the resource
// groups live in: a vault must find its group there.
func New(cfg config.Config, st *store.Store) *Provider {
	return &Provider{cfg: cfg, store: st}
}

// ServeHTTP dispatches on the type chain RouteRequest parsed.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := gateway.RouteFromContext(r.Context())
	if !ok {
		azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
			"The request was not routed before dispatch.")
		return
	}
	chain := strings.ToLower(strings.Join(rt.ID.Types, "/"))
	switch chain {
	case "vaults":
		if rt.ID.IsInstance() {
			p.serveVault(w, r, rt.ID)
		} else {
			p.serveVaults(w, r, rt.ID)
		}
	case "deletedvaults", "managedhsms", "deletedmanagedhsms":
		// Collections az enumerates next to vaults that Provisio does not
		// model: vault soft delete is not emulated and there are no
		// managed HSMs. Always empty, so az keyvault list and
		// list-deleted work and show nothing extra.
		if r.Method != http.MethodGet {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on '"+chain+"'.")
			return
		}
		gateway.WriteJSON(w, http.StatusOK, struct {
			Value []any `json:"value"`
		}{[]any{}})
	case "locations/deletedvaults":
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"Vault soft delete is not emulated: no deleted vault named '"+rt.ID.Names[1]+"' exists.")
	default:
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeInvalidResourceType,
			"The resource type '"+chain+"' could not be found in the namespace "+
				"'Microsoft.KeyVault' for api version '"+rt.APIVersion+"'.")
	}
}

// internalError is the provider's own failure: logged with detail, told
// to the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("keyvault: %v", err)
	azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
		"An internal error occurred in the Microsoft.KeyVault provider.")
}
