// Package keyvault is the Microsoft.KeyVault provider: the management
// plane (vaults as ARM resources in the shared resource store) and the
// data plane (secrets, served under each vault's own hostname).
package keyvault

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/state"
	"github.com/ioflux-org/armite/internal/store"
)

// Provider serves the Microsoft.KeyVault namespace.
type Provider struct {
	cfg     config.Config
	store   *store.Store // vaults, next to the resource groups they live in
	secrets *secretStore // each vault's secrets
	now     func() time.Time
}

// New builds the provider over the resource store the resource
// groups live in: a vault must find its group there. Secrets live in
// the provider's own store, persisted through journal (nil: memory
// only).
func New(cfg config.Config, st *store.Store, journal *state.Log) *Provider {
	return &Provider{cfg: cfg, store: st, secrets: newSecretStore(journal), now: time.Now}
}

// ResourceTypes lists what this provider serves, for the catalogue.
func (p *Provider) ResourceTypes() []gateway.ResourceType {
	return []gateway.ResourceType{
		{Type: "vaults", APIVersions: []string{"2025-05-01"}},
		{Type: "deletedVaults", APIVersions: []string{"2025-05-01"}},
		{Type: "locations/deletedVaults", APIVersions: []string{"2025-05-01"}},
	}
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
		// Collections az enumerates next to vaults that Armite does not
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
	case "locations/deletedvaults/purge":
		// Terraform purges every vault it destroys (purge_soft_delete_on_destroy
		// defaults to true). Nothing lingers here, so the purge is an
		// already-finished long-running operation: 202 with a Location the
		// SDK polls once and finds complete.
		if r.Method != http.MethodPost {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on '"+chain+"'.")
			return
		}
		w.Header().Set("Location", p.cfg.ARMBaseURL()+"/subscriptions/"+p.cfg.SubscriptionID+
			"/providers/Microsoft.KeyVault/locations/"+rt.ID.Names[0]+"/operationResults/"+
			newVersionID()+"?api-version="+rt.APIVersion)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusAccepted)
	case "locations/operationresults":
		// Every operation Armite ever accepted finished before it answered.
		if r.Method != http.MethodGet {
			azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
				"The method '"+r.Method+"' is not allowed on '"+chain+"'.")
			return
		}
		gateway.WriteJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{"Succeeded"})
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
