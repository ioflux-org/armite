// Package resources is the Microsoft.Resources provider: subscriptions,
// tenants and resource groups. It is registered in the gateway's
// Registry, so it only ever sees routed, authenticated and authorized
// requests.
package resources

import (
	"log"
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

// Provider serves the Microsoft.Resources namespace: the fixed
// subscription and tenant from config, resource groups from the store.
type Provider struct {
	cfg   config.Config
	store *store.Store
}

// New returns a provider describing cfg's subscription and tenant,
// storing groups in st.
func New(cfg config.Config, st *store.Store) *Provider {
	return &Provider{cfg: cfg, store: st}
}

// ServeHTTP dispatches on the type chain RouteRequest parsed. Native
// routes arrive with canonical casing; comparing lowercase keeps the
// table honest anyway.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rt, ok := gateway.RouteFromContext(r.Context())
	if !ok {
		azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
			"The request was not routed before dispatch.")
		return
	}
	switch strings.ToLower(strings.Join(rt.ID.Types, "/")) {
	case "subscriptions":
		p.serveSubscriptions(w, r, rt.ID)
	case "subscriptions/resourcegroups":
		if rt.ID.IsInstance() {
			p.serveGroup(w, r, rt.ID)
		} else {
			p.serveGroups(w, r, rt.ID)
		}
	case "tenants":
		p.serveTenants(w, r, rt.ID)
	case "subscriptions/resources", "subscriptions/resourcegroups/resources":
		p.serveResources(w, r, rt.ID)
	default:
		// The parser's native whitelist admits nothing else today; this
		// is the fail-closed answer for a future entry without a handler.
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"Provisio has no handler for '"+r.URL.Path+"'.")
	}
}

// internalError is the provider's own failure: logged with detail, told
// to the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("resources: %v", err)
	azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
		"An internal error occurred in the Microsoft.Resources provider.")
}
