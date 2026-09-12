package resources

import (
	"log"
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

// Provider serves the Microsoft.Resources namespace on top of the
// generic resource store.
type Provider struct {
	store *store.Store
}

// New returns a provider backed by st.
func New(st *store.Store) *Provider {
	return &Provider{store: st}
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
	case "subscriptions/resourcegroups":
		if rt.ID.IsInstance() {
			p.serveGroup(w, r, rt.ID)
		} else {
			p.serveGroups(w, r, rt.ID)
		}
	default:
		// subscriptions and tenants: M3f.
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"Provisio has no handler for '"+r.URL.Path+"' yet.")
	}
}

// internalError is the provider's own failure: logged with detail, told
// to the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("resources: %v", err)
	azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
		"An internal error occurred in the Microsoft.Resources provider.")
}
