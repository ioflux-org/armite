package resources

import (
	"net/http"
	"strings"

	"github.com/ioflux-org/provisio/internal/arm"
	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/gateway"
)

// subscription is the Subscriptions API resource (api-version
// 2022-12-01). az login reads id, displayName, state and tenantId; the
// rest is what a real subscription carries, with fixed values.
type subscription struct {
	ID                   string               `json:"id"`
	SubscriptionID       string               `json:"subscriptionId"`
	DisplayName          string               `json:"displayName"`
	State                string               `json:"state"`
	TenantID             string               `json:"tenantId"`
	AuthorizationSource  string               `json:"authorizationSource"`
	ManagedByTenants     []managedTenant      `json:"managedByTenants"`
	SubscriptionPolicies subscriptionPolicies `json:"subscriptionPolicies"`
}

type managedTenant struct {
	TenantID string `json:"tenantId"`
}

type subscriptionPolicies struct {
	LocationPlacementID string `json:"locationPlacementId"`
	QuotaID             string `json:"quotaId"`
	SpendingLimit       string `json:"spendingLimit"`
}

// tenant is the Tenants API resource (api-version 2022-12-01).
type tenant struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenantId"`
	TenantCategory string `json:"tenantCategory"`
	DisplayName    string `json:"displayName"`
	TenantType     string `json:"tenantType"`
}

func (p *Provider) subscription() subscription {
	return subscription{
		ID:                  "/subscriptions/" + p.cfg.SubscriptionID,
		SubscriptionID:      p.cfg.SubscriptionID,
		DisplayName:         p.cfg.SubscriptionName,
		State:               "Enabled",
		TenantID:            p.cfg.TenantID,
		AuthorizationSource: "RoleBased",
		ManagedByTenants:    []managedTenant{},
		SubscriptionPolicies: subscriptionPolicies{
			LocationPlacementID: "Public_2014-09-01",
			QuotaID:             "PayAsYouGo_2014-09-01",
			SpendingLimit:       "Off",
		},
	}
}

func (p *Provider) tenant() tenant {
	return tenant{
		ID:             "/tenants/" + p.cfg.TenantID,
		TenantID:       p.cfg.TenantID,
		TenantCategory: "Home",
		DisplayName:    p.cfg.TenantName,
		TenantType:     "AAD",
	}
}

// serveSubscriptions handles GET /subscriptions (list) and
// GET /subscriptions/{id} (get). Provisio has one subscription and every
// authenticated principal sees it; real ARM lists only the subscriptions
// the caller has some access to.
func (p *Provider) serveSubscriptions(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on subscriptions.")
		return
	}
	if id.IsInstance() {
		if !strings.EqualFold(id.Names[0], p.cfg.SubscriptionID) {
			azerr.WriteError(w, http.StatusNotFound, azerr.CodeSubscriptionNotFound,
				"The subscription '"+id.Names[0]+"' could not be found.")
			return
		}
		gateway.WriteJSON(w, http.StatusOK, p.subscription())
		return
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []subscription `json:"value"`
	}{[]subscription{p.subscription()}})
}

// serveTenants handles GET /tenants. The API has no "get one tenant"
// operation, so an instance path is a 404.
func (p *Provider) serveTenants(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on tenants.")
		return
	}
	if id.IsInstance() {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"The resource '"+r.URL.Path+"' does not exist: tenants can only be listed.")
		return
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []tenant `json:"value"`
	}{[]tenant{p.tenant()}})
}
