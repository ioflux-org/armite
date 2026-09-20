package resources

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/ioflux-org/provisio/internal/arm"
	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/gateway"
)

// genericResource is one entry of the generic resource listing: identity
// and placement, never properties. az keyvault list and az resource list
// read it, and az keyvault show without --resource-group finds the
// group through it.
// Spec: resources mgmt 2024-11-01 resources.json#/definitions/GenericResourceExpanded (subset)
type genericResource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Location string            `json:"location,omitempty"`
	Tags     map[string]string `json:"tags,omitempty"`
}

// The listing filter az sends: resourceType eq '…' and name eq '…',
// in either order, joined by "and".
var (
	resourceTermRe = regexp.MustCompile(`(?i)^(resourceType|name)\s+eq\s+'([^']*)'$`)
	filterAndRe    = regexp.MustCompile(`(?i)\s+and\s+`)
)

// parseResourceFilter returns the type and name to keep ("" for any);
// ok is false for a filter Provisio does not understand.
func parseResourceFilter(filter string) (typ, name string, ok bool) {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return "", "", true
	}
	for _, term := range filterAndRe.Split(filter, -1) {
		m := resourceTermRe.FindStringSubmatch(term)
		if m == nil {
			return "", "", false
		}
		if strings.EqualFold(m[1], "resourceType") {
			typ = m[2]
		} else {
			name = m[2]
		}
	}
	return typ, name, true
}

// serveResources lists every resource below a subscription or a group:
// GET {scope}/resources. Groups are containers, not resources, and are
// left out. $expand and $top are accepted and ignored.
func (p *Provider) serveResources(w http.ResponseWriter, r *http.Request, id arm.ResourceID) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"The method '"+r.Method+"' is not allowed on the resource listing.")
		return
	}
	if id.IsInstance() {
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeResourceNotFound,
			"The resource listing has no members of its own; address a resource by its full ID.")
		return
	}
	filter := r.URL.Query().Get("$filter")
	typ, name, ok := parseResourceFilter(filter)
	if !ok {
		azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidFilter,
			"The filter '"+filter+"' is not supported. Use resourceType eq '...' and name eq '...'.")
		return
	}
	scope := "/subscriptions/" + id.Names[0]
	if len(id.Names) == 2 {
		scope += "/resourceGroups/" + id.Names[1]
	}
	all, err := p.store.List(scope, typ)
	if err != nil {
		internalError(w, err)
		return
	}
	out := make([]genericResource, 0, len(all))
	for _, res := range all {
		if strings.EqualFold(res.Type, groupType) {
			continue
		}
		if name != "" && !strings.EqualFold(res.Name, name) {
			continue
		}
		out = append(out, genericResource{
			ID: res.ID, Name: res.Name, Type: res.Type, Location: res.Location, Tags: res.Tags,
		})
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []genericResource `json:"value"`
	}{out})
}
