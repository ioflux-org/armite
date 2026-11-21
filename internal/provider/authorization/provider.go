// Package authorization is the Microsoft.Authorization provider: role
// definitions, read-only from the embedded built-in seed, and role
// assignments, created and deleted in the RBAC engine's own store.
// Serving both from the evaluator's data means a listing and a 403 can
// never disagree, and a revoked grant is gone on the next request.
package authorization

import (
	"log"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/directory"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/rbac"
)

// Principals is what the provider needs from a directory: whether an
// object id is a user, a group or a service principal there, and which.
// *directory.Store is one; a Provider built without a directory answers
// from the configuration's identities.
type Principals interface {
	PrincipalByID(id string) (directory.Object, bool)
}

// Provider serves the Microsoft.Authorization namespace.
type Provider struct {
	cfg   config.Config
	defs  map[string]rbac.RoleDefinition
	keys  []string // definition GUIDs, sorted: listings are deterministic
	store *rbac.AssignmentStore
	dir   Principals
	now   func() time.Time
}

// New returns a provider over defs and store. now stamps createdOn on
// new assignments; tests pass a fixed clock.
func New(
	cfg config.Config, defs map[string]rbac.RoleDefinition,
	store *rbac.AssignmentStore, now func() time.Time,
) *Provider {
	return &Provider{
		cfg:   cfg,
		defs:  defs,
		keys:  slices.Sorted(maps.Keys(defs)),
		store: store,
		dir:   configPrincipals{cfg},
		now:   now,
	}
}

// WithDirectory makes role assignments consult dir for their principal,
// so one created through Graph a moment ago can be granted a role at
// once. It returns p, for use where the provider is built.
func (p *Provider) WithDirectory(dir Principals) *Provider {
	p.dir = dir
	return p
}

// ResourceTypes lists what this provider serves, for the catalogue.
func (p *Provider) ResourceTypes() []gateway.ResourceType {
	return []gateway.ResourceType{
		{Type: "roleAssignments", APIVersions: []string{"2022-04-01"}},
		{Type: "roleDefinitions",
			APIVersions: []string{"2022-05-01-preview", "2022-04-01"}},
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
	switch strings.ToLower(strings.Join(rt.ID.Types, "/")) {
	case "roledefinitions":
		p.serveDefinitions(w, r, rt)
	case "roleassignments":
		p.serveAssignments(w, r, rt)
	default:
		azerr.WriteError(w, http.StatusNotFound, azerr.CodeInvalidResourceType,
			"The resource type '"+strings.Join(rt.ID.Types, "/")+"' could not be found in the "+
				"namespace 'Microsoft.Authorization' for api version '"+rt.APIVersion+"'.")
	}
}

// subscriptionRe matches the "/subscriptions/{id}" prefix of a scope.
var subscriptionRe = regexp.MustCompile(`(?i)^/subscriptions/[^/]+`)

// definitionID is the ID a role definition is echoed under for a request
// at scope: below the scope's subscription when there is one, at the
// tenant root otherwise, as real ARM does. The same function builds the
// roleDefinitionId inside assignments, so the two always agree - az
// relies on that to label assignments with role names.
func definitionID(scope, guid string) string {
	return subscriptionRe.FindString(scope) + "/providers/Microsoft.Authorization/roleDefinitions/" + guid
}

// lastSegment reduces a role definition reference to its GUID: the full
// ARM path and the bare GUID both yield the GUID.
func lastSegment(id string) string {
	if i := strings.LastIndexByte(id, '/'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// sameScope compares scopes the way ARM does: case-insensitively,
// ignoring a trailing slash.
func sameScope(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// configPrincipals answers from the configuration alone: its clients
// and its managed identity, all service principals.
type configPrincipals struct{ cfg config.Config }

func (c configPrincipals) PrincipalByID(id string) (directory.Object, bool) {
	for _, cl := range c.cfg.Clients {
		if strings.EqualFold(cl.ObjectID, id) {
			return directory.Object{ID: cl.ObjectID, Kind: directory.KindServicePrincipal, AppID: cl.ID}, true
		}
	}
	if mi := c.cfg.ManagedIdentity; strings.EqualFold(mi.ObjectID, id) {
		return directory.Object{ID: mi.ObjectID, Kind: directory.KindServicePrincipal, AppID: mi.ClientID}, true
	}
	return directory.Object{}, false
}

// principalTypeOf is the name RBAC gives a directory object's kind.
func principalTypeOf(o directory.Object) string {
	switch o.Kind {
	case directory.KindUser:
		return "User"
	case directory.KindGroup:
		return "Group"
	default:
		return "ServicePrincipal"
	}
}

// internalError is the provider's own failure: logged with detail, told
// to the client without it.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("authorization: %v", err)
	azerr.WriteError(w, http.StatusInternalServerError, azerr.CodeInternalServerError,
		"An internal error occurred in the Microsoft.Authorization provider.")
}
