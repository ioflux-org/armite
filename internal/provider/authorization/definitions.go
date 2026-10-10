package authorization

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/rbac"
)

// definition is the Role Definitions API resource (api-version
// 2022-05-01-preview). The seed keeps the flat `az role definition list`
// shape; the wire nests everything but identity under properties and
// calls the role type "type".
type definition struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Type       string               `json:"type"`
	Properties definitionProperties `json:"properties"`
}

type definitionProperties struct {
	RoleName         string            `json:"roleName"`
	Type             string            `json:"type"`
	Description      string            `json:"description"`
	AssignableScopes []string          `json:"assignableScopes"`
	Permissions      []rbac.Permission `json:"permissions"`
}

func toDefinition(scope string, d rbac.RoleDefinition) definition {
	return definition{
		ID:   definitionID(scope, d.Name),
		Name: d.Name,
		Type: "Microsoft.Authorization/roleDefinitions",
		Properties: definitionProperties{
			RoleName:         d.RoleName,
			Type:             d.RoleType,
			Description:      d.Description,
			AssignableScopes: d.AssignableScopes,
			Permissions:      d.Permissions,
		},
	}
}

// definitionFilterRe accepts the two filters az sends: roleName eq '…'
// (how a role name becomes a GUID) and type eq '…' (--custom-role-only).
var definitionsFilterRe = regexp.MustCompile(`(?i)^(roleName|type)\s+eq\s+'([^']*)'$`)

// serveDefinitions handles GET on the collection (with $filter) and on
// one definition. Custom roles are deferred, so every other verb is 405.
func (p *Provider) serveDefinitions(w http.ResponseWriter, r *http.Request, rt gateway.Route) {
	if r.Method != http.MethodGet {
		azerr.WriteError(w, http.StatusMethodNotAllowed, azerr.CodeMethodNotAllowed,
			"Custom role definitions are not supported yet; built-in roles are read-only.")
		return
	}
	id := rt.ID
	if id.IsInstance() {
		d, ok := p.defs[strings.ToLower(id.Names[0])]
		if !ok {
			azerr.WriteError(w, http.StatusNotFound, azerr.CodeRoleDefinitionDoesNotExist,
				"The specified role definition with ID '"+id.Names[0]+"' does not exist.")
			return
		}
		gateway.WriteJSON(w, http.StatusOK, toDefinition(id.Scope, d))
		return
	}

	field, value := "", ""
	filter := strings.TrimSpace(r.URL.Query().Get("$filter"))
	switch {
	case filter == "", strings.EqualFold(filter, "atScopeAndBelow()"):
		// Every built-in role is assignable everywhere: nothing to narrow.
	default:
		m := definitionsFilterRe.FindStringSubmatch(filter)
		if m == nil {
			azerr.WriteError(w, http.StatusBadRequest, azerr.CodeInvalidFilter,
				"The filter '"+filter+"' is not supported. Use roleName eq '...' or type eq '...'.")
			return
		}
		field, value = strings.ToLower(m[1]), m[2]
	}
	out := make([]definition, 0)
	for _, guid := range p.keys {
		d := p.defs[guid]
		if field == "rolename" && !strings.EqualFold(d.RoleName, value) {
			continue
		}
		if field == "type" && !strings.EqualFold(d.RoleType, value) {
			continue
		}
		out = append(out, toDefinition(id.Scope, d))
	}
	gateway.WriteJSON(w, http.StatusOK, struct {
		Value []definition `json:"value"`
	}{out})
}
