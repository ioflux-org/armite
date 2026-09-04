package arm

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrUnsupportedMethod reports an HTTP method ARM has no verb semantics
// for. The gateway maps it to 405; ErrInvalidPath maps to 400/404.
var ErrUnsupportedMethod = errors.New("unsupported HTTP method")

// DeriveAction maps an HTTP method applied to a parsed resource ID onto
// the RBAC action string and the scope to evaluate it at. The mapping is
// mechanical: GET/HEAD -> read, PUT/PATCH -> write, DELETE -> delete, and
// POST turns the trailing unpaired type into {name}/action - the action
// name rides the type slot, which is why listKeys yields
// Microsoft.KeyVault/vaults/listKeys/action with no special casing.
// Scope casing is preserved; the rbac package normalizes internally.
func DeriveAction(method string, id ResourceID) (action, scope string, err error) {
	typePath := id.Namespace + "/" + strings.Join(id.Types, "/")

	switch method {
	case http.MethodGet, http.MethodHead:
		action = typePath + "/read"
	case http.MethodPut, http.MethodPatch:
		if !id.IsInstance() {
			return "", "", fmt.Errorf("%w: %s requires a resource name", ErrInvalidPath, method)
		}
		action = typePath + "/write"
	case http.MethodDelete:
		if !id.IsInstance() {
			return "", "", fmt.Errorf("%w: DELETE requires a resource name", ErrInvalidPath)
		}
		action = typePath + "/delete"
	case http.MethodPost:
		if id.IsInstance() {
			return "", "", fmt.Errorf("%w: POST requires an action name", ErrInvalidPath)
		}
		action = typePath + "/action"
	default:
		return "", "", fmt.Errorf("%w: %s", ErrUnsupportedMethod, method)
	}
	return action, authScope(id), nil
}

// authScope returns the scope an assignment must cover for this request:
// the addressed resource itself for an instance; the parent for a
// collection or action, by truncating the type chain to its paired
// prefix. Listing vaults in a group is authorized at the group; invoking
// listKeys on a vault is authorized at the vault.
func authScope(id ResourceID) string {
	pairs := len(id.Names)
	if pairs == 0 {
		if id.Scope == "" {
			return "/"
		}
		return id.Scope
	}
	instance := id
	instance.Types = instance.Types[:pairs]
	return instance.String()
}
