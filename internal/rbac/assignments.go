package rbac

// RoleAssignment binds a principal to a role definition at a scope:
// "principal P has role R at scope S", nothing more. In real Azure,
// RoleDefinitionID is the full ARM path ("/providers/Microsoft.
// Authorization/roleDefinitions/{guid}"); the store will accept the
// bare GUID too and normalize.
type RoleAssignment struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	Scope            string `json:"scope"`
}
