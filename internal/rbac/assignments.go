package rbac

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// RoleAssignment binds a principal to a role definition at a scope:
// "principal P has role R at scope S". It is both the evaluator's input
// and the ARM resource the Microsoft.Authorization provider serves, so
// the store is the single source of truth for both.
//
// Name is the assignment's GUID: ARM clients choose it on PUT, and the
// store derives one when it is empty. ID is the full ARM path, set by
// Add. RoleDefinitionID is stored as the bare lowercase GUID; the full
// ARM path is accepted on the way in.
type RoleAssignment struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	PrincipalID      string    `json:"principalId"`
	PrincipalType    string    `json:"principalType"`
	RoleDefinitionID string    `json:"roleDefinitionId"`
	Scope            string    `json:"scope"`
	CreatedOn        time.Time `json:"createdOn"`
}

// assignmentID is the ARM resource ID of the assignment named name at
// scope: {scope}/providers/Microsoft.Authorization/roleAssignments/{name}.
// At the tenant root the scope prefix is empty, not "/".
func assignmentID(scope, name string) string {
	return strings.TrimSuffix(scope, "/") + "/providers/Microsoft.Authorization/roleAssignments/" + name
}

// deriveName returns a GUID-shaped name computed from the assignment's
// triple, so unnamed assignments (config seeds, tests) get the same name
// on every boot. The version and variant nibbles follow RFC 4122, making
// it a well-formed name-based UUID.
func deriveName(principal, role, scope string) string {
	sum := sha256.Sum256([]byte(principal + "|" + role + "|" + scope))
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[0:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}
