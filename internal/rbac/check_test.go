package rbac

import (
	"strings"
	"testing"
)

const (
	unknownPrincipal = "99999999-9999-9999-9999-999999999999"
	danglingRoleID   = "aaaabbbb-aaaa-bbbb-aaaa-bbbbaaaabbbb"

	subScope   = "/subscriptions/00000000-0000-0000-0000-000000000000"
	rgScope    = subScope + "/resourcegroups/dev"
	vaultScope = rgScope + "/providers/microsoft.keyvault/vaults/kv1"

	actVaultWrite  = "Microsoft.KeyVault/vaults/write"
	actVaultRead   = "Microsoft.KeyVault/vaults/read"
	actGetSecret   = "Microsoft.KeyVault/vaults/secrets/getSecret/action"
	actAssignWrite = "Microsoft.Authorization/roleAssignments/write"
)

// assign builds the minimal assignment the evaluator needs.
func assign(roleDefID, scope string) RoleAssignment {
	return RoleAssignment{PrincipalID: testPrincipal, RoleDefinitionID: roleDefID, Scope: scope}
}

// newTestChecker loads the real builtin seed and returns a Checker over
// the given assignments.
func newTestChecker(t *testing.T, assignments ...RoleAssignment) *Checker {
	t.Helper()
	defs, err := LoadBuiltinRoles()
	if err != nil {
		t.Fatalf("LoadBuiltinRoles: %v", err)
	}
	store := NewAssignmentStore()
	for _, a := range assignments {
		if err := store.Add(a); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	return NewChecker(defs, store)
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name         string
		assignments  []RoleAssignment
		principal    string
		action       string
		scope        string
		isDataAction bool
		want         bool
	}{
		// 1. THE acceptance pair: same principal, same role, both planes.
		{"owner allows management write", []RoleAssignment{assign(ownerID, subScope)},
			testPrincipal, actVaultWrite, vaultScope, false, true},
		{"owner DENIED data action", []RoleAssignment{assign(ownerID, subScope)},
			testPrincipal, actGetSecret, vaultScope, true, false},

		// 2. The mirror image.
		{"secrets user allows getSecret", []RoleAssignment{assign(kvSecretsUserID, vaultScope)},
			testPrincipal, actGetSecret, vaultScope, true, true},
		{"secrets user denied management write", []RoleAssignment{assign(kvSecretsUserID, vaultScope)},
			testPrincipal, actVaultWrite, vaultScope, false, false},

		// 3. NotActions subtract within their own definition...
		{"contributor allows vault write", []RoleAssignment{assign(contributorID, subScope)},
			testPrincipal, actVaultWrite, vaultScope, false, true},
		{"contributor denied roleAssignments write", []RoleAssignment{assign(contributorID, subScope)},
			testPrincipal, actAssignWrite, subScope, false, false},

		// 4. ...but NEVER veto another assignment's grant.
		{"contributor plus owner allows roleAssignments write",
			[]RoleAssignment{assign(contributorID, subScope), assign(ownerID, subScope)},
			testPrincipal, actAssignWrite, subScope, false, true},

		// 5. Reader's */read through the full path.
		{"reader allows read", []RoleAssignment{assign(readerID, subScope)},
			testPrincipal, actVaultRead, vaultScope, false, true},
		{"reader denied write", []RoleAssignment{assign(readerID, subScope)},
			testPrincipal, actVaultWrite, vaultScope, false, false},

		// 6. Inheritance flows down, never up.
		{"rg assignment grants at vault below", []RoleAssignment{assign(ownerID, rgScope)},
			testPrincipal, actVaultWrite, vaultScope, false, true},
		{"rg assignment grants nothing at subscription", []RoleAssignment{assign(ownerID, rgScope)},
			testPrincipal, actVaultWrite, subScope, false, false},

		// 7. Defaults.
		{"unknown principal denied", []RoleAssignment{assign(ownerID, subScope)},
			unknownPrincipal, actVaultRead, vaultScope, false, false},
		{"no assignments denied", nil,
			testPrincipal, actVaultRead, vaultScope, false, false},
		{"dangling role definition grants nothing", []RoleAssignment{assign(danglingRoleID, subScope)},
			testPrincipal, actVaultRead, vaultScope, false, false},

		// 8. Case-insensitivity composes end to end.
		{"mixed case action and scope", []RoleAssignment{assign(ownerID, subScope)},
			testPrincipal, strings.ToUpper(actVaultWrite), strings.ToUpper(vaultScope), false, true},
	}

	for _, tc := range tests {
		checker := newTestChecker(t, tc.assignments...)
		got, err := checker.Check(tc.principal, tc.action, tc.scope, tc.isDataAction)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: Check(%q, %q, %q, %v) = %v, want %v",
				tc.name, tc.principal, tc.action, tc.scope, tc.isDataAction, got, tc.want)
		}
	}
}
