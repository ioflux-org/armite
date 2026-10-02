package arm

import (
	"errors"
	"net/http"
	"testing"

	"github.com/ioflux-org/provisio/internal/rbac"
)

// mustParse fails the test immediately on a path the table meant to be valid.
func mustParse(t *testing.T, path string) ResourceID {
	t.Helper()
	id, err := ParseResourceID(path)
	if err != nil {
		t.Fatalf("ParseResourceID(%q) unexpected error: %v", path, err)
	}
	return id
}

func TestDeriveAction(t *testing.T) {
	const (
		rg    = "/subscriptions/sub-1/resourceGroups/dev"
		vault = rg + "/providers/Microsoft.KeyVault/vaults/kv1"
	)
	tests := []struct {
		name       string
		method     string
		path       string
		wantAction string
		wantScope  string
		wantErr    error
	}{
		{"read resource group", http.MethodGet, rg, "Microsoft.Resources/subscriptions/resourceGroups/read", rg, nil},
		{"list groups: same action, parent scope", http.MethodGet, "/subscriptions/sub-1/resourceGroups", "Microsoft.Resources/subscriptions/resourceGroups/read", "/subscriptions/sub-1", nil},
		{"list resources: read at the subscription", http.MethodGet, "/subscriptions/sub-1/resources", "Microsoft.Resources/subscriptions/resources/read", "/subscriptions/sub-1", nil},
		{"create resource group", http.MethodPut, rg, "Microsoft.Resources/subscriptions/resourceGroups/write", rg, nil},
		{"delete resource group", http.MethodDelete, rg, "Microsoft.Resources/subscriptions/resourceGroups/delete", rg, nil},
		{"head is read", http.MethodHead, rg, "Microsoft.Resources/subscriptions/resourceGroups/read", rg, nil},
		{"list vaults in group", http.MethodGet, rg + "/providers/Microsoft.KeyVault/vaults", "Microsoft.KeyVault/vaults/read", rg, nil},
		{"action name rides the type slot", http.MethodPost, vault + "/listKeys", "Microsoft.KeyVault/vaults/listKeys/action", vault, nil},
		{"action at subscription scope", http.MethodPost, "/subscriptions/sub-1/providers/Microsoft.KeyVault/checkNameAvailability", "Microsoft.KeyVault/checkNameAvailability/action", "/subscriptions/sub-1", nil},
		{"role assignment write on a vault", http.MethodPut, vault + "/providers/Microsoft.Authorization/roleAssignments/ra-1", "Microsoft.Authorization/roleAssignments/write", vault + "/providers/Microsoft.Authorization/roleAssignments/ra-1", nil},
		{"list subscriptions at root", http.MethodGet, "/subscriptions", "Microsoft.Resources/subscriptions/read", "/", nil},
		{"put needs a name", http.MethodPut, "/subscriptions/sub-1/resourceGroups", "", "", ErrInvalidPath},
		{"delete needs a name", http.MethodDelete, rg + "/providers/Microsoft.KeyVault/vaults", "", "", ErrInvalidPath},
		{"post needs an action name", http.MethodPost, vault, "", "", ErrInvalidPath},
		{"options has no verb semantics", http.MethodOptions, rg, "", "", ErrUnsupportedMethod},
	}
	for _, tc := range tests {
		action, scope, err := DeriveAction(tc.method, mustParse(t, tc.path))
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: DeriveAction(%s, %q) error = %v, wantErr %v", tc.name, tc.method, tc.path, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: DeriveAction(%s, %q) unexpected error: %v", tc.name, tc.method, tc.path, err)
			continue
		}
		if action != tc.wantAction || scope != tc.wantScope {
			t.Errorf("%s: DeriveAction(%s, %q) = (%q, %q), want (%q, %q)", tc.name, tc.method, tc.path, action, scope, tc.wantAction, tc.wantScope)
		}
	}
}

// TestDeriveActionFeedsCheck proves the M3a<->M2 contract end to end: what
// DeriveAction produces is exactly what Checker.Check consumes, with no
// adapter in between. A hand-built wildcard role stands in for Owner so
// the test exercises plumbing, not seed data.
func TestDeriveActionFeedsCheck(t *testing.T) {
	defs := map[string]rbac.RoleDefinition{
		"role-1": {Permissions: []rbac.Permission{{Actions: []string{"*"}}}},
	}
	store := rbac.NewAssignmentStore(nil)
	if err := store.Add(rbac.RoleAssignment{PrincipalID: "user-1", RoleDefinitionID: "role-1", Scope: "/subscriptions/sub-1"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	checker := rbac.NewChecker(defs, store)

	action, scope, err := DeriveAction(http.MethodPut, mustParse(t, "/subscriptions/sub-1/resourceGroups/dev"))
	if err != nil {
		t.Fatalf("DeriveAction: %v", err)
	}
	allowed, err := checker.Check("user-1", action, scope, false)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Errorf("Check(%q, %q) = false, want true: subscription-scoped wildcard must cover a group write", action, scope)
	}
}
