package rbac

import (
	"testing"
)

const (
	ownerID         = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	contributorID   = "b24988ac-6180-42a0-ab88-20f7382dd24c"
	readerID        = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	kvSecretsUserID = "4633458b-17de-408a-b874-0445c86b69e6"
)

func TestLoadBuiltinRoles(t *testing.T) {
	defs, err := LoadBuiltinRoles()
	if err != nil {
		t.Fatalf("LoadBuiltinRoles: %v", err)
	}
	if len(defs) != 934 {
		t.Fatalf("got %d role definitions, want 934", len(defs))
	}
	tests := []struct {
		guid           string
		roleName       string
		wantAction     string // must appear in Actions; "" means Actions must be empty
		wantDataAction string // same, for DataActions
	}{
		{ownerID, "Owner", "*", ""},
		{contributorID, "Contributor", "*", ""},
		{readerID, "Reader", "*/read", ""},
		{kvSecretsUserID, "Key Vault Secrets User", "", "Microsoft.KeyVault/vaults/secrets/getSecret/action"},
	}

	for _, tc := range tests {
		d, ok := defs[tc.guid]
		if !ok {
			t.Errorf("%s: GUID %s missing from index", tc.roleName, tc.guid)
			continue
		}
		if d.RoleName != tc.roleName {
			t.Errorf("%s: RoleName = %q", tc.guid, d.RoleName)
			continue
		}
		if len(d.Permissions) != 1 {
			t.Errorf("%s: %d permissions entries, want 1", tc.roleName, len(d.Permissions))
			continue
		}
		p := d.Permissions[0]
		if !containsOrEmpty(p.Actions, tc.wantAction) {
			t.Errorf("%s: Actions = %v, want %q", tc.roleName, p.Actions, tc.wantAction)
		}
		if !containsOrEmpty(p.DataActions, tc.wantDataAction) {
			t.Errorf("%s: DataActions = %v, want %q", tc.roleName, p.DataActions, tc.wantDataAction)
		}
	}
}

func TestContributorCannotGrantRBAC(t *testing.T) {
	defs, err := LoadBuiltinRoles()
	if err != nil {
		t.Fatalf("LoadBuiltinRoles: %v", err)
	}
	notActions := defs[contributorID].Permissions[0].NotActions
	for _, want := range []string{
		"Microsoft.Authorization/*/Write",
		"Microsoft.Authorization/*/Delete",
	} {
		if !containsOrEmpty(notActions, want) {
			t.Errorf("Contributor NotActions missing %q (got %v)", want, notActions)
		}
	}
}

// containsOrEmpty reports whether list contains want, or - when want is
// "" - whether list is empty.
func containsOrEmpty(list []string, want string) bool {
	if want == "" {
		return len(list) == 0
	}
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
