package arm

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseResourceID(t *testing.T) {
	const rg = "/subscriptions/sub-1/resourceGroups/dev"

	// native and provider build the two shapes of expected ID; passing nil
	// for names is deliberate - splitPairs leaves Names nil for a collection,
	// and reflect.DeepEqual treats nil and []string{} as different.
	native := func(types, names []string) ResourceID {
		return ResourceID{Namespace: "Microsoft.Resources", Native: true, Types: types, Names: names}
	}
	provider := func(scope, ns string, types, names []string) ResourceID {
		return ResourceID{Scope: scope, Namespace: ns, Types: types, Names: names}
	}

	tests := []struct {
		name    string
		path    string
		want    ResourceID
		wantErr error
	}{
		{"resource group instance", rg, native([]string{"subscriptions", "resourceGroups"}, []string{"sub-1", "dev"}), nil},
		{"resource group collection", "/subscriptions/sub-1/resourceGroups", native([]string{"subscriptions", "resourceGroups"}, []string{"sub-1"}), nil},
		{"subscription list", "/subscriptions", native([]string{"subscriptions"}, nil), nil},
		{"generic resource listing", "/subscriptions/sub-1/resources", native([]string{"subscriptions", "resources"}, []string{"sub-1"}), nil},
		{"generic listing in a group", rg + "/resources", native([]string{"subscriptions", "resourceGroups", "resources"}, []string{"sub-1", "dev"}), nil}, {"az sends lowercase resourcegroups", "/subscriptions/sub-1/resourcegroups/dev", native([]string{"subscriptions", "resourceGroups"}, []string{"sub-1", "dev"}), nil},
		{"provider resource", rg + "/providers/Microsoft.KeyVault/vaults/kv1", provider(rg, "Microsoft.KeyVault", []string{"vaults"}, []string{"kv1"}), nil},
		{"nested child resource", rg + "/providers/Microsoft.KeyVault/vaults/kv1/secrets/db-pass", provider(rg, "Microsoft.KeyVault", []string{"vaults", "secrets"}, []string{"kv1", "db-pass"}), nil},
		{"singleton child", rg + "/providers/Microsoft.Storage/storageAccounts/sa1/blobServices/default", provider(rg, "Microsoft.Storage", []string{"storageAccounts", "blobServices"}, []string{"sa1", "default"}), nil},
		{"extension resource: LAST providers wins", rg + "/providers/Microsoft.KeyVault/vaults/kv1/providers/Microsoft.Authorization/roleAssignments/ra-1", provider(rg+"/providers/Microsoft.KeyVault/vaults/kv1", "Microsoft.Authorization", []string{"roleAssignments"}, []string{"ra-1"}), nil},
		{"tenant-level provider route", "/providers/Microsoft.Authorization/roleDefinitions/def-1", provider("", "Microsoft.Authorization", []string{"roleDefinitions"}, []string{"def-1"}), nil},
		{"trailing slash tolerated", rg + "/", native([]string{"subscriptions", "resourceGroups"}, []string{"sub-1", "dev"}), nil},
		{"PROVIDERS marker is case-insensitive", "/subscriptions/sub-1/PROVIDERS/Microsoft.KeyVault/vaults/kv1", provider("/subscriptions/sub-1", "Microsoft.KeyVault", []string{"vaults"}, []string{"kv1"}), nil},
		{"root path", "/", ResourceID{}, ErrInvalidPath},
		{"relative path", "subscriptions/sub-1", ResourceID{}, ErrInvalidPath},
		{"empty segment", "/subscriptions//dev", ResourceID{}, ErrInvalidPath},
		{"providers catalogue", "/subscriptions/sub-1/providers",
			native([]string{"subscriptions", "providers"}, []string{"sub-1"}), nil},
		{"one provider", "/subscriptions/sub-1/providers/Microsoft.KeyVault",
			native([]string{"subscriptions", "providers"}, []string{"sub-1", "Microsoft.KeyVault"}), nil},
		{"namespace without a dot", rg + "/providers/keyvault/vaults/kv1", ResourceID{}, ErrInvalidPath},
		{"unknown native route", "/blobs/b1", ResourceID{}, ErrInvalidPath},
		{"excess native segments", rg + "/deployments/d1", ResourceID{}, ErrInvalidPath},
		{"group named providers", "/subscriptions/sub-1/resourceGroups/providers",
			native([]string{"subscriptions", "resourceGroups"}, []string{"sub-1", "providers"}), nil},
	}
	for _, tc := range tests {
		got, err := ParseResourceID(tc.path)
		if tc.wantErr != nil {
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("%s: ParseResourceID(%q) error = %v, wantErr %v", tc.name, tc.path, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: ParseResourceID(%q) unexpected error: %v", tc.name, tc.path, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: ParseResourceID(%q) = %+v, want %+v", tc.name, tc.path, got, tc.want)
		}
	}

}

func TestResourceIDString(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"native id round-trips", "/subscriptions/sub-1/resourceGroups/dev", "/subscriptions/sub-1/resourceGroups/dev"},
		{"lowercase native types come back canonical", "/subscriptions/sub-1/resourcegroups/dev", "/subscriptions/sub-1/resourceGroups/dev"},
		{"trailing slash dropped", "/subscriptions/sub-1/", "/subscriptions/sub-1"},
		{"provider id round-trips", "/subscriptions/sub-1/resourceGroups/dev/providers/Microsoft.KeyVault/vaults/kv1", "/subscriptions/sub-1/resourceGroups/dev/providers/Microsoft.KeyVault/vaults/kv1"},
		{"collection id keeps unpaired type", "/subscriptions/sub-1/resourceGroups/dev/providers/Microsoft.KeyVault/vaults", "/subscriptions/sub-1/resourceGroups/dev/providers/Microsoft.KeyVault/vaults"},
	}
	for _, tc := range tests {
		id, err := ParseResourceID(tc.path)
		if err != nil {
			t.Errorf("%s: ParseResourceID(%q) unexpected error: %v", tc.name, tc.path, err)
			continue
		}
		if got := id.String(); got != tc.want {
			t.Errorf("%s: String() = %q, want %q", tc.name, got, tc.want)
		}

	}
}
