package rbac

import "testing"

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		action  string
		want    bool
	}{
		// no wildcard: exact match only
		{"exact match", "Microsoft.KeyVault/vaults/read", "Microsoft.KeyVault/vaults/read", true},
		{"exact match ignores case", "microsoft.keyvault/VAULTS/read", "Microsoft.KeyVault/vaults/READ", true},
		{"no implicit prefix", "Microsoft.KeyVault/vaults", "Microsoft.KeyVault/vaults/read", false},
		{"empty pattern, empty action", "", "", true},
		{"empty pattern, non-empty action", "", "Microsoft.KeyVault/vaults/read", false},

		// bare star
		{"star matches anything", "*", "Microsoft.Compute/virtualMachines/write", true},
		{"star matches empty", "*", "", true},

		// leading star spans slashes
		{"*/read matches deep read", "*/read", "Microsoft.Compute/virtualMachines/read", true},
		{"*/read rejects write", "*/read", "Microsoft.Compute/virtualMachines/write", false},
		{"*/read rejects action verb", "*/read", "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action", false},

		// middle star
		{"middle star", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/Write", true},
		{"middle star rejects wrong verb", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/roleAssignments/Delete", false},
		{"middle star spans nesting", "Microsoft.Authorization/*/Write", "Microsoft.Authorization/policies/nested/Write", true},

		// trailing star
		{"trailing star", "Microsoft.Storage/*", "Microsoft.Storage/storageAccounts/blobServices/containers/read", true},
		{"prefix includes the slash", "Microsoft.Storage/*", "Microsoft.StorageCache/caches/read", false},
		{"trailing star matches empty", "foo*", "foo", true},

		// case-insensitivity with wildcards
		{"wildcard ignores case", "microsoft.authorization/*/write", "Microsoft.Authorization/roleAssignments/Write", true},

		// multiple stars
		{"middle between stars", "a*b*c", "axxbxxc", true},
		{"missing middle", "a*b*c", "axxc", false},
		{"stars match empty runs", "a*b*c", "abc", true},
		{"middle may not double as suffix", "a*b*b", "ab", false},
	}

	for _, tc := range tests {
		if got := matchPattern(tc.pattern, tc.action); got != tc.want {
			t.Errorf("%s: matchPattern(%q, %q) = %v, want %v", tc.name, tc.pattern, tc.action, got, tc.want)
		}
	}
}
