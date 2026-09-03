package arm

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseResourceID(t *testing.T) {
	const rg = "subscriptions/sub-1/resourceGroups/rg-1"

	tests := []struct {
		name    string
		path    string
		want    ResourceID
		wantErr error
	}{}
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
