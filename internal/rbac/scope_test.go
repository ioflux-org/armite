package rbac

import "testing"

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercases", "/subscriptions/ABC/resourceGroups/Dev", "/subscriptions/abc/resourcegroups/dev"},
		{"trims trailing slash", "/subscriptions/abc/", "/subscriptions/abc"},
		{"root survives", "/", "/"},
		{"already canonical", "/subscriptions/abc", "/subscriptions/abc"},
	}
	for _, tc := range tests {
		if got := normalizeScope(tc.in); got != tc.want {
			t.Errorf("%s: normalizeScope(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestScopeAtOrAbove(t *testing.T) {
	const (
		sub = "/subscriptions/abc"
		rg  = "/subscriptions/abc/resourcegroups/dev"
	)
	tests := []struct {
		name       string
		assignment string
		request    string
		want       bool
	}{
		{"equal scopes", rg, rg, true},
		{"subscription contains rg", sub, rg, true},
		{"rg does not contain subscription", rg, sub, false},
		{"segment boundary: dev vs dev2", rg, rg + "2", false},
		{"root contains everything", "/", rg, true},
		{"resource under rg", rg, rg + "/providers/microsoft.keyvault/vaults/kv1", true},
		{"sibling rg", rg, sub + "/resourcegroups/other", false},
	}
	for _, tc := range tests {
		if got := scopeAtOrAbove(tc.assignment, tc.request); got != tc.want {
			t.Errorf("%s: scopeAtOrAbove(%q, %q) = %v, want %v", tc.name, tc.assignment, tc.request, got, tc.want)
		}
	}
}
