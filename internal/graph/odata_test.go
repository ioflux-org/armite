package graph

import (
	"testing"

	"github.com/ioflux-org/armite/internal/directory"
)

func TestFilterSubset(t *testing.T) {
	sp := directory.Object{Kind: directory.KindServicePrincipal, ID: "4444", AppID: "3333",
		DisplayName: "Capture-SP", AccountEnabled: true}
	grp := directory.Object{Kind: directory.KindGroup, DisplayName: "capture-group", MailNickname: "capturegroup"}
	tests := []struct {
		filter string
		obj    directory.Object
		want   bool
	}{
		{"displayName eq 'capture-sp'", sp, true}, // case-insensitive
		{"displayName eq 'other'", sp, false},
		{"appId eq '3333'", sp, true},
		{"startswith(displayName,'cap')", sp, true},
		{"startswith(displayName, 'zzz')", sp, false},
		{"servicePrincipalNames/any(c:c eq '3333')", sp, true},
		{"servicePrincipalNames/any(c:c eq 'nope')", sp, false},
		{"displayName eq 'capture-group' and mailNickname eq 'capturegroup'", grp, true},
		{"displayName eq 'capture-group' and mailNickname eq 'other'", grp, false},
		{"accountEnabled eq true", sp, true},
		{"displayName eq 'it''s'", directory.Object{DisplayName: "it's"}, true},
	}
	for _, tc := range tests {
		keep, err := parseFilter(tc.filter)
		if err != nil {
			t.Errorf("%s: %v", tc.filter, err)
			continue
		}
		if got := keep(tc.obj); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.filter, got, tc.want)
		}
	}
	if keep, err := parseFilter(""); keep != nil || err != nil {
		t.Errorf("empty filter: %v %v, want nil, nil", keep, err)
	}
	for _, bad := range []string{"foo eq 'x'", "displayName gt 'x'", "displayName eq", "displayName eq 'open",
		"displayName eq 'a' or appId eq 'b'", "servicePrincipalNames/all(c:c eq 'x')", "accountEnabled eq 'yes'"} {
		if _, err := parseFilter(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
