package storage

import (
	"net/http"
	"net/url"
	"testing"
)

func TestParseOperation(t *testing.T) {
	tests := []struct {
		method, target string
		action         string
		data           bool
		container      string
	}{
		{"GET", "/?comp=list", actContainersRead, false, ""},
		{"GET", "/?restype=service&comp=properties", actServiceRead, false, ""},
		{"POST", "/?restype=service&comp=userdelegationkey", actDelegationKey, false, ""},
		{"PUT", "/cont?restype=container", actContainersWrite, false, "cont"},
		{"GET", "/cont?restype=container", actContainersRead, false, "cont"},
		{"PUT", "/cont?restype=container&comp=metadata", actContainersWrite, false, "cont"},
		{"DELETE", "/cont?restype=container", actContainersDelete, false, "cont"},
		{"GET", "/cont?restype=container&comp=list", actBlobsRead, true, "cont"},
		{"GET", "/cont/dir/a%20b.txt", actBlobsRead, true, "cont"},
		{"HEAD", "/cont/a.txt", actBlobsRead, true, "cont"},
		{"PUT", "/cont/a.txt", actBlobsWrite, true, "cont"},
		{"PUT", "/cont/a.txt?comp=block&blockid=AAA", actBlobsWrite, true, "cont"},
		{"PUT", "/cont/a.txt?comp=blocklist", actBlobsWrite, true, "cont"},
		{"PUT", "/cont/a.txt?comp=metadata", actBlobsWrite, true, "cont"},
		{"PUT", "/cont/a.txt?comp=appendblock", actBlobsWrite, true, "cont"},
		{"PUT", "/cont/a.txt?comp=tags", actBlobsTagsWrite, true, "cont"},
		{"GET", "/cont/a.txt?comp=tags", actBlobsTagsRead, true, "cont"},
		{"DELETE", "/cont/a.txt", actBlobsDelete, true, "cont"},
	}
	for _, tc := range tests {
		u, _ := url.Parse("https://acct.blob.localhost:8443" + tc.target)
		op, ok := parseOperation(tc.method, u)
		if !ok {
			t.Errorf("%s %s: not recognized", tc.method, tc.target)
			continue
		}
		if op.action != tc.action || op.data != tc.data || op.container != tc.container {
			t.Errorf("%s %s = %s data=%v container=%q, want %s data=%v container=%q",
				tc.method, tc.target, op.action, op.data, op.container,
				tc.action, tc.data, tc.container)
		}
	}
	for _, bad := range []string{"/?comp=batch", "/cont?restype=container&comp=batch",
		"/cont/a.txt?comp=immutabilitypolicies"} {
		u, _ := url.Parse("https://acct.blob.localhost:8443" + bad)
		if _, ok := parseOperation(http.MethodPost, u); ok {
			t.Errorf("POST %s must not be recognized", bad)
		}
	}
	u, _ := url.Parse("https://acct.blob.localhost:8443/cont/a.txt?comp=appendblock")
	if op, _ := parseOperation(http.MethodPut, u); op.alt != actBlobsAdd {
		t.Errorf("Append Block must also be permitted by %s, got alt %q", actBlobsAdd, op.alt)
	}
}
