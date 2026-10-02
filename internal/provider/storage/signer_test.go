package storage

import (
	"net/http"
	"strings"
	"testing"
)

// The reference example from the Shared Key documentation, reduced to
// what the function sees: a GET of a container listing with an
// x-ms-date and a version header.
func TestStringToSign(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet,
		"https://myaccount.blob.core.windows.net/mycontainer?restype=container&comp=metadata", nil)
	r.Header.Set("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT")
	r.Header.Set("x-ms-version", "2015-02-21")
	got := stringToSign(r, "myaccount")
	want := "GET\n\n\n\n\n\n\n\n\n\n\n\n" +
		"x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n" +
		"/myaccount/mycontainer\ncomp:metadata\nrestype:container"
	if got != want {
		t.Errorf("stringToSign =\n%q\nwant\n%q", got, want)
	}
}

func TestStringToSignBodyAndQueryRules(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPut,
		"https://a.blob.localhost:8443/c/hello%20world.txt?Comp=block&blockid=b&blockid=a",
		strings.NewReader("hi"))
	r.Header.Set("Content-Length", "2")
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("Date", "ignored when x-ms-date is set")
	r.Header.Set("X-MS-Date", "Fri, 26 Jun 2015 23:39:12 GMT")
	got := stringToSign(r, "a")
	for _, want := range []string{"PUT\n\n\n2\n\ntext/plain\n\n", "x-ms-date:Fri",
		"/a/c/hello%20world.txt\nblockid:a,b\ncomp:block"} {
		if !strings.Contains(got, want) {
			t.Errorf("stringToSign lacks %q:\n%q", want, got)
		}
	}
	r.Header.Set("Content-Length", "0")
	if !strings.HasPrefix(stringToSign(r, "a"), "PUT\n\n\n\n\n") {
		t.Error("a zero Content-Length must be signed as empty")
	}
}

func TestSignSharedKeySetsHeader(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "https://a.blob.localhost:8443/?comp=list", nil)
	signSharedKey(r, "a", []byte("0123456789abcdef0123456789abcdef"))
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "SharedKey a:") || len(auth) < len("SharedKey a:")+44 {
		t.Errorf("Authorization = %q", auth)
	}
}
