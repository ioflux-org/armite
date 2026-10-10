package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Shared Key is the Storage service's own request signature: an HMAC
// over the method, a fixed list of standard headers, every x-ms-*
// header and the canonicalized resource, keyed by the account key.
// Armite signs the requests it forwards on a client's behalf after a
// bearer token was verified and authorized, so Azurite - which trusts
// only keys - accepts them.

// stringToSign builds the Shared Key string for the Blob service (the
// 2009-09-19 format, still current). account is the storage account the
// request addresses; the URL path and query are canonicalized per the
// specification: the escaped path, then every query parameter, lowercase
// names, sorted, values sorted and comma-joined.
func stringToSign(r *http.Request, account string) string {
	h := func(name string) string { return r.Header.Get(name) }
	length := h("Content-Length")
	if length == "" && r.ContentLength > 0 {
		length = fmt.Sprint(r.ContentLength)
	}
	if length == "0" {
		length = "" // the 2015-02-21 rule: a zero length is signed as empty
	}
	date := h("Date")
	if h("x-ms-date") != "" {
		date = "" // x-ms-date takes over, and is signed among the x-ms headers
	}
	var b strings.Builder
	for _, s := range []string{r.Method, h("Content-Encoding"), h("Content-Language"), length,
		h("Content-MD5"), h("Content-Type"), date, h("If-Modified-Since"), h("If-Match"),
		h("If-None-Match"), h("If-Unmodified-Since"), h("Range")} {
		b.WriteString(s)
		b.WriteString("\n")
	}
	var names []string
	for name := range r.Header {
		if lower := strings.ToLower(name); strings.HasPrefix(lower, "x-ms-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		value := strings.TrimSpace(strings.Join(r.Header.Values(name), ","))
		b.WriteString(name + ":" + value + "\n")
	}
	b.WriteString("/" + account + r.URL.EscapedPath())
	params := map[string][]string{}
	for k, vals := range r.URL.Query() {
		k = strings.ToLower(k)
		params[k] = append(params[k], vals...)
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sort.Strings(params[k])
		b.WriteString("\n" + k + ":" + strings.Join(params[k], ","))
	}
	return b.String()
}

// signSharedKey sets the Authorization header of r for account with the
// decoded account key.
func signSharedKey(r *http.Request, account string, key []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(stringToSign(r, account)))
	r.Header.Set("Authorization",
		"SharedKey "+account+":"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
}
