package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// upstream is the Azurite the provider forwards to. Requests are sent
// host-style - the account is the first label of the Host header, which
// is how Azurite tells accounts apart - and signed with the account's
// key, the only credential Azurite trusts.
type upstream struct {
	base   *url.URL
	client *http.Client
	keys   func(account string) ([]byte, bool)
}

func newUpstream(rawurl string, keys func(account string) ([]byte, bool)) (*upstream, error) {
	base, err := url.Parse(rawurl)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("storage: upstream %q is not a URL", rawurl)
	}
	return &upstream{base: base, client: &http.Client{Timeout: 60 * time.Second}, keys: keys}, nil
}

// hostFor is the Host header that makes Azurite serve account.
func hostFor(account string) string {
	return account + ".blob.localhost"
}

// request builds a signed request to account's blob service: path is
// the container/blob path with its query ("/c?restype=container").
func (u *upstream) request(ctx context.Context, account, method, path string,
	headers http.Header, body io.Reader, length int64) (*http.Request, error) {
	key, ok := u.keys(account)
	if !ok {
		return nil, fmt.Errorf("storage: no key for account %s", account)
	}
	target := *u.base
	ref, err := url.Parse(path)
	if err != nil {
		return nil, err
	}
	target.Path, target.RawPath, target.RawQuery = ref.Path, ref.RawPath, ref.RawQuery
	r, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	r.ContentLength = length
	r.Host = hostFor(account)
	for name, vals := range headers {
		r.Header[name] = vals
	}
	if r.Header.Get("x-ms-date") == "" {
		r.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	}
	if r.Header.Get("x-ms-version") == "" {
		r.Header.Set("x-ms-version", apiVersion)
	}
	if length > 0 {
		r.Header.Set("Content-Length", fmt.Sprint(length))
	}
	signSharedKey(r, account, key)
	return r, nil
}

// do performs a signed request and returns the response; the caller
// closes the body.
func (u *upstream) do(ctx context.Context, account, method, path string,
	headers http.Header, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	r, err := u.request(ctx, account, method, path, headers, rd, int64(len(body)))
	if err != nil {
		return nil, err
	}
	return u.client.Do(r)
}

// apiVersion is the x-ms-version the provider itself speaks upstream.
const apiVersion = "2025-07-05"

func decodeKey(b64 string) ([]byte, bool) {
	key, err := base64.StdEncoding.DecodeString(b64)
	return key, err == nil
}
