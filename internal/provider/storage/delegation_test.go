package storage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
)

const (
	blobDataReaderRole = "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1"
	keyRequest         = "/?restype=service&comp=userdelegationkey"
)

type delegationKey struct {
	SignedOid     string `xml:"SignedOid"`
	SignedTid     string `xml:"SignedTid"`
	SignedStart   string `xml:"SignedStart"`
	SignedExpiry  string `xml:"SignedExpiry"`
	SignedService string `xml:"SignedService"`
	SignedVersion string `xml:"SignedVersion"`
	Value         string `xml:"Value"`
}

// getKey asks the data plane for a user delegation key as the client.
func getKey(t *testing.T, h http.Handler, tok, expiry string) delegationKey {
	t.Helper()
	body := "<KeyInfo><Start>2026-10-02T10:00:00Z</Start><Expiry>" + expiry + "</Expiry></KeyInfo>"
	rec := dp(t, h, http.MethodPost, accountHost, keyRequest, tok, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("get user delegation key: %d %s", rec.Code, rec.Body.String())
	}
	var k delegationKey
	if err := xml.Unmarshal(rec.Body.Bytes(), &k); err != nil {
		t.Fatalf("key is not XML: %v\n%s", err, rec.Body.String())
	}
	return k
}

// udSAS signs a user delegation SAS the way the SDKs do for the newest
// layout (2026-04-06 and later): the fields in order, joined by newlines,
// HMAC-SHA256 with the key's value.
func udSAS(k delegationKey, account, container, blob, perms, expiry string) string {
	sv := "2026-10-06"
	resource := "c"
	canonical := "/blob/" + account + "/" + container
	if blob != "" {
		resource = "b"
		canonical += "/" + blob
	}
	fields := []string{perms, "", expiry, canonical, k.SignedOid, k.SignedTid, k.SignedStart,
		k.SignedExpiry, k.SignedService, k.SignedVersion, "", "", "", "", "", "", "", sv, resource,
		"", "", "", "", "", "", "", "", ""}
	key, _ := base64.StdEncoding.DecodeString(k.Value)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Join(fields, "\n")))
	q := url.Values{"sv": {sv}, "se": {expiry}, "sp": {perms}, "sr": {resource},
		"skoid": {k.SignedOid}, "sktid": {k.SignedTid}, "skt": {k.SignedStart},
		"ske": {k.SignedExpiry}, "sks": {k.SignedService}, "skv": {k.SignedVersion},
		"sig": {base64.StdEncoding.EncodeToString(mac.Sum(nil))}}
	return q.Encode()
}

func TestUserDelegationKey(t *testing.T) {
	h, _, _ := storagePlane(t, &recordingAzurite{})
	cfg := config.Default()
	tok := "Bearer " + mintClientToken(t, cfg, config.StorageAudience+"/.default")
	expiry := time.Now().UTC().Add(time.Hour).Format(sasTimeLayout)

	k := getKey(t, h, tok, expiry)
	if k.SignedOid != cfg.Clients[0].ObjectID || k.SignedTid != cfg.TenantID ||
		k.SignedService != "b" || k.SignedVersion != "2025-07-05" || k.SignedExpiry != expiry {
		t.Errorf("key = %+v", k)
	}
	if raw, err := base64.StdEncoding.DecodeString(k.Value); err != nil || len(raw) != 32 {
		t.Errorf("key value must be 32 base64 bytes: %q %v", k.Value, err)
	}
	if again := getKey(t, h, tok, expiry); again.Value != k.Value {
		t.Error("the same window must yield the same key: nothing is stored, it is derived")
	}
	later := time.Now().UTC().Add(2 * time.Hour).Format(sasTimeLayout)
	if other := getKey(t, h, tok, later); other.Value == k.Value {
		t.Error("a different window must yield a different key")
	}
	tooLong := time.Now().UTC().Add(8 * 24 * time.Hour).Format(sasTimeLayout)
	body := "<KeyInfo><Expiry>" + tooLong + "</Expiry></KeyInfo>"
	if rec := dp(t, h, http.MethodPost, accountHost, keyRequest, tok, body); rec.Code != 400 {
		t.Errorf("an 8-day key: %d, want 400", rec.Code)
	}
	if rec := dp(t, h, http.MethodPost, accountHost, keyRequest, "", body); rec.Code != 401 {
		t.Errorf("a key without a token: %d, want 401", rec.Code)
	}
}

func TestUserDelegationSAS(t *testing.T) {
	fake := &recordingAzurite{}
	h, p, _ := storagePlane(t, fake, grant(blobDataReaderRole, rg+accounts+"/stdemo"))
	tok := "Bearer " + mintClientToken(t, config.Default(), config.StorageAudience+"/.default")
	expiry := time.Now().UTC().Add(time.Hour).Format(sasTimeLayout)
	k := getKey(t, h, tok, expiry)

	// A blob SAS with r: read forwarded as the account, SAS parameters gone.
	sas := udSAS(k, "stdemo", "demo", "hello.txt", "r", expiry)
	rec := dp(t, h, http.MethodGet, accountHost, "/demo/hello.txt?"+sas, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("read with a UD SAS: %d %s", rec.Code, rec.Body.String())
	}
	up := fake.last(t)
	if !strings.HasPrefix(up.Header.Get("Authorization"), "SharedKey stdemo:") ||
		up.URL.RawQuery != "" {
		t.Errorf("forwarded Authorization=%q query=%q", up.Header.Get("Authorization"),
			up.URL.RawQuery)
	}
	calls := len(fake.calls)

	expired := udSAS(k, "stdemo", "demo", "hello.txt", "r", "2026-10-02T11:00:00Z")
	refused := []struct{ name, method, target, code string }{
		{"write with a read SAS", http.MethodPut, "/demo/hello.txt?" + sas, errPermissionMismatch},
		{"another blob", http.MethodGet, "/demo/other.txt?" + sas, "AuthenticationFailed"},
		{"tampered signature", http.MethodGet, "/demo/hello.txt?" + sas + "x",
			"AuthenticationFailed"},
		{"expired", http.MethodGet, "/demo/hello.txt?" + expired, "AuthenticationFailed"},
		{"container op with a blob SAS", http.MethodGet,
			"/demo?restype=container&comp=list&" + sas, "AuthorizationResourceTypeMismatch"},
	}
	for _, tc := range refused {
		rec := dp(t, h, tc.method, accountHost, tc.target, "", "x")
		if rec.Code != http.StatusForbidden || storageCode(rec) != tc.code {
			t.Errorf("%s: %d %s, want 403 %s", tc.name, rec.Code, storageCode(rec), tc.code)
		}
	}
	if len(fake.calls) != calls {
		t.Error("refused SAS requests must not reach the upstream")
	}

	// A container SAS with rl covers listing and every blob under it.
	csas := udSAS(k, "stdemo", "demo", "", "rl", expiry)
	covered := []string{"/demo?restype=container&comp=list&" + csas, "/demo/any.txt?" + csas}
	for _, target := range covered {
		rec := dp(t, h, http.MethodGet, accountHost, target, "", "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s with a container SAS: %d %s", target, rec.Code, rec.Body.String())
		}
	}

	// The SAS is bounded by the delegating principal's RBAC, at use time:
	// a write SAS from a Reader cannot write.
	wsas := udSAS(k, "stdemo", "demo", "hello.txt", "cw", expiry)
	rec = dp(t, h, http.MethodPut, accountHost, "/demo/hello.txt?"+wsas, "", "x")
	if rec.Code != http.StatusForbidden || storageCode(rec) != errPermissionMismatch ||
		!strings.Contains(rec.Body.String(), "Caller: oid="+k.SignedOid) {
		t.Errorf("write SAS from a Reader: %d %s\n%s", rec.Code, storageCode(rec),
			rec.Body.String())
	}
	// Key access disallowed on the account: a UD SAS is not key access.
	serve(t, p, http.MethodPatch, rg+accounts+"/stdemo",
		`{"properties":{"allowSharedKeyAccess":false}}`)
	rec = dp(t, h, http.MethodGet, accountHost, "/demo/hello.txt?"+sas, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("UD SAS with key access disallowed: %d, want 200", rec.Code)
	}
}
