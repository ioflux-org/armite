package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/rbac"
)

const (
	blobDataContributorRole = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
	readerRole              = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	accountHost             = "stdemo.blob.core.localhost:8443"
)

var (
	testKey     = mustKey()
	builtinDefs = mustDefs()
)

func mustKey() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func mustDefs() map[string]rbac.RoleDefinition {
	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		panic(err)
	}
	return defs
}

// mintClientToken gets a token for the configured client from the real
// entra handler, for any scope - the storage audience included.
func mintClientToken(t *testing.T, cfg config.Config, scope string) string {
	t.Helper()
	cl := cfg.Clients[0]
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID},
		"client_secret": {cl.Secret}, "scope": {scope}}
	req := httptest.NewRequest(http.MethodPost, "/"+cfg.TenantID+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	entra.New(cfg, testKey).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token endpoint: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.AccessToken
}

// recordingAzurite answers every request with 200 and remembers what it
// was asked, so the test can see exactly what the proxy forwarded.
type recordingAzurite struct {
	calls []*http.Request
}

func (f *recordingAzurite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body.Close()
	f.calls = append(f.calls, r)
	w.Header().Set("x-ms-request-id", "upstream")
	w.Write([]byte("ok"))
}

func (f *recordingAzurite) last(t *testing.T) *http.Request {
	t.Helper()
	if len(f.calls) == 0 {
		t.Fatal("nothing reached the upstream")
	}
	return f.calls[len(f.calls)-1]
}

// storagePlane returns the data plane over a provider whose upstream is
// the recording fake, with the account stdemo created, the default
// seeds (the client is Owner of the subscription) plus grants.
func storagePlane(t *testing.T, fake *recordingAzurite,
	grants ...rbac.RoleAssignment) (http.Handler, *Provider, string) {
	t.Helper()
	ts := httptest.NewServer(fake)
	t.Cleanup(ts.Close)
	cfg := config.Default()
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 64)))
	cfg.Azurite = config.Azurite{Mode: "byo", Upstream: ts.URL,
		Accounts: []config.StorageAccount{{Name: "stdemo", Key: key}}}
	p := newProvider(t, cfg)
	rec := serve(t, p, http.MethodPut, rg+accounts+"/stdemo", azBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("create account: %d %s", rec.Code, rec.Body.String())
	}
	as := rbac.NewAssignmentStore(nil)
	all := append(gateway.SeedAssignments(cfg), grants...)
	if err := rbac.Seed(as, builtinDefs, all); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	h := p.DataPlane(&testKey.PublicKey, time.Now, rbac.NewChecker(builtinDefs, as))
	return h, p, key
}

func dp(t *testing.T, h http.Handler, method, host, target, auth, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://"+host+target, rd)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("x-ms-version", "2025-07-05")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func storageCode(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("x-ms-error-code")
}

func grant(role, scope string) rbac.RoleAssignment {
	return rbac.RoleAssignment{PrincipalID: config.Default().Clients[0].ObjectID,
		RoleDefinitionID: role, Scope: scope}
}

// Owner holds every management action and no data action: it can make
// a container and list them, and cannot touch a blob. That split is
// Azure's own, and the reason "but I'm Owner" happens on blobs too.
func TestOwnerCreatesContainersButCannotTouchBlobs(t *testing.T) {
	fake := &recordingAzurite{}
	h, _, _ := storagePlane(t, fake)
	tok := "Bearer " + mintClientToken(t, config.Default(), config.StorageAudience+"/.default")

	rec := dp(t, h, http.MethodPut, accountHost, "/cont?restype=container", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("create container as Owner: %d %s", rec.Code, rec.Body.String())
	}
	up := fake.last(t)
	if up.Host != "stdemo.blob.localhost" || up.URL.RequestURI() != "/cont?restype=container" ||
		!strings.HasPrefix(up.Header.Get("Authorization"), "SharedKey stdemo:") {
		t.Errorf("forwarded as %s %s Host=%s Authorization=%q", up.Method, up.URL.RequestURI(),
			up.Host, up.Header.Get("Authorization"))
	}
	rec = dp(t, h, http.MethodGet, accountHost, "/?comp=list", tok, "")
	if rec.Code != http.StatusOK {
		t.Errorf("list containers as Owner: %d", rec.Code)
	}

	calls := len(fake.calls)
	for _, tc := range []struct{ method, target string }{
		{http.MethodPut, "/cont/hello.txt"},
		{http.MethodGet, "/cont/hello.txt"},
		{http.MethodGet, "/cont?restype=container&comp=list"},
		{http.MethodDelete, "/cont/hello.txt"},
	} {
		rec = dp(t, h, tc.method, accountHost, tc.target, tok, "x")
		if rec.Code != http.StatusForbidden || storageCode(rec) != errPermissionMismatch {
			t.Errorf("%s %s as Owner: %d %s, want 403 %s", tc.method, tc.target, rec.Code,
				storageCode(rec), errPermissionMismatch)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "<Code>AuthorizationPermissionMismatch</Code>") ||
			!strings.Contains(body, "Action: 'Microsoft.Storage/storageAccounts/blobServices/") {
			t.Errorf("403 body must carry Azure's code and name the action:\n%s", body)
		}
	}
	if len(fake.calls) != calls {
		t.Error("a refused request must never reach the upstream")
	}
}

func TestBlobDataContributorIsReSigned(t *testing.T) {
	fake := &recordingAzurite{}
	h, _, _ := storagePlane(t, fake, grant(blobDataContributorRole, rg+accounts+"/stdemo"))
	tok := "Bearer " + mintClientToken(t, config.Default(), config.StorageAudience+"/.default")

	rec := dp(t, h, http.MethodPut, accountHost, "/cont/hello%20world.txt", tok, "hello")
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("put blob: %d %s", rec.Code, rec.Body.String())
	}
	up := fake.last(t)
	if up.Host != "stdemo.blob.localhost" || up.URL.EscapedPath() != "/cont/hello%20world.txt" ||
		strings.HasPrefix(up.Header.Get("Authorization"), "Bearer") ||
		!strings.HasPrefix(up.Header.Get("Authorization"), "SharedKey stdemo:") ||
		up.Header.Get("x-ms-version") != "2025-07-05" {
		t.Errorf("forwarded Host=%s path=%s Authorization=%q version=%q", up.Host,
			up.URL.EscapedPath(), up.Header.Get("Authorization"), up.Header.Get("x-ms-version"))
	}
	if rec.Header().Get("x-ms-request-id") != "upstream" {
		t.Error("the upstream's response headers must be relayed")
	}
	// Reader has */read: containers yes, blobs no.
	h2, _, _ := storagePlane(t, &recordingAzurite{}, grant(readerRole, rg+accounts+"/stdemo"))
	rec = dp(t, h2, http.MethodGet, accountHost, "/cont?restype=container", tok, "")
	if rec.Code != http.StatusOK {
		t.Errorf("Reader reads container properties: %d", rec.Code)
	}
	rec = dp(t, h2, http.MethodGet, accountHost, "/cont/hello.txt", tok, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("Reader reading a blob: %d, want 403", rec.Code)
	}
}

func TestKeyAndSASPassThrough(t *testing.T) {
	fake := &recordingAzurite{}
	h, p, _ := storagePlane(t, fake)

	const signed = "SharedKey stdemo:c2ln"
	rec := dp(t, h, http.MethodGet, accountHost, "/cont/hello.txt", signed, "")
	if rec.Code != http.StatusOK || fake.last(t).Header.Get("Authorization") != signed {
		t.Errorf("Shared Key must pass through untouched: %d %q", rec.Code,
			fake.last(t).Header.Get("Authorization"))
	}
	rec = dp(t, h, http.MethodGet, accountHost, "/cont/hello.txt?sv=2025-07-05&sp=r&sig=abc",
		"", "")
	if rec.Code != http.StatusOK || !strings.Contains(fake.last(t).URL.RawQuery, "sig=abc") {
		t.Errorf("a SAS must pass through untouched: %d %q", rec.Code, fake.last(t).URL.RawQuery)
	}

	// allowSharedKeyAccess=false: keys and account SAS refused here, bearer unaffected.
	rec = serve(t, p, http.MethodPatch, rg+accounts+"/stdemo",
		`{"properties":{"allowSharedKeyAccess":false}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d", rec.Code)
	}
	calls := len(fake.calls)
	rec = dp(t, h, http.MethodGet, accountHost, "/cont/hello.txt", "SharedKey stdemo:c2ln", "")
	if rec.Code != http.StatusForbidden || storageCode(rec) != errKeyAuthNotPermitted {
		t.Errorf("key auth when disallowed: %d %s", rec.Code, storageCode(rec))
	}
	rec = dp(t, h, http.MethodGet, accountHost, "/cont/hello.txt?sp=r&sig=abc", "", "")
	if rec.Code != http.StatusForbidden || storageCode(rec) != errKeyAuthNotPermitted {
		t.Errorf("SAS when key auth is disallowed: %d %s", rec.Code, storageCode(rec))
	}
	if len(fake.calls) != calls {
		t.Error("refused key requests must not reach the upstream")
	}
	tok := "Bearer " + mintClientToken(t, config.Default(), config.StorageAudience+"/.default")
	if rec := dp(t, h, http.MethodGet, accountHost, "/?comp=list", tok, ""); rec.Code != 200 {
		t.Errorf("bearer with key auth disallowed: %d, want 200", rec.Code)
	}
}

func TestDataPlaneRefusals(t *testing.T) {
	fake := &recordingAzurite{}
	h, _, _ := storagePlane(t, fake)
	cfg := config.Default()
	tok := "Bearer " + mintClientToken(t, cfg, config.StorageAudience+"/.default")
	armTok := "Bearer " + mintClientToken(t, cfg, "https://management.azure.com/.default")

	rec := dp(t, h, http.MethodGet, accountHost, "/cont/hello.txt", "", "")
	challenge := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusUnauthorized || storageCode(rec) != errNoAuthentication ||
		!strings.Contains(challenge, "resource_id="+config.StorageAudience) {
		t.Errorf("anonymous: %d %s %q", rec.Code, storageCode(rec), challenge)
	}
	rec = dp(t, h, http.MethodGet, accountHost, "/?comp=list", armTok, "")
	if rec.Code != http.StatusUnauthorized || storageCode(rec) != errInvalidAuthentication {
		t.Errorf("ARM-audience token: %d %s, want 401", rec.Code, storageCode(rec))
	}
	rec = dp(t, h, http.MethodGet, "nope.blob.core.localhost:8443", "/?comp=list", tok, "")
	if rec.Code != http.StatusNotFound || storageCode(rec) != errResourceNotFound {
		t.Errorf("unknown account: %d %s", rec.Code, storageCode(rec))
	}
	rec = dp(t, h, http.MethodPost, accountHost, "/?comp=batch", tok, "")
	if rec.Code != http.StatusBadRequest || storageCode(rec) != errUnsupported {
		t.Errorf("unsupported operation: %d %s", rec.Code, storageCode(rec))
	}
	if len(fake.calls) != 0 {
		t.Error("nothing refused may reach the upstream")
	}

	// The queue and table hosts answer the one probe Terraform makes.
	rec = dp(t, h, http.MethodGet, "stdemo.queue.core.localhost:8443",
		"/?restype=service&comp=properties", tok, "")
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "<StorageServiceProperties>") {
		t.Errorf("queue probe: %d %s", rec.Code, rec.Body.String())
	}
	rec = dp(t, h, http.MethodPut, "stdemo.table.core.localhost:8443", "/Tables", tok, "")
	if rec.Code != http.StatusNotFound || storageCode(rec) != "FeatureNotSupported" {
		t.Errorf("table operation: %d %s", rec.Code, storageCode(rec))
	}
}
