package keyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/entra"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/rbac"
)

const (
	secretsUserRole    = "4633458b-17de-408a-b874-0445c86b69e6"
	secretsOfficerRole = "b86a8fe4-44ce-4948-aee5-eccb2c155cd7"
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
// entra handler, for any scope - the data plane's audience included.
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
	return accessToken(t, rec)
}

// mintIMDSToken gets the managed identity's token from the real IMDS
// handler for the given resource.
func mintIMDSToken(t *testing.T, cfg config.Config, resource string) string {
	t.Helper()
	target := "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
		url.QueryEscape(resource)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Metadata", "true")
	rec := httptest.NewRecorder()
	entra.NewIMDS(cfg, testKey).ServeHTTP(rec, req)
	return accessToken(t, rec)
}

func accessToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
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

// dataPlaneFor builds the data plane over p with the default seeds plus
// grants, so several handlers can share one provider (and its secrets).
func dataPlaneFor(t *testing.T, p *Provider, grants ...rbac.RoleAssignment) http.Handler {
	t.Helper()
	as := rbac.NewAssignmentStore(nil)
	all := append(gateway.SeedAssignments(p.cfg), grants...)
	if err := rbac.Seed(as, builtinDefs, all); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	// Tokens are minted at the real time, so the verifier's clock must be real too.
	return p.DataPlane(&testKey.PublicKey, time.Now, rbac.NewChecker(builtinDefs, as))
}

// vaultProvider returns a provider whose store holds the group and the
// vault kv-demo, created through the management plane.
func vaultProvider(t *testing.T) *Provider {
	t.Helper()
	p := newProvider(t)
	rec := serve(t, p, http.MethodPut, rg+vaults+"/kv-demo", azBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create vault: %d %s", rec.Code, rec.Body.String())
	}
	return p
}

func dp(t *testing.T, h http.Handler, method, host, path, token, body string,
) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "https://"+host+path+"?api-version=7.4", rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestDataPlaneAuthentication(t *testing.T) {
	cfg := config.Default()
	h := dataPlaneFor(t, vaultProvider(t))
	vaultTok := mintClientToken(t, cfg, cfg.VaultAudience()+"/.default")
	armTok := mintClientToken(t, cfg, "https://management.azure.com/.default")

	rec := dp(t, h, http.MethodGet, vaultHost, "/secrets/db", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: status = %d, want 401", rec.Code)
	}
	challenge := rec.Header().Get("WWW-Authenticate")
	wantParts := []string{
		`Bearer authorization="https://login.localhost:8443/` + cfg.TenantID + `"`,
		`resource="https://vault.localhost:8443"`,
	}
	for _, want := range wantParts {
		if !strings.Contains(challenge, want) {
			t.Errorf("challenge %q lacks %s", challenge, want)
		}
	}
	if code, _ := kvCode(t, rec); code != kvUnauthorized {
		t.Errorf("anonymous: code = %s, want Unauthorized", code)
	}
	rec = dp(t, h, http.MethodGet, vaultHost, "/secrets/db", armTok, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("ARM-audience token: status = %d, want 401", rec.Code)
	}
	rec = dp(t, h, http.MethodGet, "nope.vault.localhost:8443", "/secrets/db", vaultTok, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown vault: status = %d, want 404", rec.Code)
	}
	rec = dp(t, h, http.MethodGet, "vault.localhost:8443", "/secrets/db", vaultTok, "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("bare suffix: status = %d, want 404", rec.Code)
	}
	// The thesis: Owner on the management plane, nothing on the data plane.
	rec = dp(t, h, http.MethodGet, vaultHost, "/secrets/db", vaultTok, "")
	code, inner := kvCode(t, rec)
	if rec.Code != http.StatusForbidden || code != kvForbidden || inner != kvForbiddenByRbac {
		t.Errorf("owner reads a secret: %d %s/%s, want 403 ForbiddenByRbac", rec.Code, code, inner)
	}
	if !strings.Contains(rec.Body.String(), "Action: '"+actionPrefix+"getSecret/action'") {
		t.Errorf("403 message must name the action: %s", rec.Body.String())
	}
}

func TestDataPlaneAuthorization(t *testing.T) {
	cfg := config.Default()
	p := vaultProvider(t)
	mi := cfg.ManagedIdentity.ObjectID
	vaultID := rg + vaults + "/kv-demo"
	grant := func(role string) rbac.RoleAssignment {
		return rbac.RoleAssignment{PrincipalID: mi, RoleDefinitionID: role, Scope: vaultID}
	}
	officer := dataPlaneFor(t, p, grant(secretsOfficerRole))
	user := dataPlaneFor(t, p, grant(secretsUserRole))
	miTok := mintIMDSToken(t, cfg, cfg.VaultAudience()+"/")
	ownerTok := mintClientToken(t, cfg, cfg.VaultAudience()+"/.default")

	steps := []struct {
		name       string
		h          http.Handler
		method     string
		path       string
		token      string
		body       string
		wantStatus int
	}{
		{"officer sets", officer, http.MethodPut, "/secrets/db", miTok, `{"value":"s3cret"}`, 200},
		{"user reads", user, http.MethodGet, "/secrets/db", miTok, "", 200},
		{"user lists", user, http.MethodGet, "/secrets", miTok, "", 200},
		{"user cannot set", user, http.MethodPut, "/secrets/db", miTok, `{"value":"x"}`, 403},
		{"user cannot delete", user, http.MethodDelete, "/secrets/db", miTok, "", 403},
		{"owner cannot read", officer, http.MethodGet, "/secrets/db", ownerTok, "", 403},
		{"officer deletes", officer, http.MethodDelete, "/secrets/db", miTok, "", 200},
		{"user reads the deleted secret", user, http.MethodGet, "/deletedsecrets/db", miTok, "", 200},
		{"user cannot purge", user, http.MethodDelete, "/deletedsecrets/db", miTok, "", 403},
		{"officer purges", officer, http.MethodDelete, "/deletedsecrets/db", miTok, "", 204},
	}
	for _, st := range steps {
		rec := dp(t, st.h, st.method, vaultHost, st.path, st.token, st.body)
		if rec.Code != st.wantStatus {
			t.Errorf("%s: status = %d, want %d: %s", st.name, rec.Code, st.wantStatus, rec.Body.String())
		}
		if st.wantStatus == 403 {
			if _, inner := kvCode(t, rec); inner != kvForbiddenByRbac {
				t.Errorf("%s: innererror = %q, want ForbiddenByRbac", st.name, inner)
			}
		}
	}
}
