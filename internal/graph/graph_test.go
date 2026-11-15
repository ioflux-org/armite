package graph

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/directory"
	"github.com/ioflux-org/armite/internal/entra"
)

var testKey = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}()

func mintToken(t *testing.T, cfg config.Config, scope string) string {
	t.Helper()
	cl := cfg.Clients[0]
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cl.ID},
		"client_secret": {cl.Secret}, "scope": {scope}}
	req := httptest.NewRequest(http.MethodPost, "/"+cfg.TenantID+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	entra.New(cfg, testKey).ServeHTTP(rec, req)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.AccessToken == "" {
		t.Fatalf("token: %d %s", rec.Code, rec.Body.String())
	}
	return body.AccessToken
}

func newPlane(t *testing.T) (*Plane, config.Config, string) {
	t.Helper()
	cfg := config.Default()
	dir := directory.New(nil)
	if err := dir.Seed(cfg); err != nil {
		t.Fatal(err)
	}
	return New(cfg, dir, &testKey.PublicKey, time.Now), cfg, mintToken(t, cfg, cfg.GraphAudience()+"/.default")
}

func call(t *testing.T, p *Plane, method, target, token, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "https://graph.localhost:8443"+target, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s: not JSON: %s", method, target, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestNeedsAGraphToken(t *testing.T) {
	p, cfg, _ := newPlane(t)
	if code, out := call(t, p, "GET", "/v1.0/servicePrincipals", "", ""); code != 401 ||
		out["error"].(map[string]any)["code"] != "InvalidAuthenticationToken" {
		t.Errorf("no token: %d %v", code, out)
	}
	arm := mintToken(t, cfg, "https://management.azure.com/.default")
	if code, _ := call(t, p, "GET", "/v1.0/servicePrincipals", arm, ""); code != 401 {
		t.Errorf("an ARM token was accepted by Graph: %d", code)
	}
}

func TestSeedsAreListedTheWayAzLooksForThem(t *testing.T) {
	p, cfg, tok := newPlane(t)
	cl := cfg.Clients[0]
	q := url.Values{"$filter": {"servicePrincipalNames/any(c:c eq '" + cl.ID + "')"}}
	code, out := call(t, p, "GET", "/v1.0/servicePrincipals?"+q.Encode(), tok, "")
	vals, _ := out["value"].([]any)
	if code != 200 || len(vals) != 1 {
		t.Fatalf("any() by appId: %d %v", code, out)
	}
	sp := vals[0].(map[string]any)
	if sp["id"] != cl.ObjectID || sp["appId"] != cl.ID || sp["servicePrincipalType"] != "Application" {
		t.Errorf("seeded sp on the wire: %v", sp)
	}
	q = url.Values{"$filter": {"startswith(displayName,'armite-client')"}}
	code, out = call(t, p, "GET", "/v1.0/applications?"+q.Encode(), tok, "")
	if code != 200 || len(out["value"].([]any)) != 1 {
		t.Fatalf("applications by displayName prefix: %d %v", code, out)
	}
	app := out["value"].([]any)[0].(map[string]any)
	creds := app["passwordCredentials"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["hash"] != nil || creds[0].(map[string]any)["secretText"] != nil {
		t.Errorf("credentials must show metadata only: %v", creds)
	}
	if code, out := call(t, p, "GET", "/v1.0/servicePrincipals/"+cl.ObjectID, tok, ""); code != 200 || out["appId"] != cl.ID {
		t.Errorf("get by object id: %d %v", code, out)
	}
}

func TestGetByIdsNamesThePrincipals(t *testing.T) {
	p, cfg, tok := newPlane(t)
	body := `{"ids":["` + cfg.Clients[0].ObjectID + `","` + cfg.ManagedIdentity.ObjectID + `","00000000-0000-0000-0000-000000000000"],` +
		`"types":["user","group","servicePrincipal","directoryObjectPartnerReference"]}`
	code, out := call(t, p, "POST", "/v1.0/directoryObjects/getByIds", tok, body)
	vals, _ := out["value"].([]any)
	if code != 200 || len(vals) != 2 {
		t.Fatalf("getByIds: %d %v", code, out)
	}
	if vals[0].(map[string]any)["@odata.type"] != "#microsoft.graph.servicePrincipal" {
		t.Errorf("odata type: %v", vals[0])
	}
}

func TestErrorsHaveGraphShape(t *testing.T) {
	p, _, tok := newPlane(t)
	for _, tc := range []struct {
		method, target string
		code           int
		errCode        string
	}{
		{"GET", "/v1.0/users/nobody@armite.local", 404, "Request_ResourceNotFound"},
		{"GET", "/v1.0/nonsense", 404, "Request_ResourceNotFound"},
		{"GET", "/v1.0/servicePrincipals?%24filter=displayName+gt+%27x%27", 400, "Request_UnsupportedQuery"},
		{"GET", "/v1.0/me", 400, "BadRequest"},
	} {
		code, out := call(t, p, tc.method, tc.target, tok, "")
		e, _ := out["error"].(map[string]any)
		if code != tc.code || e["code"] != tc.errCode || e["innerError"] == nil {
			t.Errorf("%s %s: %d %v", tc.method, tc.target, code, out)
		}
	}
}
