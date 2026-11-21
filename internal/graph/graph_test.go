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

func errCode(out map[string]any) any {
	e, _ := out["error"].(map[string]any)
	return e["code"]
}

// The az ad sp create-for-rbac sequence, request for request: an
// application, a password on it, a service principal for it.
func TestCreateApplicationPasswordAndServicePrincipal(t *testing.T) {
	p, _, tok := newPlane(t)
	code, app := call(t, p, "POST", "/v1.0/applications", tok, `{"displayName":"ci-app","keyCredentials":[]}`)
	appObj, _ := app["id"].(string)
	appID, _ := app["appId"].(string)
	if code != 201 || appObj == "" || appID == "" || app["displayName"] != "ci-app" {
		t.Fatalf("create application: %d %v", code, app)
	}
	code, cred := call(t, p, "POST", "/v1.0/applications/"+appObj+"/addPassword", tok,
		`{"passwordCredential":{"displayName":"rbac","startDateTime":"2026-11-12T12:39:20Z","endDateTime":"2126-11-12T12:39:20Z"}}`)
	secret, _ := cred["secretText"].(string)
	if code != 200 || len(secret) != 64 || cred["keyId"] == "" || cred["hint"] != secret[:3] ||
		cred["endDateTime"] != "2126-11-12T12:39:20Z" || cred["displayName"] != "rbac" {
		t.Fatalf("addPassword: %d %v", code, cred)
	}
	code, sp := call(t, p, "POST", "/v1.0/servicePrincipals", tok, `{"appId":"`+appID+`","accountEnabled":true}`)
	if code != 201 || sp["appId"] != appID || sp["displayName"] != "ci-app" || sp["servicePrincipalType"] != "Application" {
		t.Fatalf("create service principal: %d %v", code, sp)
	}

	// The secret is never shown again, and the directory accepts it.
	_, got := call(t, p, "GET", "/v1.0/applications/"+appObj, tok, "")
	creds, _ := got["passwordCredentials"].([]any)
	if len(creds) != 1 || creds[0].(map[string]any)["secretText"] != nil || creds[0].(map[string]any)["hint"] != secret[:3] {
		t.Errorf("credentials after addPassword: %v", creds)
	}
	if o, ok := p.dir.Authenticate(appID, secret); !ok || o.ID != sp["id"] {
		t.Errorf("the directory does not accept the secret Graph returned: %+v %v", o, ok)
	}

	if code, out := call(t, p, "POST", "/v1.0/servicePrincipals", tok, `{"appId":"`+appID+`"}`); code != 409 ||
		errCode(out) != "Request_MultipleObjectsWithSameKeyValue" {
		t.Errorf("a second service principal for one application: %d %v", code, out)
	}
	if code, out := call(t, p, "POST", "/v1.0/servicePrincipals", tok,
		`{"appId":"00000000-0000-0000-0000-000000000000"}`); code != 400 || errCode(out) != "Request_BadRequest" {
		t.Errorf("a service principal for no application: %d %v", code, out)
	}
	if code, out := call(t, p, "POST", "/v1.0/applications", tok, `{}`); code != 400 || errCode(out) != "Request_BadRequest" {
		t.Errorf("an application without a displayName: %d %v", code, out)
	}
	if code, out := call(t, p, "POST", "/v1.0/users", tok, `{"displayName":"u"}`); code != 501 || errCode(out) != "NotImplemented" {
		t.Errorf("creating a user is not served yet: %d %v", code, out)
	}
}

func TestPatchRemovePasswordAndDelete(t *testing.T) {
	p, cfg, tok := newPlane(t)
	_, app := call(t, p, "POST", "/v1.0/applications", tok, `{"displayName":"temp"}`)
	appObj, appID := app["id"].(string), app["appId"].(string)
	_, sp := call(t, p, "POST", "/v1.0/servicePrincipals", tok, `{"appId":"`+appID+`"}`)
	spObj := sp["id"].(string)

	// No dates: the credential starts now and lasts two years.
	code, cred := call(t, p, "POST", "/v1.0/servicePrincipals/"+spObj+"/addPassword", tok, "")
	secret, _ := cred["secretText"].(string)
	start, _ := time.Parse(time.RFC3339, cred["startDateTime"].(string))
	end, _ := time.Parse(time.RFC3339, cred["endDateTime"].(string))
	if code != 200 || secret == "" || end.Sub(start) < 729*24*time.Hour {
		t.Fatalf("addPassword with no body: %d %v", code, cred)
	}
	if _, ok := p.dir.Authenticate(appID, secret); !ok {
		t.Error("a password on the service principal must log in")
	}

	// PATCH changes only what it names.
	if code, out := call(t, p, "PATCH", "/v1.0/applications/"+appObj, tok, `{"displayName":"renamed"}`); code != 204 {
		t.Fatalf("patch application: %d %v", code, out)
	}
	if _, got := call(t, p, "GET", "/v1.0/applications/"+appObj, tok, ""); got["displayName"] != "renamed" || got["appId"] != appID {
		t.Errorf("after the patch: %v", got)
	}
	if code, _ := call(t, p, "PATCH", "/v1.0/servicePrincipals/"+spObj, tok, `{"accountEnabled":false}`); code != 204 {
		t.Errorf("disable the service principal: %d", code)
	}
	if _, got := call(t, p, "GET", "/v1.0/servicePrincipals/"+spObj, tok, ""); got["accountEnabled"] != false || got["displayName"] != "temp" {
		t.Errorf("after disabling: %v", got)
	}
	if _, ok := p.dir.Authenticate(appID, secret); ok {
		t.Error("a disabled service principal still logs in")
	}

	keyID := cred["keyId"].(string)
	if code, _ := call(t, p, "POST", "/v1.0/servicePrincipals/"+spObj+"/removePassword", tok, `{"keyId":"`+keyID+`"}`); code != 204 {
		t.Errorf("removePassword: %d", code)
	}
	if code, out := call(t, p, "POST", "/v1.0/servicePrincipals/"+spObj+"/removePassword", tok, `{"keyId":"`+keyID+`"}`); code != 400 ||
		errCode(out) != "Request_BadRequest" {
		t.Errorf("removePassword twice: %d %v", code, out)
	}

	// Deleting the application takes its service principal with it.
	if code, _ := call(t, p, "DELETE", "/v1.0/applications/"+appObj, tok, ""); code != 204 {
		t.Errorf("delete application: %d", code)
	}
	if code, _ := call(t, p, "GET", "/v1.0/servicePrincipals/"+spObj, tok, ""); code != 404 {
		t.Errorf("the service principal outlived its application: %d", code)
	}
	if code, out := call(t, p, "DELETE", "/v1.0/applications/"+appObj, tok, ""); code != 404 || errCode(out) != "Request_ResourceNotFound" {
		t.Errorf("delete twice: %d %v", code, out)
	}

	// The configuration's identities can be changed, not deleted.
	seed := cfg.Clients[0]
	if code, out := call(t, p, "DELETE", "/v1.0/servicePrincipals/"+seed.ObjectID, tok, ""); code != 403 ||
		errCode(out) != "Authorization_RequestDenied" {
		t.Errorf("deleting the configured service principal: %d %v", code, out)
	}
	q := url.Values{"$filter": {"appId eq '" + seed.ID + "'"}}
	_, list := call(t, p, "GET", "/v1.0/applications?"+q.Encode(), tok, "")
	seedApp := list["value"].([]any)[0].(map[string]any)["id"].(string)
	if code, _ := call(t, p, "PATCH", "/v1.0/applications/"+seedApp, tok, `{"displayName":"mine now"}`); code != 204 {
		t.Errorf("renaming the configured application: %d", code)
	}
	if code, out := call(t, p, "DELETE", "/v1.0/applications/"+seedApp, tok, ""); code != 403 {
		t.Errorf("deleting the configured application, even after a change: %d %v", code, out)
	}
}
