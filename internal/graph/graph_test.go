package graph

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
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

// values is the "value" array of a listing as ids, in order.
func values(t *testing.T, out map[string]any) []string {
	t.Helper()
	list, ok := out["value"].([]any)
	if !ok {
		t.Fatalf("no value array in %v", out)
	}
	ids := make([]string, len(list))
	for i, v := range list {
		switch v := v.(type) {
		case string:
			ids[i] = v
		case map[string]any:
			ids[i], _ = v["id"].(string)
		}
	}
	return ids
}

// What az ad user create sends, and the ways az looks a user up after.
func TestUsersAsAzCreatesAndFindsThem(t *testing.T) {
	p, _, tok := newPlane(t)
	const ada = `{"userPrincipalName":"ada@armite.local","displayName":"Ada","mailNickname":"ada",` +
		`"accountEnabled":true,"passwordProfile":{"password":"P@ssw0rd!","forceChangePasswordNextSignIn":false}}`
	code, user := call(t, p, "POST", "/v1.0/users", tok, ada)
	id, _ := user["id"].(string)
	if code != 201 || id == "" || user["userPrincipalName"] != "ada@armite.local" || user["accountEnabled"] != true {
		t.Fatalf("create user: %d %v", code, user)
	}
	if raw, _ := json.Marshal(user); strings.Contains(string(raw), "assw") {
		t.Errorf("the response carries the password or its hash: %s", raw)
	}
	for _, key := range []string{id, "ada@armite.local", "ADA@armite.local"} {
		if code, got := call(t, p, "GET", "/v1.0/users/"+key, tok, ""); code != 200 || got["id"] != id {
			t.Errorf("GET /users/%s: %d %v", key, code, got)
		}
	}
	q := url.Values{"$filter": {"userPrincipalName eq 'ada@armite.local'"}}
	if _, list := call(t, p, "GET", "/v1.0/users?"+q.Encode(), tok, ""); !slices.Equal(values(t, list), []string{id}) {
		t.Errorf("filter by userPrincipalName: %v", list)
	}

	if code, out := call(t, p, "POST", "/v1.0/users", tok, ada); code != 400 || errCode(out) != "Request_BadRequest" {
		t.Errorf("a second user with the same userPrincipalName: %d %v", code, out)
	}
	for _, missing := range []string{"userPrincipalName", "displayName", "mailNickname", "accountEnabled", "passwordProfile"} {
		var body map[string]any
		_ = json.Unmarshal([]byte(strings.Replace(ada, "ada@", "bob@", 1)), &body)
		delete(body, missing)
		raw, _ := json.Marshal(body)
		code, out := call(t, p, "POST", "/v1.0/users", tok, string(raw))
		msg, _ := out["error"].(map[string]any)["message"].(string)
		if code != 400 || !strings.Contains(msg, "'"+missing+"'") {
			t.Errorf("a user without %s: %d %q", missing, code, msg)
		}
	}
	if code, _ := call(t, p, "POST", "/v1.0/users", tok, strings.Replace(ada, "ada@armite.local", "no-domain", 1)); code != 400 {
		t.Errorf("a userPrincipalName without a domain: %d", code)
	}

	before, _ := p.dir.Get(id)
	if code, out := call(t, p, "PATCH", "/v1.0/users/ada@armite.local", tok,
		`{"displayName":"Ada L","passwordProfile":{"password":"N3w-secret"}}`); code != 204 {
		t.Fatalf("patch user: %d %v", code, out)
	}
	after, _ := p.dir.Get(id)
	if after.DisplayName != "Ada L" || after.PasswordHash == "" || after.PasswordHash == before.PasswordHash {
		t.Errorf("after the patch: name %q, password changed %v", after.DisplayName, after.PasswordHash != before.PasswordHash)
	}
	if code, _ := call(t, p, "DELETE", "/v1.0/users/ada@armite.local", tok, ""); code != 204 {
		t.Errorf("delete user: %d", code)
	}
	if code, _ := call(t, p, "GET", "/v1.0/users/"+id, tok, ""); code != 404 {
		t.Errorf("the user after its delete: %d", code)
	}
}

// What az ad group create and az ad group member send: a group, a
// group inside it, and the membership questions answered through the
// nesting.
func TestGroupsAndTheirMembers(t *testing.T) {
	p, cfg, tok := newPlane(t)
	ref := func(id string) string {
		return `{"@odata.id":"` + cfg.GraphBaseURL() + `/v1.0/directoryObjects/` + id + `"}`
	}
	group := func(name string) string {
		t.Helper()
		code, g := call(t, p, "POST", "/v1.0/groups", tok,
			`{"displayName":"`+name+`","mailNickname":"`+name+`","mailEnabled":false,"securityEnabled":true}`)
		if code != 201 || g["securityEnabled"] != true || g["description"] != nil {
			t.Fatalf("create group %s: %d %v", name, code, g)
		}
		return g["id"].(string)
	}
	outer, inner := group("outer"), group("inner")
	_, user := call(t, p, "POST", "/v1.0/users", tok, `{"userPrincipalName":"ada@armite.local","displayName":"Ada",`+
		`"mailNickname":"ada","accountEnabled":true,"passwordProfile":{"password":"P@ssw0rd!"}}`)
	userID := user["id"].(string)
	sp := cfg.Clients[0].ObjectID // the configured service principal

	if code, out := call(t, p, "POST", "/v1.0/groups", tok, `{"displayName":"x","mailNickname":"x"}`); code != 400 ||
		!strings.Contains(out["error"].(map[string]any)["message"].(string), "'mailEnabled'") {
		t.Errorf("a group without its flags: %d %v", code, out)
	}

	// outer holds the user and inner; inner holds the service principal.
	for _, add := range [][2]string{{outer, userID}, {outer, inner}, {inner, sp}} {
		if code, out := call(t, p, "POST", "/v1.0/groups/"+add[0]+"/members/$ref", tok, ref(add[1])); code != 204 {
			t.Fatalf("add member: %d %v", code, out)
		}
	}
	if code, out := call(t, p, "POST", "/v1.0/groups/"+outer+"/members/$ref", tok, ref(userID)); code != 400 ||
		errCode(out) != "Request_BadRequest" {
		t.Errorf("the same member twice: %d %v", code, out)
	}
	if code, _ := call(t, p, "POST", "/v1.0/groups/"+outer+"/members/$ref", tok, ref(outer)); code != 400 {
		t.Errorf("a group as its own member: %d", code)
	}
	if code, out := call(t, p, "POST", "/v1.0/groups/"+outer+"/members/$ref", tok,
		ref("00000000-0000-0000-0000-000000000000")); code != 404 || errCode(out) != "Request_ResourceNotFound" {
		t.Errorf("a member that does not exist: %d %v", code, out)
	}
	if code, _ := call(t, p, "POST", "/v1.0/groups/"+outer+"/members/$ref", tok, `{}`); code != 400 {
		t.Errorf("a $ref without a body: %d", code)
	}

	_, direct := call(t, p, "GET", "/v1.0/groups/"+outer+"/members", tok, "")
	if !slices.Equal(values(t, direct), []string{userID, inner}) {
		t.Errorf("members of outer = %v, want the user and inner", values(t, direct))
	}
	first := direct["value"].([]any)[0].(map[string]any)
	if first["@odata.type"] != "#microsoft.graph.user" || first["userPrincipalName"] != "ada@armite.local" {
		t.Errorf("a member must say what it is: %v", first)
	}
	_, all := call(t, p, "GET", "/v1.0/groups/"+outer+"/transitiveMembers", tok, "")
	if !slices.Equal(values(t, all), []string{userID, inner, sp}) {
		t.Errorf("transitive members of outer = %v, want the user, inner and the service principal", values(t, all))
	}

	// The service principal is in inner directly and in outer through it.
	_, in := call(t, p, "POST", "/v1.0/directoryObjects/"+sp+"/checkMemberGroups", tok,
		`{"groupIds":["`+outer+`","00000000-0000-0000-0000-000000000000","`+inner+`"]}`)
	if !slices.Equal(values(t, in), []string{outer, inner}) {
		t.Errorf("checkMemberGroups = %v, want outer and inner, in the order asked", values(t, in))
	}
	_, of := call(t, p, "POST", "/v1.0/servicePrincipals/"+sp+"/getMemberGroups", tok, `{"securityEnabledOnly":false}`)
	if got := values(t, of); len(got) != 2 || !slices.Contains(got, outer) || !slices.Contains(got, inner) {
		t.Errorf("getMemberGroups of the service principal = %v", got)
	}
	_, of = call(t, p, "POST", "/v1.0/users/ada@armite.local/getMemberGroups", tok, "")
	if !slices.Equal(values(t, of), []string{outer}) {
		t.Errorf("getMemberGroups of the user = %v, want outer", values(t, of))
	}
	if code, out := call(t, p, "POST", "/v1.0/applications/"+sp+"/checkMemberGroups", tok, `{"groupIds":[]}`); code != 400 ||
		errCode(out) != "BadRequest" {
		t.Errorf("an application has no memberships to ask about: %d %v", code, out)
	}
	if code, _ := call(t, p, "POST", "/v1.0/directoryObjects/00000000-0000-0000-0000-000000000000/checkMemberGroups", tok,
		`{"groupIds":[]}`); code != 404 {
		t.Errorf("checkMemberGroups for nobody: %d", code)
	}

	// az role assignment list names users and groups through getByIds.
	_, named := call(t, p, "POST", "/v1.0/directoryObjects/getByIds", tok, `{"ids":["`+userID+`","`+outer+`"]}`)
	list := named["value"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["@odata.type"] != "#microsoft.graph.user" ||
		list[1].(map[string]any)["@odata.type"] != "#microsoft.graph.group" || list[1].(map[string]any)["displayName"] != "outer" {
		t.Errorf("getByIds = %v", list)
	}

	if code, _ := call(t, p, "DELETE", "/v1.0/groups/"+outer+"/members/"+userID+"/$ref", tok, ""); code != 204 {
		t.Errorf("remove member: %d", code)
	}
	if code, out := call(t, p, "DELETE", "/v1.0/groups/"+outer+"/members/"+userID+"/$ref", tok, ""); code != 404 ||
		errCode(out) != "Request_ResourceNotFound" {
		t.Errorf("remove a non-member: %d %v", code, out)
	}
	// A deleted group leaves the group it was in.
	if code, _ := call(t, p, "DELETE", "/v1.0/groups/"+inner, tok, ""); code != 204 {
		t.Errorf("delete inner: %d", code)
	}
	if _, left := call(t, p, "GET", "/v1.0/groups/"+outer+"/transitiveMembers", tok, ""); len(values(t, left)) != 0 {
		t.Errorf("outer after inner is gone = %v, want empty", values(t, left))
	}
	if code, _ := call(t, p, "GET", "/v1.0/groups/"+inner+"/members", tok, ""); code != 404 {
		t.Errorf("members of a deleted group: %d", code)
	}
}
