package authorization

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/rbac"
)

const (
	sub      = "/subscriptions/22222222-2222-2222-2222-222222222222"
	rg       = sub + "/resourceGroups/Dev"
	client   = "44444444-4444-4444-4444-444444444444"
	mi       = "66666666-6666-6666-6666-666666666666"
	defsPath = "/providers/Microsoft.Authorization/roleDefinitions/"
	asgPath  = "/providers/Microsoft.Authorization/roleAssignments/"
	nameA    = "11111111-aaaa-4aaa-8aaa-111111111111"
	nameB    = "22222222-bbbb-4bbb-8bbb-222222222222"
)

// builtinDefs is parsed once: the seed is 1.6 MB.
var builtinDefs = mustLoadDefs()

var clock = time.Date(2026, 9, 13, 10, 0, 0, 0, time.UTC)

func mustLoadDefs() map[string]rbac.RoleDefinition {
	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		panic(err)
	}
	return defs
}

// newProvider seeds the default config's grants - client is Owner, the
// managed identity is Contributor, both at the subscription - under a
// fixed clock.
func newProvider(t *testing.T) *Provider {
	t.Helper()
	cfg := config.Default()
	store := rbac.NewAssignmentStore(nil)
	if err := rbac.Seed(store, builtinDefs, gateway.SeedAssignments(cfg)); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	return New(cfg, builtinDefs, store, func() time.Time { return clock })
}

// serve runs one request through RouteRequest and the provider. A
// non-empty filter is sent URL-encoded as $filter, the way az sends it.
func serve(t *testing.T, p *Provider, method, path, filter, body string) *httptest.ResponseRecorder {
	t.Helper()
	target := path + "?api-version=2022-04-01"
	if filter != "" {
		target += "&" + url.Values{"$filter": {filter}}.Encode()
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	rec := httptest.NewRecorder()
	gateway.RouteRequest(p).ServeHTTP(rec, req)
	return rec
}

func code(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("x-ms-error-code")
}

// grant is the PUT body for a role assignment.
func grant(roleGUID, principal string) string {
	return `{"properties":{"roleDefinitionId":"` + sub + defsPath + roleGUID +
		`","principalId":"` + principal + `","principalType":"ServicePrincipal"}}`
}

type wireAssignment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties struct {
		RoleDefinitionID string    `json:"roleDefinitionId"`
		PrincipalID      string    `json:"principalId"`
		PrincipalType    string    `json:"principalType"`
		Scope            string    `json:"scope"`
		CreatedOn        time.Time `json:"createdOn"`
	} `json:"properties"`
}

func decodeAssignment(t *testing.T, rec *httptest.ResponseRecorder) wireAssignment {
	t.Helper()
	var a wireAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
		t.Fatalf("body is not an assignment: %v\n%s", err, rec.Body.String())
	}
	return a
}

func decodeList(t *testing.T, rec *httptest.ResponseRecorder) []wireAssignment {
	t.Helper()
	var list struct {
		Value []wireAssignment `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("body is not a list: %v\n%s", err, rec.Body.String())
	}
	return list.Value
}

func TestRoleDefinitions(t *testing.T) {
	p := newProvider(t)
	defs := sub + "/providers/Microsoft.Authorization/roleDefinitions"

	rec := serve(t, p, http.MethodGet, defs, "roleName eq 'Reader'", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("by name: status = %d %s, want 200", rec.Code, code(rec))
	}
	var list struct {
		Value []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			Properties struct {
				RoleName    string            `json:"roleName"`
				Type        string            `json:"type"`
				Permissions []rbac.Permission `json:"permissions"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("by name: body: %v", err)
	}
	if len(list.Value) != 1 {
		t.Fatalf("by name: %d definitions, want 1", len(list.Value))
	}
	got := list.Value[0]
	if got.ID != sub+defsPath+config.ReaderRoleID || got.Name != config.ReaderRoleID {
		t.Errorf("by name: id %q name %q, want Reader under the subscription", got.ID, got.Name)
	}
	gp := got.Properties
	if gp.RoleName != "Reader" || gp.Type != "BuiltInRole" || len(gp.Permissions) != 1 {
		t.Errorf("by name: properties = %+v", gp)
	}

	counts := []struct {
		name   string
		filter string
		want   int
	}{
		{"no filter", "", len(builtinDefs)},
		{"atScopeAndBelow", "atScopeAndBelow()", len(builtinDefs)},
		{"built-in only", "type eq 'BuiltInRole'", len(builtinDefs)},
		{"custom only", "type eq 'CustomRole'", 0},
		{"name, other casing", "rolename EQ 'reader'", 1},
	}
	for _, tt := range counts {
		rec := serve(t, p, http.MethodGet, defs, tt.filter, "")
		var l struct {
			Value []json.RawMessage `json:"value"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &l) != nil {
			t.Errorf("%s: status = %d %s", tt.name, rec.Code, code(rec))
			continue
		}
		if len(l.Value) != tt.want {
			t.Errorf("%s: %d definitions, want %d", tt.name, len(l.Value), tt.want)
		}
	}
	rec = serve(t, p, http.MethodGet, defs, "type eq 'CustomRole'", "")
	if rec.Body.String() != `{"value":[]}` {
		t.Errorf("empty list = %s, want {\"value\":[]}", rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, defs, "roleName ne 'Reader'", "")
	if rec.Code != http.StatusBadRequest || code(rec) != azerr.CodeInvalidFilter {
		t.Errorf("unsupported filter: status = %d code %q, want 400 InvalidFilter", rec.Code, code(rec))
	}

	owner := config.OwnerRoleID
	ids := []struct {
		name, path, wantID string
	}{
		{"get at rg scope, other casing", rg + defsPath + strings.ToUpper(owner), sub + defsPath + owner},
		{"get at tenant scope", defsPath + owner, defsPath + owner},
	}
	for _, tt := range ids {
		rec := serve(t, p, http.MethodGet, tt.path, "", "")
		var one struct {
			ID string `json:"id"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &one) != nil {
			t.Errorf("%s: status = %d %s", tt.name, rec.Code, code(rec))
			continue
		}
		if one.ID != tt.wantID {
			t.Errorf("%s: id = %q, want %q", tt.name, one.ID, tt.wantID)
		}
	}
	rec = serve(t, p, http.MethodGet, sub+defsPath+"00000000-0000-0000-0000-000000000000", "", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeRoleDefinitionDoesNotExist {
		t.Errorf("get unknown: status = %d code %q, want 404", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPut, sub+defsPath+nameA, "", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("custom role PUT: status = %d, want 405", rec.Code)
	}
}

func TestAssignmentLifecycle(t *testing.T) {
	p := newProvider(t)
	subs := sub + "/providers/Microsoft.Authorization/roleAssignments"
	rgs := rg + "/providers/Microsoft.Authorization/roleAssignments"

	rec := serve(t, p, http.MethodPut, sub+asgPath+nameA, "", grant(config.ReaderRoleID, mi))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d %s %s", rec.Code, code(rec), rec.Body.String())
	}
	got := decodeAssignment(t, rec)
	if got.ID != sub+asgPath+nameA || got.Name != nameA {
		t.Errorf("create identity = %q %q", got.ID, got.Name)
	}
	if got.Type != "Microsoft.Authorization/roleAssignments" {
		t.Errorf("create type = %q", got.Type)
	}
	pr := got.Properties
	if pr.RoleDefinitionID != sub+defsPath+config.ReaderRoleID || pr.PrincipalID != mi ||
		pr.PrincipalType != "ServicePrincipal" || pr.Scope != sub || !pr.CreatedOn.Equal(clock) {
		t.Errorf("create properties = %+v", pr)
	}

	rec = serve(t, p, http.MethodGet, sub+asgPath+strings.ToUpper(nameA), "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("get: status = %d %s, want 200", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPut, sub+asgPath+nameA, "", grant(config.ReaderRoleID, mi))
	if rec.Code != http.StatusCreated {
		t.Errorf("identical re-PUT: status = %d %s, want 201", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPut, sub+asgPath+nameA, "", grant(config.OwnerRoleID, mi))
	if rec.Code != http.StatusBadRequest || code(rec) != azerr.CodeRoleAssignmentUpdateNotPermitted {
		t.Errorf("changed re-PUT: status = %d code %q, want 400", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPut, sub+asgPath+nameB, "", grant(config.ReaderRoleID, mi))
	if rec.Code != http.StatusConflict || code(rec) != azerr.CodeRoleAssignmentExists {
		t.Errorf("same grant, new name: status = %d code %q, want 409", rec.Code, code(rec))
	}

	// A second assignment below the subscription, to prove scoping.
	rec = serve(t, p, http.MethodPut, rg+asgPath+nameB, "", grant(config.ReaderRoleID, client))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create at rg: status = %d %s", rec.Code, code(rec))
	}
	lists := []struct {
		name   string
		path   string
		filter string
		want   int
	}{
		{"sub, at or above", subs, "atScope()", 3},
		{"sub, everything", subs, "", 4},
		{"rg, at or above", rgs, "atScope()", 4},
		{"sub, one principal", subs, "principalId eq '" + mi + "'", 2},
		{"sub, assignedTo", subs, "assignedTo('" + strings.ToUpper(client) + "')", 2},
		{"rg, at scope and principal", rgs, "atScope() and assignedTo('" + client + "')", 2},
	}
	for _, tt := range lists {
		rec := serve(t, p, http.MethodGet, tt.path, tt.filter, "")
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d %s", tt.name, rec.Code, code(rec))
			continue
		}
		if got := decodeList(t, rec); len(got) != tt.want {
			t.Errorf("%s: %d assignments, want %d", tt.name, len(got), tt.want)
		}
	}
	rec = serve(t, p, http.MethodGet, subs, "scope eq 'x'", "")
	if rec.Code != http.StatusBadRequest || code(rec) != azerr.CodeInvalidFilter {
		t.Errorf("unsupported filter: status = %d code %q, want 400 InvalidFilter", rec.Code, code(rec))
	}

	// Names are global, scopes are not: the rg assignment is invisible
	// through the subscription path, and a delete there touches nothing.
	rec = serve(t, p, http.MethodGet, sub+asgPath+nameB, "", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeRoleAssignmentNotFound {
		t.Errorf("get under wrong scope: status = %d code %q, want 404", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodDelete, sub+asgPath+nameB, "", "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete under wrong scope: status = %d, want 204", rec.Code)
	}
	rec = serve(t, p, http.MethodGet, rg+asgPath+nameB, "", "")
	if rec.Code != http.StatusOK {
		t.Errorf("rg assignment after wrong-scope delete: status = %d, want 200", rec.Code)
	}

	rec = serve(t, p, http.MethodDelete, sub+asgPath+nameA, "", "")
	if rec.Code != http.StatusOK || decodeAssignment(t, rec).Name != nameA {
		t.Errorf("delete: status = %d body %s, want 200 + body", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodDelete, sub+asgPath+nameA, "", "")
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("second delete: status = %d body %q, want 204, no body", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, sub+asgPath+nameA, "", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("get after delete: status = %d, want 404", rec.Code)
	}
}

func TestAssignmentRejections(t *testing.T) {
	unknownRole := `{"properties":{"roleDefinitionId":"` + sub + defsPath +
		`00000000-0000-0000-0000-000000000000","principalId":"` + mi + `"}}`
	stranger := `{"properties":{"roleDefinitionId":"` + config.ReaderRoleID +
		`","principalId":"99999999-9999-9999-9999-999999999999"}}`
	noPrincipal := `{"properties":{"roleDefinitionId":"` + config.ReaderRoleID + `"}}`
	tests := []struct {
		name     string
		body     string
		wantCode string
	}{
		{"no body", "", azerr.CodeInvalidRequestContent},
		{"not json", "role=Reader", azerr.CodeInvalidRequestContent},
		{"missing principal", noPrincipal, azerr.CodeInvalidRequestContent},
		{"unknown role", unknownRole, azerr.CodeRoleDefinitionDoesNotExist},
		{"unknown principal", stranger, azerr.CodePrincipalNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(t, newProvider(t), http.MethodPut, sub+asgPath+nameB, "", tt.body)
			if rec.Code != http.StatusBadRequest || code(rec) != tt.wantCode {
				t.Errorf("status = %d code %q, want 400 %s", rec.Code, code(rec), tt.wantCode)
			}
		})
	}
}

func TestAssignmentAcceptsBareGUIDAndDefaultsType(t *testing.T) {
	body := `{"properties":{"roleDefinitionId":"` + config.ReaderRoleID +
		`","principalId":"` + strings.ToUpper(mi) + `"}}`
	rec := serve(t, newProvider(t), http.MethodPut, rg+asgPath+nameB, "", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d %s, want 201", rec.Code, code(rec))
	}
	got := decodeAssignment(t, rec).Properties
	if got.PrincipalType != "ServicePrincipal" || got.PrincipalID != mi || got.Scope != rg {
		t.Errorf("properties = %+v, want ServicePrincipal, lowercase principal, rg scope as given", got)
	}
}

func TestUnknownTypeAndUnrouted(t *testing.T) {
	p := newProvider(t)
	rec := serve(t, p, http.MethodGet, sub+"/providers/Microsoft.Authorization/denyAssignments", "", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeInvalidResourceType {
		t.Errorf("unknown type: status = %d code %q, want 404", rec.Code, code(rec))
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, sub+asgPath+nameA+"?api-version=2022-04-01", nil)
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("unrouted: status = %d, want 500", rec.Code)
	}
}
