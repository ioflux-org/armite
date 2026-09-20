package resources

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

const (
	sub = "/subscriptions/22222222-2222-2222-2222-222222222222"
	v   = "?api-version=2021-04-01"
)

// newProvider builds a provider on the default config and an empty store.
func newProvider() *Provider {
	return New(config.Default(), store.New())
}

// serve runs one request through RouteRequest and the provider: the
// pipeline as the provider sees it, after authentication and
// authorization have already said yes.
func serve(t *testing.T, p *Provider, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path+v, rd)
	rec := httptest.NewRecorder()
	gateway.RouteRequest(p).ServeHTTP(rec, req)
	return rec
}

// code returns the x-ms-error-code header; "" on a success response.
func code(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("x-ms-error-code")
}

func decodeGroup(t *testing.T, rec *httptest.ResponseRecorder) store.Resource {
	t.Helper()
	var res store.Resource
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("body is not a resource: %v\n%s", err, rec.Body.String())
	}
	return res
}

func TestGroupLifecycle(t *testing.T) {
	p := newProvider()
	rg := sub + "/resourceGroups/Dev"

	rec := serve(t, p, http.MethodPut, rg, `{"location":"eastus","tags":{"env":"dev"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d %s, want 201", rec.Code, code(rec))
	}
	got := decodeGroup(t, rec)
	if got.ID != rg || got.Name != "Dev" || got.Type != groupType {
		t.Errorf("create echoed id %q name %q type %q", got.ID, got.Name, got.Type)
	}
	if got.Location != "eastus" || got.Tags["env"] != "dev" || string(got.Properties) != provisioned {
		t.Errorf("create body = %+v", got)
	}

	rec = serve(t, p, http.MethodGet, sub+"/resourcegroups/DEV", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d %s, want 200", rec.Code, code(rec))
	}
	if got = decodeGroup(t, rec); got.Name != "Dev" {
		t.Errorf("get echoed name %q, want the casing from creation", got.Name)
	}

	if rec = serve(t, p, http.MethodHead, rg, ""); rec.Code != http.StatusNoContent {
		t.Errorf("head: status = %d, want 204", rec.Code)
	}
	rec = serve(t, p, http.MethodPut, sub+"/resourceGroups/dev", `{"location":"EastUS"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: status = %d %s, want 200", rec.Code, code(rec))
	}
	got = decodeGroup(t, rec)
	if got.Name != "Dev" || got.Location != "eastus" || got.Tags != nil {
		t.Errorf("replace = %+v, want original casing and location, tags removed", got)
	}

	rec = serve(t, p, http.MethodGet, sub+"/resourceGroups", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d %s, want 200", rec.Code, code(rec))
	}

	var list struct {
		Value []store.Resource `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(list.Value) != 1 || list.Value[0].ID != rg {
		t.Errorf("list = %+v, want just %s", list.Value, rg)
	}

	if rec = serve(t, p, http.MethodDelete, rg, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete: status = %d %s, want 200", rec.Code, code(rec))
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodDelete} {
		rec = serve(t, p, method, rg, "")
		if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeResourceGroupNotFound {
			t.Errorf("%s after delete: status = %d code %q, want 404 ResourceGroupNotFound",
				method, rec.Code, code(rec))
		}
	}
}

func TestPutRejections(t *testing.T) {
	long := strings.Repeat("a", 91)
	loc := `{"location":"eastus"}`
	moved := `{"location":"westus"}`
	tests := []struct {
		name     string
		path     string // below sub
		before   string // body of a prior PUT to the same path; "" for none
		body     string
		wantCode string
	}{
		{"no body", "/resourceGroups/dev", "", "", azerr.CodeInvalidRequestContent},
		{"not json", "/resourceGroups/dev", "", "location=eastus", azerr.CodeInvalidRequestContent},
		{"missing location", "/resourceGroups/dev", "", `{"tags":{}}`, azerr.CodeLocationRequired},
		{"location change", "/resourceGroups/dev", loc, moved, azerr.CodeInvalidResourceGroupLocation},
		{"name too long", "/resourceGroups/" + long, "", loc, azerr.CodeInvalidResourceGroupName},
		{"name ends with period", "/resourceGroups/dev.", "", loc, azerr.CodeInvalidResourceGroupName},
		{"name with space", "/resourceGroups/my%20rg", "", loc, azerr.CodeInvalidResourceGroupName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newProvider()
			if tt.before != "" {
				if rec := serve(t, p, http.MethodPut, sub+tt.path, tt.before); rec.Code != http.StatusCreated {
					t.Fatalf("setup PUT: status = %d %s", rec.Code, code(rec))
				}
			}
			rec := serve(t, p, http.MethodPut, sub+tt.path, tt.body)
			if rec.Code != http.StatusBadRequest || code(rec) != tt.wantCode {
				t.Errorf("status = %d code %q, want 400 %s", rec.Code, code(rec), tt.wantCode)
			}
		})
	}
}

func TestPutAccepts(t *testing.T) {
	extra := `{"location":"eastus","managedBy":"x","properties":{}}`
	tests := []struct{ name, path, body string }{
		{"unknown fields ignored", "/resourceGroups/dev", extra},
		{"tags omitted", "/resourceGroups/dev", `{"location":"eastus"}`},
		{"all allowed punctuation", "/resourceGroups/a.b(c)-d_e", `{"location":"eastus"}`},
		{"ninety characters", "/resourceGroups/" + strings.Repeat("a", 90), `{"location":"eastus"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(t, newProvider(), http.MethodPut, sub+tt.path, tt.body)
			if rec.Code != http.StatusCreated {
				t.Errorf("status = %d %s, want 201", rec.Code, code(rec))
			}
		})
	}
}

func TestListScopedAndSorted(t *testing.T) {
	p := newProvider()
	other := "/subscriptions/99999999-9999-9999-9999-999999999999"
	for _, path := range []string{"/resourceGroups/beta", "/resourceGroups/alpha"} {
		serve(t, p, http.MethodPut, sub+path, `{"location":"eastus"}`)
	}
	serve(t, p, http.MethodPut, other+"/resourceGroups/gamma", `{"location":"eastus"}`)

	rec := serve(t, p, http.MethodGet, sub+"/resourceGroups", "")
	var list struct {
		Value []store.Resource `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list body: %v", err)
	}
	var names []string
	for _, r := range list.Value {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "alpha,beta" {
		t.Errorf("list = %v, want [alpha beta]: only this subscription, sorted", names)
	}
}

func TestListEmptyIsArray(t *testing.T) {
	rec := serve(t, newProvider(), http.MethodGet, sub+"/resourceGroups", "")
	if rec.Code != http.StatusOK || rec.Body.String() != `{"value":[]}` {
		t.Errorf("empty list = %d %s, want 200 {\"value\":[]}", rec.Code, rec.Body.String())
	}
}

func TestMethodsNotSupported(t *testing.T) {
	p := newProvider()
	rg := sub + "/resourceGroups/dev"
	serve(t, p, http.MethodPut, rg, `{"location":"eastus"}`)

	tests := []struct{ name, method, path string }{
		{"patch is deferred", http.MethodPatch, rg},
		{"post on the collection", http.MethodPost, sub + "/resourceGroups"},
	}
	for _, tt := range tests {
		rec := serve(t, p, tt.method, tt.path, `{}`)
		if rec.Code != http.StatusMethodNotAllowed || code(rec) != azerr.CodeMethodNotAllowed {
			t.Errorf("%s: status = %d code %q, want 405 MethodNotAllowed", tt.name, rec.Code, code(rec))
		}
	}
}

func TestSubscriptions(t *testing.T) {
	cfg := config.Default()
	p := newProvider()

	rec := serve(t, p, http.MethodGet, "/subscriptions", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d %s, want 200", rec.Code, code(rec))
	}
	var list struct {
		Value []struct {
			ID             string `json:"id"`
			SubscriptionID string `json:"subscriptionId"`
			DisplayName    string `json:"displayName"`
			State          string `json:"state"`
			TenantID       string `json:"tenantId"`
		} `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(list.Value) != 1 {
		t.Fatalf("list = %d subscriptions, want 1", len(list.Value))
	}
	got := list.Value[0]
	if got.ID != sub || got.SubscriptionID != cfg.SubscriptionID || got.TenantID != cfg.TenantID {
		t.Errorf("subscription ids = %+v, want %s under tenant %s", got, sub, cfg.TenantID)
	}
	if got.State != "Enabled" || got.DisplayName != cfg.SubscriptionName {
		t.Errorf("subscription = %+v, want Enabled and named %q", got, cfg.SubscriptionName)
	}

	rec = serve(t, p, http.MethodGet, strings.ToUpper(sub), "")
	if rec.Code != http.StatusOK {
		t.Errorf("get with other casing: status = %d %s, want 200", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodGet, "/subscriptions/99999999-9999-9999-9999-999999999999", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeSubscriptionNotFound {
		t.Errorf("get unknown: status = %d code %q, want 404 SubscriptionNotFound", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPost, "/subscriptions", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("post: status = %d, want 405", rec.Code)
	}
}

func TestTenants(t *testing.T) {
	cfg := config.Default()
	p := newProvider()

	rec := serve(t, p, http.MethodGet, "/tenants", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status = %d %s, want 200", rec.Code, code(rec))
	}
	var list struct {
		Value []struct {
			ID       string `json:"id"`
			TenantID string `json:"tenantId"`
		} `json:"value"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(list.Value) != 1 {
		t.Fatalf("tenants = %+v, want exactly one", list.Value)
	}
	if got := list.Value[0]; got.TenantID != cfg.TenantID || got.ID != "/tenants/"+cfg.TenantID {
		t.Errorf("tenant = %+v, want %s", got, cfg.TenantID)
	}
	rec = serve(t, p, http.MethodGet, "/tenants/"+cfg.TenantID, "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeResourceNotFound {
		t.Errorf("get one tenant: status = %d code %q, want 404 ResourceNotFound", rec.Code, code(rec))
	}
}

func TestUnroutedRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, sub+"/resourceGroups"+v, nil)
	newProvider().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a request that skipped RouteRequest", rec.Code)
	}
}

// serveFilter is serve with a $filter, URL-encoded the way az sends it.
func serveFilter(t *testing.T, p *Provider, path, filter string) *httptest.ResponseRecorder {
	t.Helper()
	target := path + v
	if filter != "" {
		target += "&" + url.Values{"$filter": {filter}}.Encode()
	}
	rec := httptest.NewRecorder()
	gateway.RouteRequest(p).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func TestGenericResourceListing(t *testing.T) {
	p := newProvider()
	rg := sub + "/resourceGroups/dev"
	serve(t, p, http.MethodPut, rg, `{"location":"eastus"}`)
	vault := store.Resource{ID: rg + "/providers/Microsoft.KeyVault/vaults/kv1", Name: "kv1",
		Type: "Microsoft.KeyVault/vaults", Location: "eastus"}
	account := store.Resource{ID: rg + "/providers/Microsoft.Storage/storageAccounts/sa1", Name: "sa1",
		Type: "Microsoft.Storage/storageAccounts", Location: "eastus"}
	for _, res := range []store.Resource{vault, account} {
		if _, err := p.store.Put(res); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	tests := []struct {
		name, path, filter string
		want               []string // names, in order
	}{
		{"everything, groups excluded", sub + "/resources", "", []string{"kv1", "sa1"}},
		{"by type", sub + "/resources", "resourceType eq 'Microsoft.KeyVault/vaults'", []string{"kv1"}},
		{"by type and name, as az keyvault show does", sub + "/resources",
			"resourceType eq 'Microsoft.KeyVault/vaults' and name eq 'KV1'", []string{"kv1"}},
		{"within a group", rg + "/resources", "", []string{"kv1", "sa1"}},
		{"other group: nothing", sub + "/resourceGroups/nope/resources", "", nil},
	}
	for _, tt := range tests {
		rec := serveFilter(t, p, tt.path, tt.filter)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d %s", tt.name, rec.Code, code(rec))
			continue
		}
		var list struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatalf("%s: body: %v", tt.name, err)
		}
		var names []string
		for _, r := range list.Value {
			names = append(names, r.Name)
		}
		if strings.Join(names, ",") != strings.Join(tt.want, ",") {
			t.Errorf("%s: names = %v, want %v", tt.name, names, tt.want)
		}
	}
	rec := serveFilter(t, p, sub+"/resources", "location eq 'eastus'")
	if rec.Code != http.StatusBadRequest || code(rec) != azerr.CodeInvalidFilter {
		t.Errorf("unsupported filter: status = %d code %q, want 400 InvalidFilter", rec.Code, code(rec))
	}
	if rec := serve(t, p, http.MethodGet, sub+"/resources/kv1", ""); rec.Code != http.StatusNotFound {
		t.Errorf("listing member: status = %d, want 404", rec.Code)
	}
}

func TestDeleteGroupCascades(t *testing.T) {
	p := newProvider()
	rg := sub + "/resourceGroups/dev"
	serve(t, p, http.MethodPut, rg, `{"location":"eastus"}`)
	child := store.Resource{ID: rg + "/providers/Microsoft.KeyVault/vaults/kv1", Name: "kv1",
		Type: "Microsoft.KeyVault/vaults"}
	if _, err := p.store.Put(child); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if rec := serve(t, p, http.MethodDelete, rg, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete group: status = %d, want 200", rec.Code)
	}
	if _, err := p.store.Get(child.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("child after group delete: err = %v, want ErrNotFound", err)
	}
}
