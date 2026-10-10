package keyvault

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/config"
	"github.com/ioflux-org/armite/internal/gateway"
	"github.com/ioflux-org/armite/internal/store"
)

const (
	groupType = "Microsoft.Resources/resourceGroups"

	sub    = "/subscriptions/22222222-2222-2222-2222-222222222222"
	tenant = "11111111-1111-1111-1111-111111111111"
	rg     = sub + "/resourceGroups/dev"
	vaults = "/providers/Microsoft.KeyVault/vaults"
	v      = "?api-version=2025-05-01"
)

// azBody is what az keyvault create --enable-rbac-authorization sends,
// captured with --debug.
const azBody = `{"location": "eastus", "properties": {"tenantId": "` + tenant + `", ` +
	`"sku": {"name": "standard", "family": "A"}, "accessPolicies": [], ` +
	`"enableRbacAuthorization": true, "enableSoftDelete": true, "softDeleteRetentionInDays": 90, ` +
	`"networkAcls": {"bypass": "AzureServices", "defaultAction": "Allow"}}}`

// newProvider returns a provider over a store that already holds the
// resource group "dev".
func newProvider(t *testing.T) *Provider {
	t.Helper()
	st := store.New(nil)
	group := store.Resource{ID: rg, Name: "dev", Type: groupType, Location: "eastus"}
	if _, err := st.Put(group); err != nil {
		t.Fatalf("Put group: %v", err)
	}
	return New(config.Default(), st, nil)
}

// serve runs one request through RouteRequest and the provider.
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

func code(rec *httptest.ResponseRecorder) string {
	return rec.Header().Get("x-ms-error-code")
}

func decodeVault(t *testing.T, rec *httptest.ResponseRecorder) vault {
	t.Helper()
	var got vault
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not a vault: %v\n%s", err, rec.Body.String())
	}
	return got
}

func TestVaultLifecycle(t *testing.T) {
	p := newProvider(t)
	id := rg + vaults + "/kv-demo"

	rec := serve(t, p, http.MethodPut, id, azBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d %s %s", rec.Code, code(rec), rec.Body.String())
	}
	got := decodeVault(t, rec)
	if got.ID != id || got.Name != "kv-demo" || got.Type != vaultType || got.Location != "eastus" {
		t.Errorf("create identity = %+v", got)
	}
	pr := got.Properties
	if pr.VaultURI != "https://kv-demo.vault.localhost:8443/" || pr.ProvisioningState != "Succeeded" {
		t.Errorf("create uri/state = %q %q", pr.VaultURI, pr.ProvisioningState)
	}
	if pr.TenantID != tenant || pr.Sku != (sku{Family: "A", Name: "standard"}) {
		t.Errorf("create tenant/sku = %q %+v", pr.TenantID, pr.Sku)
	}
	if pr.EnableRbacAuthorization == nil || !*pr.EnableRbacAuthorization {
		t.Errorf("create enableRbacAuthorization = %v, want true", pr.EnableRbacAuthorization)
	}
	if pr.EnableSoftDelete == nil || !*pr.EnableSoftDelete || pr.PublicNetworkAccess != "Enabled" {
		t.Errorf("create defaults = %+v", pr)
	}
	if pr.SoftDeleteRetentionInDays == nil || *pr.SoftDeleteRetentionInDays != 90 {
		t.Errorf("create softDeleteRetentionInDays = %v, want 90", pr.SoftDeleteRetentionInDays)
	}
	body := rec.Body.String()
	for _, want := range []string{`"tags":{}`, `"accessPolicies":[]`, `"networkAcls":{"bypass":"AzureServices"`} {
		if !strings.Contains(body, want) {
			t.Errorf("create body lacks %s: %s", want, body)
		}
	}

	rec = serve(t, p, http.MethodGet, strings.ToUpper(id), "")
	if rec.Code != http.StatusOK || decodeVault(t, rec).Name != "kv-demo" {
		t.Errorf("get with other casing: status = %d %s", rec.Code, code(rec))
	}

	withTags := `"location": "EastUS", "tags": {"env": "dev"},`
	tagged := strings.Replace(azBody, `"location": "eastus",`, withTags, 1)
	rec = serve(t, p, http.MethodPut, id, tagged)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace: status = %d %s", rec.Code, code(rec))
	}
	if got = decodeVault(t, rec); got.Tags["env"] != "dev" || got.Location != "eastus" {
		t.Errorf("replace = %+v, want tags set and the original location kept", got)
	}

	for _, scope := range []string{rg, sub} {
		rec = serve(t, p, http.MethodGet, scope+vaults, "")
		var list struct {
			Value []vault `json:"value"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &list) != nil {
			t.Fatalf("list at %s: status = %d %s", scope, rec.Code, code(rec))
		}
		if len(list.Value) != 1 {
			t.Errorf("list at %s: %d vaults, want 1", scope, len(list.Value))
		}
	}

	if rec = serve(t, p, http.MethodDelete, id, ""); rec.Code != http.StatusOK {
		t.Errorf("delete: status = %d, want 200", rec.Code)
	}
	rec = serve(t, p, http.MethodGet, id, "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeResourceNotFound {
		t.Errorf("get after delete: status = %d code %q, want 404 ResourceNotFound", rec.Code, code(rec))
	}
	if !strings.Contains(rec.Body.String(), "under resource group 'dev' was not found") {
		t.Errorf("get after delete: message = %s", rec.Body.String())
	}
	if rec = serve(t, p, http.MethodDelete, id, ""); rec.Code != http.StatusNoContent {
		t.Errorf("second delete: status = %d, want 204", rec.Code)
	}
	if rec = serve(t, p, http.MethodPatch, id, `{}`); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("patch: status = %d, want 405", rec.Code)
	}
}

func TestPutRejections(t *testing.T) {
	long := "a" + strings.Repeat("b", 24)
	foreign := strings.Replace(azBody, tenant, "99999999-9999-9999-9999-999999999999", 1)
	badSku := strings.Replace(azBody, `"standard"`, `"gold"`, 1)
	kv1 := rg + vaults + "/kv1"
	tests := []struct {
		name       string
		path       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"no body", kv1, "", 400, azerr.CodeInvalidRequestContent},
		{"missing location", kv1, `{"properties":{}}`, 400, azerr.CodeLocationRequired},
		{"missing properties", kv1, `{"location":"eastus"}`, 400, azerr.CodeInvalidRequestContent},
		{"foreign tenant", kv1, foreign, 400, azerr.CodeInvalidRequestContent},
		{"bad sku", kv1, badSku, 400, azerr.CodeInvalidRequestContent},
		{"name too short", rg + vaults + "/ab", azBody, 400, azerr.CodeVaultNameNotValid},
		{"name too long", rg + vaults + "/" + long, azBody, 400, azerr.CodeVaultNameNotValid},
		{"name starts with digit", rg + vaults + "/1abc", azBody, 400, azerr.CodeVaultNameNotValid},
		{"name ends with hyphen", rg + vaults + "/abc-", azBody, 400, azerr.CodeVaultNameNotValid},
		{"consecutive hyphens", rg + vaults + "/a--b", azBody, 400, azerr.CodeVaultNameNotValid},
		{"group missing", sub + "/resourceGroups/nope" + vaults + "/kv1", azBody, 404,
			azerr.CodeResourceGroupNotFound},
		{"not inside a group", sub + vaults + "/kv1", azBody, 400, azerr.CodeInvalidRequestContent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := serve(t, newProvider(t), http.MethodPut, tt.path, tt.body)
			if rec.Code != tt.wantStatus || code(rec) != tt.wantCode {
				t.Errorf("status = %d code %q, want %d %s", rec.Code, code(rec), tt.wantStatus, tt.wantCode)
			}
		})
	}
}

func TestLocationIsImmutable(t *testing.T) {
	p := newProvider(t)
	id := rg + vaults + "/kv-demo"
	serve(t, p, http.MethodPut, id, azBody)
	moved := strings.Replace(azBody, `"eastus"`, `"westus"`, 1)
	rec := serve(t, p, http.MethodPut, id, moved)
	if rec.Code != http.StatusBadRequest || code(rec) != azerr.CodeInvalidRequestContent {
		t.Errorf("status = %d code %q, want 400 InvalidRequestContent", rec.Code, code(rec))
	}
}

func TestVaultNamesAreGlobal(t *testing.T) {
	p := newProvider(t)
	other := store.Resource{ID: sub + "/resourceGroups/other", Name: "other", Type: groupType, Location: "eastus"}
	if _, err := p.store.Put(other); err != nil {
		t.Fatal(err)
	}
	if rec := serve(t, p, http.MethodPut, rg+vaults+"/kv-demo", azBody); rec.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d %s", rec.Code, code(rec))
	}
	rec := serve(t, p, http.MethodPut, other.ID+vaults+"/KV-Demo", azBody)
	if rec.Code != http.StatusConflict || code(rec) != azerr.CodeVaultAlreadyExists {
		t.Errorf("same name in another group: status = %d code %q, want 409", rec.Code, code(rec))
	}
	if rec := serve(t, p, http.MethodPut, rg+vaults+"/kv-demo", azBody); rec.Code != http.StatusOK {
		t.Errorf("same name, same group: status = %d, want 200 (update)", rec.Code)
	}
}

func TestEmptyCollections(t *testing.T) {
	p := newProvider(t)
	for _, coll := range []string{"deletedVaults", "managedHSMs", "deletedManagedHSMs"} {
		rec := serve(t, p, http.MethodGet, sub+"/providers/Microsoft.KeyVault/"+coll, "")
		if rec.Code != http.StatusOK || rec.Body.String() != `{"value":[]}` {
			t.Errorf("%s = %d %s, want 200 {\"value\":[]}", coll, rec.Code, rec.Body.String())
		}
	}
	rec := serve(t, p, http.MethodGet, sub+"/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/kv1", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeResourceNotFound {
		t.Errorf("get deleted: status = %d code %q, want 404", rec.Code, code(rec))
	}
}

func TestUnknownTypeAndUnrouted(t *testing.T) {
	p := newProvider(t)
	rec := serve(t, p, http.MethodGet, sub+"/providers/Microsoft.KeyVault/hsmPools", "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeInvalidResourceType {
		t.Errorf("unknown type: status = %d code %q, want 404 InvalidResourceType", rec.Code, code(rec))
	}
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, rg+vaults+"/kv-demo"+v, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("unrouted: status = %d, want 500", rec.Code)
	}
}

func TestPurgeIsAFinishedOperation(t *testing.T) {
	p := newProvider(t)
	loc := sub + "/providers/Microsoft.KeyVault/locations/eastus"
	rec := serve(t, p, http.MethodPost, loc+"/deletedVaults/kv1/purge", "")
	location := rec.Header().Get("Location")
	if rec.Code != http.StatusAccepted || rec.Header().Get("Retry-After") != "0" ||
		!strings.HasPrefix(location, "https://management.localhost:8443"+loc+"/operationResults/") {
		t.Fatalf("purge: status = %d Location %q, want 202 + operationResults", rec.Code, location)
	}
	path := strings.TrimPrefix(location, "https://management.localhost:8443")
	path = strings.TrimSuffix(path, v)
	rec = serve(t, p, http.MethodGet, path, "")
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"Succeeded"}` {
		t.Errorf("operationResults = %d %s, want 200 Succeeded", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, loc+"/deletedVaults/kv1/purge", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET purge: status = %d, want 405", rec.Code)
	}
}
