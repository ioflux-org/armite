package storage

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/gateway"
	"github.com/ioflux-org/provisio/internal/store"
)

const (
	groupType = "Microsoft.Resources/resourceGroups"

	sub      = "/subscriptions/22222222-2222-2222-2222-222222222222"
	rg       = sub + "/resourceGroups/dev"
	accounts = "/providers/Microsoft.Storage/storageAccounts"
	v        = "?api-version=2025-08-01"
)

// azBody is what az storage account create --sku Standard_LRS sends,
// captured with --debug.
const azBody = `{"sku": {"name": "Standard_LRS"}, "kind": "StorageV2", "location": "eastus", ` +
	`"properties": {"encryption": {"keySource": "Microsoft.Storage", "services": {"blob": {}}}}}`

// newProvider returns a managed-mode provider with no Azurite to run
// (a nil manager: keys are generated, nothing is restarted) over a store
// that already holds the resource group "dev".
func newProvider(t *testing.T, cfg config.Config) *Provider {
	t.Helper()
	st := store.New(nil)
	group := store.Resource{ID: rg, Name: "dev", Type: groupType, Location: "eastus"}
	if _, err := st.Put(group); err != nil {
		t.Fatalf("Put group: %v", err)
	}
	p, err := New(cfg, st, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
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

func decodeAccount(t *testing.T, rec *httptest.ResponseRecorder) account {
	t.Helper()
	var got account
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not an account: %v\n%s", err, rec.Body.String())
	}
	return got
}

func prop(t *testing.T, a account, name string) any {
	t.Helper()
	var out any
	if err := json.Unmarshal(a.Properties[name], &out); err != nil {
		t.Fatalf("property %s = %s: %v", name, a.Properties[name], err)
	}
	return out
}

func TestAccountLifecycle(t *testing.T) {
	p := newProvider(t, config.Default())
	id := rg + accounts + "/stdemo"

	rec := serve(t, p, http.MethodPut, id, azBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: status = %d %s %s", rec.Code, code(rec), rec.Body.String())
	}
	got := decodeAccount(t, rec)
	if got.ID != id || got.Name != "stdemo" || got.Type != accountType || got.Kind != "StorageV2" ||
		got.Sku.Name != "Standard_LRS" || got.Sku.Tier != "Standard" {
		t.Errorf("create: envelope = %+v", got)
	}
	if prop(t, got, "provisioningState") != "Succeeded" ||
		prop(t, got, "allowSharedKeyAccess") != true ||
		prop(t, got, "minimumTlsVersion") != "TLS1_2" {
		t.Errorf("create: defaults not applied: %s", rec.Body.String())
	}
	endpoints := prop(t, got, "primaryEndpoints").(map[string]any)
	if endpoints["blob"] != "https://stdemo.blob.localhost:8443/" || endpoints["queue"] != nil {
		t.Errorf("create: primaryEndpoints = %v, want the blob endpoint only", endpoints)
	}
	if enc := prop(t, got, "encryption").(map[string]any); enc["keySource"] != "Microsoft.Storage" {
		t.Errorf("create: the client's properties must be kept: %v", enc)
	}
	// A second PUT is an update: 200, location kept, properties merged.
	rec = serve(t, p, http.MethodPut, id, `{"location":"eastus","sku":{"name":"Standard_GRS"},`+
		`"properties":{"allowSharedKeyAccess":false},"tags":{"env":"dev"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update: status = %d %s", rec.Code, rec.Body.String())
	}
	got = decodeAccount(t, rec)
	if got.Sku.Name != "Standard_GRS" || prop(t, got, "allowSharedKeyAccess") != false ||
		prop(t, got, "minimumTlsVersion") != "TLS1_2" || got.Tags["env"] != "dev" {
		t.Errorf("update: %+v", got)
	}
	rec = serve(t, p, http.MethodPut, id, `{"location":"westus","sku":{"name":"Standard_LRS"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("moving an account: status = %d, want 400", rec.Code)
	}

	// PATCH: tags and one property, nothing else touched.
	rec = serve(t, p, http.MethodPatch, id,
		`{"tags":{"env":"test"},"properties":{"accessTier":"Cool"}}`)
	got = decodeAccount(t, rec)
	if rec.Code != http.StatusOK || got.Tags["env"] != "test" ||
		prop(t, got, "accessTier") != "Cool" || got.Sku.Name != "Standard_GRS" {
		t.Errorf("patch: status %d, %+v", rec.Code, got)
	}

	rec = serve(t, p, http.MethodGet, id, "")
	if rec.Code != http.StatusOK || decodeAccount(t, rec).Name != "stdemo" {
		t.Errorf("get: status = %d %s", rec.Code, rec.Body.String())
	}
	for _, scope := range []string{sub, rg} {
		rec = serve(t, p, http.MethodGet, scope+accounts, "")
		var list struct{ Value []account }
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list.Value) != 1 {
			t.Errorf("list at %s: status %d, %s", scope, rec.Code, rec.Body.String())
		}
	}

	rec = serve(t, p, http.MethodPost, id+"/listKeys", "")
	var keys struct{ Keys []keyEntry }
	if err := json.Unmarshal(rec.Body.Bytes(), &keys); err != nil || rec.Code != http.StatusOK ||
		len(keys.Keys) != 2 || keys.Keys[0].KeyName != "key1" || keys.Keys[1].KeyName != "key2" {
		t.Fatalf("listKeys: status %d, %s", rec.Code, rec.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(keys.Keys[0].Value)
	if err != nil || len(raw) != 64 || keys.Keys[0].Value == keys.Keys[1].Value {
		t.Errorf("keys must be two distinct 64-byte base64 values: %+v", keys.Keys)
	}
	rec = serve(t, p, http.MethodPost, id+"/regenerateKey", `{"keyName":"key2"}`)
	var regen struct{ Keys []keyEntry }
	json.Unmarshal(rec.Body.Bytes(), &regen)
	if rec.Code != http.StatusOK || regen.Keys[0].Value != keys.Keys[0].Value ||
		regen.Keys[1].Value == keys.Keys[1].Value {
		t.Errorf("regenerateKey key2: status %d, key1 kept = %v, key2 changed = %v", rec.Code,
			regen.Keys[0].Value == keys.Keys[0].Value, regen.Keys[1].Value != keys.Keys[1].Value)
	}

	rec = serve(t, p, http.MethodDelete, id, "")
	if rec.Code != http.StatusOK {
		t.Errorf("delete: status = %d", rec.Code)
	}
	rec = serve(t, p, http.MethodDelete, id, "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete again: status = %d, want 204", rec.Code)
	}
	rec = serve(t, p, http.MethodGet, id, "")
	if rec.Code != http.StatusNotFound || code(rec) != azerr.CodeResourceNotFound {
		t.Errorf("get after delete: status = %d %s", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPost, id+"/listKeys", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("listKeys after delete: status = %d, want 404", rec.Code)
	}
}

func TestAccountValidation(t *testing.T) {
	p := newProvider(t, config.Default())
	tests := []struct {
		name, id, body string
		status         int
		code           string
	}{
		{"no group", sub + "/resourceGroups/nope" + accounts + "/stdemo", azBody,
			http.StatusNotFound, azerr.CodeResourceGroupNotFound},
		{"bad name", rg + accounts + "/St-Demo", azBody,
			http.StatusBadRequest, "AccountNameInvalid"},
		{"no location", rg + accounts + "/stdemo", `{"sku":{"name":"Standard_LRS"}}`,
			http.StatusBadRequest, azerr.CodeLocationRequired},
		{"no sku", rg + accounts + "/stdemo", `{"location":"eastus"}`,
			http.StatusBadRequest, azerr.CodeInvalidRequestContent},
		{"patch of a missing account", rg + accounts + "/stdemo", `{"tags":{}}`,
			http.StatusNotFound, azerr.CodeResourceNotFound},
	}
	for _, tc := range tests {
		method := http.MethodPut
		if strings.HasPrefix(tc.name, "patch") {
			method = http.MethodPatch
		}
		rec := serve(t, p, method, tc.id, tc.body)
		if rec.Code != tc.status || code(rec) != tc.code {
			t.Errorf("%s: status = %d %s, want %d %s", tc.name, rec.Code, code(rec),
				tc.status, tc.code)
		}
	}

	// Names are global: a second group cannot reuse one.
	rec := serve(t, p, http.MethodPut, rg+accounts+"/stdemo", azBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	other := store.Resource{ID: sub + "/resourceGroups/other", Name: "other",
		Type: groupType, Location: "eastus"}
	p.store.Put(other)
	rec = serve(t, p, http.MethodPut, sub+"/resourceGroups/other"+accounts+"/stdemo", azBody)
	if rec.Code != http.StatusConflict || code(rec) != "StorageAccountAlreadyTaken" {
		t.Errorf("same name in another group: status = %d %s", rec.Code, code(rec))
	}
}

func TestCheckNameAvailability(t *testing.T) {
	p := newProvider(t, config.Default())
	serve(t, p, http.MethodPut, rg+accounts+"/sttaken", azBody)
	path := sub + "/providers/Microsoft.Storage/checkNameAvailability"
	for _, tc := range []struct {
		name, reason string
		available    bool
	}{
		{"stfree", "", true},
		{"sttaken", "AlreadyExists", false},
		{"Bad_Name", "AccountNameInvalid", false},
	} {
		rec := serve(t, p, http.MethodPost, path,
			`{"name":"`+tc.name+`","type":"Microsoft.Storage/storageAccounts"}`)
		var got struct {
			NameAvailable bool   `json:"nameAvailable"`
			Reason        string `json:"reason"`
		}
		json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got.NameAvailable != tc.available ||
			got.Reason != tc.reason {
			t.Errorf("%s: status %d, %+v, want available=%v reason=%q", tc.name, rec.Code, got,
				tc.available, tc.reason)
		}
	}
}

func TestByoAccountsAreTheConfiguredOnes(t *testing.T) {
	cfg := config.Default()
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 64)))
	cfg.Azurite = config.Azurite{Mode: "byo", Upstream: "http://127.0.0.1:1",
		Accounts: []config.StorageAccount{{Name: "stbyo", Key: key}}}
	p := newProvider(t, cfg)

	rec := serve(t, p, http.MethodPut, rg+accounts+"/stother", azBody)
	if rec.Code != http.StatusBadRequest || code(rec) != "StorageAccountNotConfigured" {
		t.Errorf("unknown byo account: status = %d %s", rec.Code, code(rec))
	}
	rec = serve(t, p, http.MethodPut, rg+accounts+"/stbyo", azBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("configured byo account: status = %d %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodPost, rg+accounts+"/stbyo/listKeys", "")
	var keys struct{ Keys []keyEntry }
	json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys.Keys) != 2 || keys.Keys[0].Value != key || keys.Keys[1].Value != key {
		t.Errorf("byo listKeys must hand out the configured key twice: %+v", keys.Keys)
	}
	rec = serve(t, p, http.MethodPost, rg+accounts+"/stbyo/regenerateKey", `{"keyName":"key1"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("byo keys cannot be regenerated: status = %d", rec.Code)
	}
}

func TestOtherServicesAnswerDefaults(t *testing.T) {
	p := newProvider(t, config.Default())
	id := rg + accounts + "/stdemo"
	serve(t, p, http.MethodPut, id, azBody)
	for _, svc := range []string{"fileServices", "queueServices", "tableServices"} {
		rec := serve(t, p, http.MethodGet, id+"/"+svc+"/default", "")
		var got struct {
			Name       string         `json:"name"`
			Type       string         `json:"type"`
			Properties map[string]any `json:"properties"`
		}
		json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != http.StatusOK || got.Name != "default" || got.Properties["cors"] == nil ||
			!strings.EqualFold(got.Type, "Microsoft.Storage/storageAccounts/"+svc) {
			t.Errorf("%s: status %d, %s", svc, rec.Code, rec.Body.String())
		}
		rec = serve(t, p, http.MethodGet, id+"/"+svc, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"value":[{`) {
			t.Errorf("%s list: status %d, %s", svc, rec.Code, rec.Body.String())
		}
	}
	rec := serve(t, p, http.MethodPut, id+"/blobServices/default",
		`{"properties":{"deleteRetentionPolicy":{"enabled":true,"days":7}}}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"days":7`) {
		t.Errorf("blob service PUT: status %d, %s", rec.Code, rec.Body.String())
	}
	rec = serve(t, p, http.MethodGet, id+"/blobServices/default", "")
	body := rec.Body.String()
	if !strings.Contains(body, `"days":7`) ||
		!strings.Contains(body, `"isVersioningEnabled":false`) {
		t.Errorf("blob service GET must merge the PUT over the defaults: %s", rec.Body.String())
	}
}
