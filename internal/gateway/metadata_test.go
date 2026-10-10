package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ioflux-org/armite/internal/azerr"
	"github.com/ioflux-org/armite/internal/config"
)

func TestEndpointsDocuments(t *testing.T) {
	cfg := config.Default()
	h := serveEndpoints(cfg)
	get := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}

	rec := get("/metadata/endpoints?api-version=2022-09-01")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var doc struct {
		Name           string `json:"name"`
		Authentication struct {
			LoginEndpoint string   `json:"loginEndpoint"`
			Audiences     []string `json:"audiences"`
			Tenant        string   `json:"tenant"`
		} `json:"authentication"`
		ResourceManager string            `json:"resourceManager"`
		Graph           string            `json:"microsoftGraphResourceId"`
		Suffixes        map[string]string `json:"suffixes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if doc.Name != "Armite" || doc.Authentication.Tenant != "common" {
		t.Errorf("name/tenant = %q/%q", doc.Name, doc.Authentication.Tenant)
	}
	// az, the SDKs and Terraform build "{account}.blob." + this suffix.
	if doc.Suffixes["storage"] != "core.localhost:8443" {
		t.Errorf("suffixes.storage = %q, want core.localhost:8443", doc.Suffixes["storage"])
	}
	if doc.Authentication.LoginEndpoint != "https://login.localhost:8443/" {
		t.Errorf("loginEndpoint = %q", doc.Authentication.LoginEndpoint)
	}
	aud := doc.Authentication.Audiences
	if len(aud) != 1 || aud[0] != "https://management.azure.com/" {
		t.Errorf("audiences = %v", aud)
	}
	if doc.ResourceManager != "https://management.localhost:8443/" {
		t.Errorf("resourceManager = %q", doc.ResourceManager)
	}
	if doc.Graph != doc.ResourceManager {
		t.Errorf("microsoftGraphResourceId = %q, want the ARM host %q", doc.Graph, doc.ResourceManager)
	}
	if doc.Suffixes["keyVaultDns"] != "vault.localhost:8443" {
		t.Errorf("suffixes.keyVaultDns = %q, want vault.localhost:8443", doc.Suffixes["keyVaultDns"])
	}

	rec = get("/metadata/endpoints?api-version=2019-05-01")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Body.String(), `[{`) {
		t.Errorf("2019-05-01: status = %d body %s, want a list", rec.Code, rec.Body.String())
	}

	rec = get("/metadata/endpoints")
	got := rec.Header().Get("x-ms-error-code")
	if rec.Code != http.StatusBadRequest || got != azerr.CodeMissingApiVersionParameter {
		t.Errorf("missing api-version: status = %d code %q", rec.Code, got)
	}

	rec = httptest.NewRecorder()
	post := httptest.NewRequest(http.MethodPost, "/metadata/endpoints?api-version=2022-09-01", nil)
	h.ServeHTTP(rec, post)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status = %d, want 405", rec.Code)
	}
}
