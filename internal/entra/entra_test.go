package entra

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/config"
)

func TestDiscoveryDocument(t *testing.T) {
	cfg := config.Default()
	h := New(cfg)
	path := "/" + cfg.TenantID + "/v2.0/.well-known/openid-configuration"
	req := httptest.NewRequest("GET", "https://"+cfg.LoginHost+":8443"+path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var doc struct {
		Issuer        string   `json:"issuer"`
		TokenEndpoint string   `json:"token_endpoint"`
		JWKSURI       string   `json:"jwks_uri"`
		Algs          []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	wantIssuer := cfg.LoginBaseURL() + "/" + cfg.TenantID + "/v2.0"
	if doc.Issuer != wantIssuer {
		t.Errorf("issuer = %q, want %q", doc.Issuer, wantIssuer)
	}
	wantHost := strings.TrimPrefix(cfg.LoginBaseURL(), "https://")
	for name, raw := range map[string]string{"token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Errorf("%s = %q, not a valid URL: %v", name, raw, err)
			continue
		}
		if u.Scheme != "https" || u.Host != wantHost {
			t.Errorf("%s = %q, want https on host %q", name, raw, wantHost)
		}
	}
	if len(doc.Algs) != 1 || doc.Algs[0] != "RS256" {
		t.Errorf("signing algs = %v, want [RS256]", doc.Algs)
	}
}

func TestDiscoveryUnknownTenant(t *testing.T) {
	cfg := config.Default()
	h := New(cfg)
	req := httptest.NewRequest("GET", "https://login.localhost:8443/99999999-9999-9999-9999-999999999999/v2.0/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var oe struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &oe); err != nil {
		t.Fatalf("body not = JSON: %v", err)
	}
	if oe.Error != "invalid_request" {
		t.Errorf("error = %q, want invalid_request", oe.Error)
	}
	if !strings.Contains(oe.ErrorDescription, "AADSTS90002") {
		t.Errorf("error_description = %q, want AADSTS90002 mentioned", oe.ErrorDescription)
	}
}

func TestDiscoveryRejectsWrongMethod(t *testing.T) {
	cfg := config.Default()
	h := New(cfg)
	req := httptest.NewRequest("POST", "https://login.localhost:8443/"+cfg.TenantID+"/v2.0/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 405 {
		t.Errorf("status = %d, want 405 (the GET-prefixed mux pattern should reject POST)", rec.Code)
	}
}
