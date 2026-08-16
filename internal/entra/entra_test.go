package entra

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/config"
)

var testKey = mustTestKey()

func mustTestKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

func TestDiscoveryDocument(t *testing.T) {
	cfg := config.Default()
	h := New(cfg, testKey)
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
	h := New(cfg, testKey)
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
	h := New(cfg, testKey)
	req := httptest.NewRequest("POST", "https://login.localhost:8443/"+cfg.TenantID+"/v2.0/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 405 {
		t.Errorf("status = %d, want 405 (the GET-prefixed mux pattern should reject POST)", rec.Code)
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	cfg := config.Default()
	h := New(cfg, testKey)
	req := httptest.NewRequest("GET", "https://login.localhost:8443/"+cfg.TenantID+"/discovery/v2.0/keys", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age") {
		t.Errorf("Cache-Control = %q, want a max-age", cc)
	}

	var set struct {
		Keys []struct {
			Kty, Use, Kid, Alg, N, E string
		} `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Kty != "RSA" || k.Use != "sig" || k.Alg != "RS256" {
		t.Errorf("kty/use/alg = %s/%s/%s, want RSA/sig/RS256", k.Kty, k.Use, k.Alg)
	}
	if k.E != "AQAB" {
		t.Errorf("e = %q, want AQAB (65537 base64url)", k.E)
	}
	if k.Kid == "" || k.Kid != keyID(&testKey.PublicKey) {
		t.Errorf("kid = %q, want stable deriavtion from the key", k.Kid)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		t.Fatalf("n is not base64url: %v", err)
	}
	if got := new(big.Int).SetBytes(nBytes); got.Cmp(testKey.N) != 0 {
		t.Errorf("decoded modulus does not match the signing key")
	}
}
