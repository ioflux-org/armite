package entra

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ioflux-org/provisio/internal/config"
)

var testKey = mustTestKey()

const imdsQuery = "?api-version=2018-02-01&resource=https://management.azure.com/"

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

func TestTokenHappyPath(t *testing.T) {
	cfg := config.Default()
	h := New(cfg, testKey)
	rec := postToken(t, h, validForm(cfg))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var resp struct {
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if resp.TokenType != "Bearer" || resp.ExpiresIn <= 0 || resp.AccessToken == "" {
		t.Fatalf("response = %+v, want Bearer/positive expiry/non-empty token", resp)
	}
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	hdrJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header is not base64url: %v", err)
	}
	var hdr struct {
		Alg,
		Kid,
		Typ string
	}
	if err := json.Unmarshal(hdrJSON, &hdr); err != nil {
		t.Fatalf("header is not JSON: %v", err)
	}
	if hdr.Alg != "RS256" || hdr.Typ != "JWT" || hdr.Kid != keyID(&testKey.PublicKey) {
		t.Errorf("header = %+v, want RS256/JWT/matching kid", hdr)
	}

	c, err := VerifyToken(&testKey.PublicKey, resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	wantIss := cfg.LoginBaseURL() + "/" + cfg.TenantID + "/v2.0"
	if c.Issuer != wantIss {
		t.Errorf("iss = %q, want %q (must byte-match discovery issuer)", c.Issuer, wantIss)
	}
	if c.Audience != "https://management.azure.com" {
		t.Errorf("aud = %q, want https://management.azure.com", c.Audience)
	}
	cl := cfg.Clients[0]
	if c.ObjectID != cl.ObjectID || c.Subject != cl.ObjectID || c.AppID != cl.ID || c.TenantID != cfg.TenantID {
		t.Errorf("identity claims = oid %q sub %q appid %q tid %q; want %q %q %q %q",
			c.ObjectID, c.Subject, c.AppID, c.TenantID, cl.ObjectID, cl.ObjectID, cl.ID, cfg.TenantID)
	}
	if c.ExpiresAt-c.IssuedAt != int64(tokenLifetime.Seconds()) {
		t.Errorf("exp-iat = %d, want %d", c.ExpiresAt-c.IssuedAt, int64(tokenLifetime.Seconds()))
	}
}

func TestTokenRejections(t *testing.T) {
	cfg := config.Default()
	h := New(cfg, testKey)
	tests := []struct {
		name       string
		mutate     func(url.Values)
		wantStatus int
		wantError  string
	}{
		{"wrong secret", func(f url.Values) { f.Set("client_secret", "nope") }, 401, "invalid_client"},
		{"unknown client", func(f url.Values) { f.Set("client_id", "55555555-5555-5555-5555-555555555555") }, 401, "unauthorized_client"},
		{"wrong grant", func(f url.Values) { f.Set("grant_type", "password") }, 400, "unsupported_grant_type"},
		{"missing scope", func(f url.Values) { f.Del("scope") }, 400, "invalid_request"},
		{"blank scope", func(f url.Values) { f.Set("scope", "   ") }, 400, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := validForm(cfg)
			tt.mutate(form)
			rec := postToken(t, h, form)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body %s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			var oe struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &oe); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if oe.Error != tt.wantError {
				t.Errorf("error = %q, want %q", oe.Error, tt.wantError)
			}
		})
	}
}

func TestTamperedTokenFailsVerification(t *testing.T) {
	cfg := config.Default()
	h := New(cfg, testKey)
	rec := postToken(t, h, validForm(cfg))
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	parts := strings.Split(resp.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"oid":"attacker"}`))
	tampered := parts[0] + "." + forged + "." + parts[2]
	if _, err := VerifyToken(&testKey.PublicKey, tampered); err == nil {
		t.Errorf("VerifyToken accepted a token with forged claims")
	}
}

func TestIMDSHappyPath(t *testing.T) {
	cfg := config.Default()
	s := NewIMDS(cfg, testKey)
	rec := imdsGet(t, s, imdsQuery, true)
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
	// String-typed fields pin IMDS's legacy wire format: a JSON number in any
	// of these fails to unmarshal.
	var resp struct {
		AccessToken string `json:"access_token"`
		ClientID    string `json:"client_id"`
		ExpiresIn   string `json:"expires_in"`
		ExpiresOn   string `json:"expires_on"`
		Resource    string `json:"resource"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not the IMDS JSON shape: %v", err)
	}
	mi := cfg.ManagedIdentity
	if resp.TokenType != "Bearer" || resp.Resource != "https://management.azure.com/" || resp.ClientID != mi.ClientID || resp.AccessToken == "" {
		t.Fatalf("response = %+v, want Bearer / echoed resource / configured client_id / token", resp)
	}
	if _, err := strconv.ParseInt(resp.ExpiresIn, 10, 64); err != nil {
		t.Errorf("expires_in = %q, not an integer string: %v", resp.ExpiresIn, err)
	}
	expiresOn, err := strconv.ParseInt(resp.ExpiresOn, 10, 64)
	if err != nil {
		t.Fatalf("expires_on = %q, not an integer string: %v", resp.ExpiresOn, err)
	}

	c, err := VerifyToken(&testKey.PublicKey, resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if c.ExpiresAt != expiresOn {
		t.Errorf("expires_on = %d, want token exp %d", expiresOn, c.ExpiresAt)
	}
	if c.Audience != "https://management.azure.com" {
		t.Errorf("aud = %q, want resource without trailing slash", c.Audience)
	}
	if c.ObjectID != mi.ObjectID || c.Subject != mi.ObjectID || c.AppID != mi.ClientID {
		t.Errorf("identity claims = oid %q sub %q appid %q; want %q %q %q",
			c.ObjectID, c.Subject, c.AppID, mi.ObjectID, mi.ObjectID, mi.ClientID)
	}
}

func TestIMDSRejections(t *testing.T) {
	cfg := config.Default()
	s := NewIMDS(cfg, testKey)
	tests := []struct {
		name     string
		query    string
		metadata bool
	}{
		{"sdk probe: no header, no query", "", false},
		{"no header", imdsQuery, false},
		{"missing resource", "?api-version=2018-02-01", true},
		{"missing api-version", "?resource=https://management.azure.com/", true},
		{"unknown client_id", imdsQuery + "&client_id=77777777-7777-7777-7777-777777777777", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := imdsGet(t, s, tt.query, tt.metadata)
			if rec.Code != 400 {
				t.Errorf("status = %d, want 400; body %s", rec.Code, rec.Body.String())
			}
			var oe struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &oe); err != nil {
				t.Fatalf("body is not JSON: %v", err)
			}
			if oe.Error != "invalid_request" {
				t.Errorf("error = %q, want invalid_request", oe.Error)
			}
		})
	}
}

func TestIMDSRejectsPost(t *testing.T) {
	cfg := config.Default()
	s := NewIMDS(cfg, testKey)
	req := httptest.NewRequest("POST", "http://169.254.169.254"+imdsTokenPath+imdsQuery, nil)
	req.Header.Set("MetaData", "true")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 405 {
		t.Errorf("status = %d, want 405", rec.Code)
	}
}

func TestIMDSAcceptsTrailingSlash(t *testing.T) {
	// MSAL Node requests ".../token/" — what the SDK sends is the contract,
	// not what the docs say.
	s := NewIMDS(config.Default(), testKey)
	req := httptest.NewRequest("GET", "http://169.254.169.254"+imdsTokenPath+"/"+imdsQuery, nil)
	req.Header.Set("Metadata", "true")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200; body %s", rec.Code, rec.Body.String())
	}
}

func postToken(t *testing.T, h *Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	cfg := config.Default()
	req := httptest.NewRequest("POST", "https://"+cfg.LoginHost+":8443/"+cfg.TenantID+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func validForm(cfg config.Config) url.Values {
	cl := cfg.Clients[0]
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {cl.Secret},
		"scope":         {"https://management.azure.com/.default"},
	}
}

func imdsGet(t *testing.T, s *IMDS, query string, metadata bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "http://169.254.169.254"+imdsTokenPath+query, nil)
	if metadata {
		req.Header.Set("Metadata", "true")
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}
