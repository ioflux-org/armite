package gateway

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
)

var (
	testKey  = mustTestKey()
	otherKey = mustTestKey()
)

func mustTestKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}

// mintToken obtains a token the way a client does: by posting client
// credentials to an entra handler built on cfg and key. No signing
// shortcut - the gateway is tested against the real issuer.
func mintToken(t *testing.T, cfg config.Config, key *rsa.PrivateKey, scope string) string {
	t.Helper()
	cl := cfg.Clients[0]
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cl.ID},
		"client_secret": {cl.Secret},
		"scope":         {scope},
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/%s/oauth2/v2.0/token", cfg.TenantID),
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	entra.New(cfg, key).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token endpoint status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("token response is not JSON: %v", err)
	}
	return resp.AccessToken
}

func TestAuthenticate(t *testing.T) {
	cfg := config.Default()
	stranger := cfg
	stranger.TenantID = "99999999-9999-9999-9999-999999999999"
	const scope = "https://management.azure.com/.default"

	good := mintToken(t, cfg, testKey, scope)
	foreign := mintToken(t, cfg, otherKey, scope)
	graph := mintToken(t, cfg, testKey, "https://graph.microsoft.com/.default")
	slashy := mintToken(t, cfg, testKey, "https://management.azure.com//.default")
	wrongTenant := mintToken(t, stranger, testKey, scope)
	now := time.Now()

	tests := []struct {
		name     string
		authz    string
		now      time.Time
		wantCode string // x-ms-error-code of the 401; "" means next must be reached
	}{
		{"missing header", "", now, azerr.CodeAuthenticationFailed},
		{"basic scheme", "Basic Zm9v", now, azerr.CodeAuthenticationFailed},
		{"bearer without token", "Bearer ", now, azerr.CodeAuthenticationFailed},
		{"garbage token", "Bearer not.a.jwt", now, azerr.CodeInvalidAuthenticationToken},
		{"signed by another key", "Bearer " + foreign, now, azerr.CodeInvalidAuthenticationToken},
		{"expired", "Bearer " + good, now.Add(2 * time.Hour), azerr.CodeExpiredAuthenticationToken},
		{"not yet valid", "Bearer " + good, now.Add(-time.Hour), azerr.CodeInvalidAuthenticationToken},
		{"wrong audience", "Bearer " + graph, now, azerr.CodeInvalidAuthenticationTokenAudience},
		{"wrong tenant", "Bearer " + wrongTenant, now, azerr.CodeInvalidAuthenticationTokenTenant},
		{"valid token", "Bearer " + good, now, ""},
		{"lowercase scheme", "bearer " + good, now, ""},
		{"az double-slash scope", "Bearer " + slashy, now, ""},
	}

	for _, tc := range tests {
		var got Principal
		reached := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got, reached = FromContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})
		auth := NewAuthenticator(cfg, &testKey.PublicKey, func() time.Time { return tc.now })
		req := httptest.NewRequest(http.MethodGet, "/subscriptions?api-version=2022-12-01", nil)
		if tc.authz != "" {
			req.Header.Set("Authorization", tc.authz)
		}
		rec := httptest.NewRecorder()
		auth.Authenticate(next).ServeHTTP(rec, req)

		if tc.wantCode == "" {
			if !reached || got.ObjectID != cfg.Clients[0].ObjectID {
				t.Errorf("%s: reached  = %v, principal = %+v, want oid %s",
					tc.name, reached, got, cfg.Clients[0].ObjectID)
			}
			continue
		}
		if reached {
			t.Errorf("%s: reached next handler, want 401 with code %q", tc.name, tc.wantCode)
			continue
		}
		code := rec.Header().Get("x-ms-error-code")
		if rec.Code != http.StatusUnauthorized || code != tc.wantCode {
			t.Errorf("%s: status %d code %q, want 401 %s", tc.name, rec.Code, code, tc.wantCode)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s: 401 without WWW-Authenticate challenge", tc.name)
		}
	}
}
