package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
)

// TestGatewayPipeline pins the M0 acceptance on the assembled pipeline:
// an anonymous request gets 401 whatever the path, and an authenticated
// one reaches the placeholder.
func TestGatewayPipeline(t *testing.T) {
	cfg := config.Default()
	g := New(cfg, &testKey.PublicKey, time.Now)                                  // testKey is declared in authn_test.go
	token := mintToken(t, cfg, testKey, "https://management.azure.com/.default") // mintToken is declared in authn_test.go

	tests := []struct {
		name       string
		path       string
		token      string
		wantStatus int
		wantCode   string
	}{
		{"anonymous", "/subscriptions?api-version=2022-12-01", "", 401, azerr.CodeAuthenticationFailed},
		{"anonymous garbage path is 401 not 404", "/no/such/thing", "", 401, azerr.CodeAuthenticationFailed},
		{"authenticated reaches placeholder", "/subscriptions?api-version=2022-12-01", token, 404, azerr.CodeResourceNotFound},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "https://management.localhost:8443"+tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)

		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d", tc.name, rec.Code, tc.wantStatus)
		}
		var env struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s: body is not a JSON envelope: %v", tc.name, err)
		}
		header := rec.Header().Get("x-ms-error-code")
		if env.Error.Code != tc.wantCode || header != tc.wantCode {
			t.Errorf("%s: code = %q (header %q), want %q", tc.name, env.Error.Code, header, tc.wantCode)
		}
	}
}
