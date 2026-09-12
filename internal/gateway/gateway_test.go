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

// TestGatewayPipeline pins the assembled pipeline end to end: the M0
// acceptance (anonymous -> 401 whatever the path)
func TestGatewayPipeline(t *testing.T) {
	cfg := config.Default()

	registry := NewRegistry()
	registry.Register("Microsoft.Resources", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"reached": "Microsoft.Resources"})
	}))
	g := New(cfg, &testKey.PublicKey, time.Now, newChecker(t, SeedAssignments(cfg)), registry) //  newChecker defined in authz_test.go                              // testKey is declared in authn_test.go
	token := mintToken(t, cfg, testKey, "https://management.azure.com/.default")               // mintToken is declared in authn_test.go
	miToken := mintIMDSToken(t, cfg, testKey)

	const v = "?api-version=2022-12-01"
	sub := "/subscriptions/" + cfg.SubscriptionID
	ra := sub + "/providers/Microsoft.Authorization/roleAssignments/ra-1"
	nope := sub + "/resourceGroups/dev/providers/Microsoft.Nope/things/x"

	tests := []struct {
		name       string
		method     string
		path       string
		token      string
		wantStatus int
		wantCode   string
	}{
		{"anonymous", http.MethodGet, "/subscriptions" + v, "", 401, azerr.CodeAuthenticationFailed},
		{"anonymous garbage path is 401 not 404", http.MethodGet, "/no/such/thing", "", 401, azerr.CodeAuthenticationFailed},
		{"subscription list reaches the provider", http.MethodGet, "/subscriptions" + v, token, 200, ""},
		{"owner group write reaches the provider", http.MethodPut, sub + "/resourceGroups/dev" + v, token, 200, ""},
		{"owner write to unknown namespace", http.MethodPut, nope + v, token, 404, azerr.CodeInvalidResourceNamespace},
		{"contributor role grant is forbidden", http.MethodPut, ra + v, miToken, 403, azerr.CodeAuthorizationFailed},
		{"missing api-version after authentication", http.MethodGet, "/subscriptions", token, 400, azerr.CodeMissingApiVersionParameter},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, "https://management.localhost:8443"+tc.path, nil)
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
