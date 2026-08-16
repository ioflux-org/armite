package router

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/ioflux-org/provisio/internal/config"
)

func TestPlaneDispatch(t *testing.T) {
	rt := New(config.Default(), nil)

	tests := []struct {
		name       string
		host       string
		path       string
		wantStatus int
		wantCode   string
	}{
		{"arm host with port", "management.localhost:8443", "/subscriptions/x?api-version=1", 401, "AuthenticationFailed"},
		{"arm host without port", "management.localhost", "/", 401, "AuthenticationFailed"},
		{"unknown host defaults to arm", "127.0.0.1:8443", "/", 401, "AuthenticationFailed"},
		{"garbage path still 401 not 404", "management.localhost:8443", "/no/such/thing", 401, "AuthenticationFailed"},
		{"login host is a different plane", "login.localhost:8443", "/", 404, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tt.host+tt.path, nil)
			rec := httptest.NewRecorder()
			rt.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantCode == "" {
				return
			}
			if got := rec.Header().Get("x-ms-error-code"); got != tt.wantCode {
				t.Errorf("x-ms-error-code: %q, want %q", got, tt.wantCode)
			}
			var env struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
				t.Fatalf("body is not a JSON envelope: %v", err)
			}
			if env.Error.Code != tt.wantCode {
				t.Errorf("envelop code = %q, want %q", env.Error.Code, tt.wantCode)
			}
		})
	}
}
