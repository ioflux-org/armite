package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ioflux-org/provisio/internal/config"
)

// plane returns a handler that identifies itself, so dispatch can be
// asserted with no real plane behind it.
func plane(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Plane", name)
		w.WriteHeader(http.StatusOK)
	})
}

func TestPlaneDispatch(t *testing.T) {
	rt := New(config.Default(), plane("login"), plane("arm"), plane("vault"))

	tests := []struct {
		name string
		host string
		want string
	}{
		{"arm host with port", "management.localhost:8443", "arm"},
		{"arm host without port", "management.localhost", "arm"},
		{"unknown host defaults to arm", "127.0.0.1:8443", "arm"},
		{"login host is a different plane", "login.localhost:8443", "login"},
		{"login host without port", "login.localhost", "login"},
		{"vault host with port", "kv-demo.vault.localhost:8443", "vault"},
		{"vault host without port", "kv-demo.vault.localhost", "vault"},
		{"bare vault suffix is not a vault", "vault.localhost:8443", "arm"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "https://"+tc.host+"/", nil)
		res := httptest.NewRecorder()
		rt.ServeHTTP(res, req)
		if got := res.Header().Get("X-Plane"); got != tc.want {
			t.Errorf("%s: dispatched to %q, want %q", tc.name, got, tc.want)
		}
	}
}
