package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ioflux-org/provisio/internal/arm"
	"github.com/ioflux-org/provisio/internal/azerr"
)

type describing struct {
	http.Handler
	types []ResourceType
}

func (d describing) ResourceTypes() []ResourceType { return d.types }

// provider is a spy handler that stamps its name on the response, the
// same trick router_test.go plays with planes.
func provider(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Provider", name)
		w.WriteHeader(http.StatusOK)
	})
}

// routed builds a request the way RouteRequest leaves it: parsed ID in
// the context. The registry never sees an unrouted request in the
// pipeline; the one test that sends one checks the fail-closed path.
func routed(t *testing.T, method, path string) *http.Request {
	t.Helper()
	id, err := arm.ParseResourceID(path)
	if err != nil {
		t.Fatalf("ParseResourceID(%s): %v", path, err)
	}
	req := httptest.NewRequest(method, path+"?api-version=2022-12-01", nil)
	return req.WithContext(withRoute(req.Context(), Route{ID: id}))
}

func TestRegistryDispatch(t *testing.T) {
	reg := NewRegistry()
	reg.Register("Microsoft.Resources", provider("resources"))
	reg.Register("Microsoft.KeyVault", provider("keyvault"))

	const rg = "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/dev"
	tests := []struct {
		name         string
		path         string
		wantProvider string // "" means no provider: expect the 404
	}{
		{"provider route", rg + "/providers/Microsoft.KeyVault/vaults/v1", "keyvault"},
		{"namespace case-insensitive", rg + "/providers/MICROSOFT.keyvault/vaults/v1", "keyvault"},
		{"native route reaches Microsoft.Resources", rg, "resources"},
		{"unknown namespace", rg + "/providers/Microsoft.Nope/things/x", ""},
	}
	for _, tc := range tests {
		rec := httptest.NewRecorder()
		reg.ServeHTTP(rec, routed(t, http.MethodGet, tc.path))

		if tc.wantProvider != "" {
			if got := rec.Header().Get("X-Provider"); got != tc.wantProvider {
				t.Errorf("%s: reached %q, want %q", tc.name, got, tc.wantProvider)
			}
			continue
		}
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404", tc.name, rec.Code)
		}
		if got := rec.Header().Get("x-ms-error-code"); got != azerr.CodeInvalidResourceNamespace {
			t.Errorf("%s: x-ms-error-code = %q, want %q", tc.name, got, azerr.CodeInvalidResourceNamespace)
		}
	}
}

func TestRegistryUnroutedRequest(t *testing.T) {
	reg := NewRegistry()
	reg.Register("Microsoft.Resources", provider("resources"))
	rec := httptest.NewRecorder()
	reg.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/subscriptions", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 for a request that skipped RouteRequest", rec.Code)
	}
	if got := rec.Header().Get("X-Provider"); got != "" {
		t.Errorf("unrouted request reached provider %q", got)
	}
}

func TestRegisterTwicePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("second Register did not panic")
		}
	}()
	reg := NewRegistry()
	reg.Register("Microsoft.Resources", provider("a"))
	reg.Register("microsoft.resources", provider("b"))
}

func TestRegistryCatalog(t *testing.T) {
	reg := NewRegistry()
	reg.Register("Microsoft.Resources", provider("resources"))
	reg.Register("Microsoft.KeyVault", describing{provider("keyvault"),
		[]ResourceType{{Type: "vaults", APIVersions: []string{"2025-05-01"}}}})
	reg.Register("Microsoft.Authorization", provider("authorization"))

	got := reg.Catalog()
	if len(got) != 3 || got[0].Namespace != "Microsoft.Authorization" ||
		got[1].Namespace != "Microsoft.KeyVault" || got[2].Namespace != "Microsoft.Resources" {
		t.Fatalf("Catalog = %+v, want three namespaces sorted", got)
	}
	if len(got[1].Types) != 1 || got[1].Types[0].Type != "vaults" {
		t.Errorf("KeyVault types = %+v, want the described vaults type", got[1].Types)
	}
	if len(got[0].Types) != 0 {
		t.Errorf("a provider without ResourceTypes must list no types, got %+v", got[0].Types)
	}
}
