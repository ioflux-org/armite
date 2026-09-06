package gateway

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ioflux-org/provisio/internal/azerr"
	"github.com/ioflux-org/provisio/internal/config"
	"github.com/ioflux-org/provisio/internal/entra"
	"github.com/ioflux-org/provisio/internal/rbac"
)

// builtinDefs is parsed once for the package: the seed is 1.6 MB and the
// authorization table builds a checker per row.
var builtinDefs = mustLoadDefs()

func mustLoadDefs() map[string]rbac.RoleDefinition {
	defs, err := rbac.LoadBuiltinRoles()
	if err != nil {
		panic(err)
	}
	return defs
}

// mintIMDSToken obtains the managed identity's token from the real IMDS
// handler, the way an SDK inside a VM would.
func mintIMDSToken(t *testing.T, cfg config.Config, key *rsa.PrivateKey) string {
	t.Helper()
	target := "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Metadata", "true")
	rec := httptest.NewRecorder()
	entra.NewIMDS(cfg, key).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("imds: status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("imds response is not JSON: %v", err)
	}
	return resp.AccessToken
}

// newChecker seeds a fresh store with grants and wraps it in a Checker.
func newChecker(t *testing.T, grants []rbac.RoleAssignment) *rbac.Checker {
	t.Helper()
	store := rbac.NewAssignmentStore()
	if err := rbac.Seed(store, builtinDefs, grants); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	return rbac.NewChecker(builtinDefs, store)
}

func TestAuthorize(t *testing.T) {
	cfg := config.Default()
	client := cfg.Clients[0].ObjectID
	clientTok := mintToken(t, cfg, testKey, "https://management.azure.com/.default") // mintToken defined in authn_test.go
	miTok := mintIMDSToken(t, cfg, testKey)

	sub := "/subscriptions/" + cfg.SubscriptionID
	rg := sub + "/resourceGroups/dev"
	ra := sub + "/providers/Microsoft.Authorization/roleAssignments/ra-1"
	grant := func(principal, role, scope string) rbac.RoleAssignment {
		return rbac.RoleAssignment{PrincipalID: principal, RoleDefinitionID: role, Scope: scope}
	}
	defaults := SeedAssignments(cfg)
	readerOnly := []rbac.RoleAssignment{grant(client, config.ReaderRoleID, sub)}
	elsewhere := []rbac.RoleAssignment{grant(client, config.OwnerRoleID, "/subscriptions/other")}

	tests := []struct {
		name   string
		grants []rbac.RoleAssignment
		token  string
		method string
		path   string
		deny   bool
	}{
		{"owner writes a group", defaults, clientTok, http.MethodPut, rg, false},
		{"contributor writes a group", defaults, miTok, http.MethodPut, rg, false},
		{"contributor cannot grant roles", defaults, miTok, http.MethodPut, ra, true},
		{"owner grants roles", defaults, clientTok, http.MethodPut, ra, false},
		{"reader reads a group", readerOnly, clientTok, http.MethodGet, rg, false},
		{"reader cannot write a group", readerOnly, clientTok, http.MethodPut, rg, true},
		{"no assignment at all", readerOnly, miTok, http.MethodGet, rg, true},
		{"owner elsewhere is nobody here", elsewhere, clientTok, http.MethodPut, rg, true},
		{"subscription listing needs no assignment", elsewhere, miTok, http.MethodGet, "/subscriptions", false},
	}
	for _, tc := range tests {
		reached := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
		auth := NewAuthenticator(cfg, &testKey.PublicKey, time.Now)
		authz := NewAuthorizer(newChecker(t, tc.grants))
		chain := auth.Authenticate(RouteRequest(authz.Authorize(next)))

		req := httptest.NewRequest(tc.method, tc.path+"?api-version=2022-12-01", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		rec := httptest.NewRecorder()
		chain.ServeHTTP(rec, req)

		if !tc.deny {
			if !reached {
				t.Errorf("%s: status %d %s, want next reached", tc.name, rec.Code, rec.Header().Get("x-ms-error-code"))
			}
			continue
		}
		if reached {
			t.Errorf("%s: reached next, want 403", tc.name)
			continue
		}
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s: body is not a JSON envelope: %v", tc.name, err)
		}
		if rec.Code != http.StatusForbidden || env.Error.Code != azerr.CodeAuthorizationFailed {
			t.Errorf("%s: status %d code %q, want 403 AuthorizationFailed", tc.name, rec.Code, env.Error.Code)
		}
		if !strings.Contains(env.Error.Message, "over scope '"+tc.path+"'") {
			t.Errorf("%s: message %q does not name the scope %q", tc.name, env.Error.Message, tc.path)
		}
	}
}

// TestAuthorizeRequiresPipelineOrder pins the fail-closed behavior when
// Authorize runs without its predecessors.
func TestAuthorizeRequiresPipelineOrder(t *testing.T) {
	authz := NewAuthorizer(newChecker(t, nil))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next reached without principal or route")
	})
	req := httptest.NewRequest(http.MethodGet, "/subscriptions?api-version=2022-12-01", nil)
	rec := httptest.NewRecorder()
	authz.Authorize(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no principal: status %d, want 401", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = req.WithContext(withPrincipal(req.Context(), Principal{ObjectID: "p"}))
	authz.Authorize(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("no route: status %d, want 500", rec.Code)
	}
}
