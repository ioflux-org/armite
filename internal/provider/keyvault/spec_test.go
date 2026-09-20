package keyvault

import (
	"net/http"
	"testing"

	"github.com/ioflux-org/provisio/internal/spectest"
)

// TestResponsesMatchSpec checks the shapes this provider emits against
// the vendored 2025-05-01 management spec: no invented property, no
// missing required one, nested models included.
func TestResponsesMatchSpec(t *testing.T) {
	spec := spectest.Load(t, "testdata/spec/2025-05-01/openapi.json",
		"../../spectest/testdata/common-types/v5/types.json")
	p := newProvider(t)
	id := rg + vaults + "/kv-demo"

	rec := serve(t, p, http.MethodPut, id, azBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d %s", rec.Code, code(rec))
	}
	spec.Check(t, "Vault", rec.Body.Bytes())

	rec = serve(t, p, http.MethodGet, id, "")
	spec.Check(t, "Vault", rec.Body.Bytes())

	rec = serve(t, p, http.MethodGet, rg+vaults, "")
	spec.Check(t, "VaultListResult", rec.Body.Bytes())
}
