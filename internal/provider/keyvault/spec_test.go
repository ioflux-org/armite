package keyvault

import (
	"net/http"
	"testing"

	"github.com/ioflux-org/armite/internal/spectest"
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

// TestSecretResponsesMatchSpec checks the data plane's shapes against the
// vendored 2025-07-01 secrets spec.
func TestSecretResponsesMatchSpec(t *testing.T) {
	spec := spectest.Load(t, "testdata/spec/data-plane/2025-07-01/secrets.json", "")
	p := newProvider(t)
	body := `{"value":"x","contentType":"text/plain","tags":{"a":"b"}}`

	rec := serveSecret(t, p, http.MethodPut, "/secrets/db", body)
	spec.Check(t, "SecretBundle", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db", "")
	spec.Check(t, "SecretBundle", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodGet, "/secrets", "")
	spec.Check(t, "SecretListResult", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db/versions", "")
	spec.Check(t, "SecretListResult", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodDelete, "/secrets/db", "")
	spec.Check(t, "DeletedSecretBundle", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodGet, "/deletedsecrets", "")
	spec.Check(t, "DeletedSecretListResult", rec.Body.Bytes())
	rec = serveSecret(t, p, http.MethodGet, "/secrets/db", "")
	spec.Check(t, "KeyVaultError", rec.Body.Bytes())
}
