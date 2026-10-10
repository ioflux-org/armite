#!/usr/bin/env bash
# The README demo and the storage demo, driven by az against a running
# server, every expectation asserted: Owner creates a vault and a
# storage account, is refused a secret and a blob, is granted the data
# roles, succeeds, and reads a blob with a user delegation SAS. Uses an
# az configuration directory of its own. Exits non-zero on any mismatch.
set -euo pipefail
CI_DIR="${CI_DIR:-/tmp/provisio-ci}"
export AZURE_CONFIG_DIR="$CI_DIR/az" REQUESTS_CA_BUNDLE="$CI_DIR/home/ca.pem"
SUB=22222222-2222-2222-2222-222222222222
OID=44444444-4444-4444-4444-444444444444

ok() { echo "ok  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
# refused runs an az command that must fail, and checks its error text.
refused() {
    local what=$1 text=$2; shift 2
    if out=$("$@" 2>&1); then fail "$what: succeeded, expected a refusal"; fi
    grep -q "$text" <<<"$out" || fail "$what: refused without '$text': $out"
    ok "$what -> $text"
}

az cloud set -n AzureCloud 2>/dev/null || true
az cloud unregister -n Provisio 2>/dev/null || true
az cloud register -n Provisio --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Provisio
az config set core.instance_discovery=false core.collect_telemetry=false core.only_show_errors=true >/dev/null
az login --service-principal -u 33333333-3333-3333-3333-333333333333 -p provisio-secret \
    --tenant 11111111-1111-1111-1111-111111111111 -o none
[ "$(az account show --query id -o tsv)" = "$SUB" ] || fail "login did not land in the subscription"
ok "az login"

# Key Vault: the README demo.
az group create -n kv-rg -l eastus -o none
az keyvault create -n kv-demo -g kv-rg -l eastus --enable-rbac-authorization -o none
ok "vault created"
refused "Owner cannot set a secret" "ForbiddenByRbac" \
    az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2
az role assignment create --role "Key Vault Secrets Officer" --assignee-object-id "$OID" \
    --assignee-principal-type ServicePrincipal \
    --scope "$(az keyvault show -n kv-demo -g kv-rg --query id -o tsv)" -o none
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2 -o none
[ "$(az keyvault secret show --vault-name kv-demo -n db-pass --query value -o tsv)" = hunter2 ] ||
    fail "secret round trip"
ok "secret set and read after the grant"

# Storage: the storage demo, through Azurite.
az group create -n st-rg -l eastus -o none
az storage account create -n stdemo -g st-rg -l eastus --sku Standard_LRS -o none
ok "storage account created"
az storage container create -n demo --account-name stdemo --auth-mode login -o none
ok "Owner creates a container"
echo hello > "$CI_DIR/hello.txt"
refused "Owner cannot upload a blob" "required permissions" \
    az storage blob upload -f "$CI_DIR/hello.txt" -c demo -n hello.txt --account-name stdemo \
    --auth-mode login
az role assignment create --role "Storage Blob Data Contributor" --assignee-object-id "$OID" \
    --assignee-principal-type ServicePrincipal \
    --scope "$(az storage account show -n stdemo -g st-rg --query id -o tsv)" -o none
az storage blob upload -f "$CI_DIR/hello.txt" -c demo -n hello.txt --account-name stdemo \
    --auth-mode login --overwrite -o none
ok "upload after the grant"
az storage blob download -c demo -n hello.txt --account-name stdemo --auth-mode login \
    -f "$CI_DIR/got.txt" -o none
[ "$(cat "$CI_DIR/got.txt")" = hello ] || fail "blob download"
ok "download"
SAS=$(az storage blob generate-sas -c demo -n hello.txt --account-name stdemo --permissions r \
    --expiry "$(date -u -d '+1 day' +%Y-%m-%dT%H:%MZ)" --auth-mode login --as-user -o tsv)
BLOB=$(az storage account show -n stdemo -g st-rg --query primaryEndpoints.blob -o tsv)
[ "$(curl -sS --cacert "$REQUESTS_CA_BUNDLE" "${BLOB}demo/hello.txt?$SAS")" = hello ] ||
    fail "read with a user delegation SAS"
ok "read with a user delegation SAS"

# The id on an error is the id in the server log.
ID=$(curl -sS --cacert "$REQUESTS_CA_BUNDLE" -D - -o /dev/null \
    'https://management.localhost:8443/subscriptions?api-version=2022-12-01' |
    awk 'tolower($1)=="x-ms-request-id:"{print $2}' | tr -d '\r')
grep -q "id=$ID" "$CI_DIR/server.log" || fail "request id $ID is not in the server log"
ok "x-ms-request-id $ID is in the server log"
echo PASS
