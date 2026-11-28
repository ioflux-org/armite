#!/usr/bin/env bash
# The README demo and the storage demo, driven by az against a running
# server, every expectation asserted: Owner creates a vault and a
# storage account, is refused a secret and a blob, is granted the data
# roles, succeeds, and reads a blob with a user delegation SAS. Uses an
# az configuration directory of its own. Exits non-zero on any mismatch.
set -euo pipefail
# Git Bash rewrites arguments that look like POSIX paths into Windows
# paths before a native program sees them: az would receive
# --scope C:/Program Files/Git/subscriptions/… — off for this script.
# The paths we pass ($CI_DIR) are already Windows paths there.
case "$(uname -s)" in MINGW*|MSYS*) export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' ;; esac

# Windows' curl verifies with Schannel, which also asks the CA for a
# revocation list; a private CA has none and Schannel fails closed
# ("the revocation status is unknown"). Best effort: skip the check
# when there is no list to consult. OpenSSL builds ignore the flag.
CURL_REVOKE=""; case "$(uname -s)" in MINGW*|MSYS*) CURL_REVOKE="--ssl-revoke-best-effort" ;; esac

CI_DIR="${CI_DIR:-/tmp/armite-ci}"
export AZURE_CONFIG_DIR="$CI_DIR/az" REQUESTS_CA_BUNDLE="$CI_DIR/home/ca.pem"
SUB=22222222-2222-2222-2222-222222222222
OID=44444444-4444-4444-4444-444444444444

ok() { echo "ok  $1"; }
fail() { echo "FAIL: $1" >&2; exit 1; }
# tsv runs az with tsv output and strips the carriage return Python
# adds on Windows; without it "$(…)" comparisons fail and the SAS URL
# carries a \r.
tsv() { az "$@" -o tsv | tr -d '\r'; }
# expiry prints tomorrow as az wants it: GNU date (Linux, Git Bash) and
# BSD date (macOS) spell "tomorrow" differently, and BSD's -d means
# something else entirely.
expiry() {
    if [ "$(uname -s)" = Darwin ]; then date -u -v+1d +%Y-%m-%dT%H:%MZ
    else date -u -d '+1 day' +%Y-%m-%dT%H:%MZ; fi
}
# refused runs an az command that must fail, and checks its error text.
refused() {
    local what=$1 text=$2; shift 2
    if out=$("$@" 2>&1); then fail "$what: succeeded, expected a refusal"; fi
    grep -q "$text" <<<"$out" || fail "$what: refused without '$text': $out"
    ok "$what -> $text"
}

# login switches az to a service principal.
login() {
    az login --service-principal -u "$1" -p "$2" --tenant 11111111-1111-1111-1111-111111111111 -o none
}

az cloud set -n AzureCloud 2>/dev/null || true
az cloud unregister -n Armite 2>/dev/null || true
az cloud register -n Armite --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Armite
az config set core.instance_discovery=false core.collect_telemetry=false core.only_show_errors=true >/dev/null
login 33333333-3333-3333-3333-333333333333 armite-secret
[ "$(tsv account show --query id)" = "$SUB" ] || fail "login did not land in the subscription"
ok "az login"

# The directory through Graph: az finds the built-in principal, and a
# role assignment listing names it instead of showing a blank.
[ "$(tsv ad sp show --id 33333333-3333-3333-3333-333333333333 --query id)" = "$OID" ] ||
    fail "az ad sp show through Graph"
ok "az ad sp show finds the built-in principal through Graph"

# A role assignment listing names its principals through Graph: az shows
# a service principal by its first servicePrincipalName, the appId, as
# in Azure (blank here until the directory existed).
[ "$(tsv role assignment list --query "[?principalId=='$OID'].principalName | [0]")" = "33333333-3333-3333-3333-333333333333" ] ||
    fail "principal names come from Graph"
ok "role assignment list names the principal"

# Key Vault: the README demo.
az group create -n kv-rg -l eastus -o none
az keyvault create -n kv-demo -g kv-rg -l eastus --enable-rbac-authorization -o none
ok "vault created"
refused "Owner cannot set a secret" "ForbiddenByRbac" \
    az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2
az role assignment create --role "Key Vault Secrets Officer" --assignee-object-id "$OID" \
    --assignee-principal-type ServicePrincipal \
    --scope "$(tsv keyvault show -n kv-demo -g kv-rg --query id)" -o none
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2 -o none
[ "$(tsv keyvault secret show --vault-name kv-demo -n db-pass --query value)" = hunter2 ] ||
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
    --scope "$(tsv storage account show -n stdemo -g st-rg --query id)" -o none
az storage blob upload -f "$CI_DIR/hello.txt" -c demo -n hello.txt --account-name stdemo \
    --auth-mode login --overwrite -o none
ok "upload after the grant"
az storage blob download -c demo -n hello.txt --account-name stdemo --auth-mode login \
    -f "$CI_DIR/got.txt" -o none
[ "$(cat "$CI_DIR/got.txt")" = hello ] || fail "blob download"
ok "download"
SAS=$(tsv storage blob generate-sas -c demo -n hello.txt --account-name stdemo --permissions r \
    --expiry "$(expiry)" --auth-mode login --as-user)
BLOB=$(tsv storage account show -n stdemo -g st-rg --query primaryEndpoints.blob)
[ "$(curl -sS $CURL_REVOKE --cacert "$REQUESTS_CA_BUNDLE" "${BLOB}demo/hello.txt?$SAS")" = hello ] ||
    fail "read with a user delegation SAS"
ok "read with a user delegation SAS"

# The id on an error is the id in the server log.
ID=$(curl -sS $CURL_REVOKE --cacert "$REQUESTS_CA_BUNDLE" -D - -o "$CI_DIR/body" \
    'https://management.localhost:8443/subscriptions?api-version=2022-12-01' |
    awk 'tolower($1)=="x-ms-request-id:"{print $2}' | tr -d '\r')
grep -q "id=$ID" "$CI_DIR/server.log" || fail "request id $ID is not in the server log"
ok "x-ms-request-id $ID is in the server log"

# Principals created through Graph, last because it changes who az is
# logged in as. create-for-rbac makes the application, a secret and the
# service principal and assigns the role, which succeeds on the first
# try: the directory is consulted, there is no replication to wait for.
az ad sp create-for-rbac -n ci-sp --role Reader --scopes "/subscriptions/$SUB" -o json > "$CI_DIR/sp.json"
APPID=$(sed -n 's/.*"appId": *"\([^"]*\)".*/\1/p' "$CI_DIR/sp.json")
PASSWORD=$(sed -n 's/.*"password": *"\([^"]*\)".*/\1/p' "$CI_DIR/sp.json")
[ -n "$APPID" ] && [ -n "$PASSWORD" ] || fail "create-for-rbac printed no credentials: $(cat "$CI_DIR/sp.json")"
SP=$(tsv ad sp show --id "$APPID" --query id)
ok "az ad sp create-for-rbac"

# A user and a group, each given a role: the group by its object id,
# the user by name. az asks Graph what kind of principal each is.
az ad user create --display-name Ada --user-principal-name ada@armite.local --password 'P@ssw0rd!2026' -o none
az ad group create --display-name builders --mail-nickname builders -o none
GROUP=$(tsv ad group show --group builders --query id)
[ "$(tsv role assignment create --assignee "$GROUP" --role Contributor \
    --scope "/subscriptions/$SUB" --query principalType)" = Group ] || fail "a role for a group"
[ "$(tsv role assignment create --assignee ada@armite.local --role Reader \
    --scope "/subscriptions/$SUB" --query principalType)" = User ] || fail "a role for a user, found by name"
ok "a user and a group hold roles"

# The new principal logs in and gets what Reader allows...
login "$APPID" "$PASSWORD"
[ "$(tsv group list --query "length(@)")" -ge 2 ] || fail "the new principal cannot read as Reader"
refused "Reader cannot create a resource group" "AuthorizationFailed" \
    az group create -n sp-rg -l eastus
ok "the new principal logs in, reads, and is refused a write"

# ...until it joins the group: Contributor reaches it through the
# membership, on the very next request.
login 33333333-3333-3333-3333-333333333333 armite-secret
az ad group member add --group builders --member-id "$SP"
[ "$(tsv ad group member check --group builders --member-id "$SP" --query value)" = true ] ||
    fail "az ad group member check"
login "$APPID" "$PASSWORD"
az group create -n sp-rg -l eastus -o none
ok "a group's role reaches its member"

echo PASS
