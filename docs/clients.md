# Client setup

Armite serves `https://management.localhost:8443` (ARM),
`https://login.localhost:8443` (Entra), `https://{vault}.vault.localhost:8443`
(Key Vault data plane), `https://{account}.blob.core.localhost:8443` (blob
data plane) and `http://127.0.0.1:8081` (IMDS). Every client needs three
things: the hostnames resolving to 127.0.0.1, the CA in `~/.armite/ca.pem`,
and Entra instance discovery disabled.

## Hosts

Linux with systemd-resolved resolves every `*.localhost` name already;
WSL2 and macOS need a one-time resolver fix, or the `/etc/hosts` lines
`armite hosts` prints. Both are in [dns.md](dns.md).

## curl

```bash
TOKEN=$(curl -s --cacert ~/.armite/ca.pem \
  -d 'grant_type=client_credentials&client_id=33333333-3333-3333-3333-333333333333' \
  -d 'client_secret=armite-secret&scope=https://management.azure.com/.default' \
  https://login.localhost:8443/11111111-1111-1111-1111-111111111111/oauth2/v2.0/token \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl -s --cacert ~/.armite/ca.pem -H "Authorization: Bearer $TOKEN" \
  'https://management.localhost:8443/subscriptions?api-version=2022-12-01'
```

On Windows, `curl.exe` verifies with Schannel and also checks
revocation, which a private CA cannot answer; add
`--ssl-revoke-best-effort` to the commands above.

## Azure CLI

Use a separate configuration directory so your real login is untouched,
and re-register the cloud whenever Armite's endpoints change: `az cloud
register` snapshots the endpoints document.

```bash
export AZURE_CONFIG_DIR=$HOME/.azure-armite
export REQUESTS_CA_BUNDLE=$HOME/.armite/ca.pem   # replaces the public roots in this shell
az cloud register -n Armite --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Armite
az config set core.instance_discovery=false
az login --service-principal -u 33333333-3333-3333-3333-333333333333 \
  -p armite-secret --tenant 11111111-1111-1111-1111-111111111111
```

As the managed identity, in another configuration directory:

```bash
export AZURE_CONFIG_DIR=$HOME/.azure-armite-mi
export AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081
az cloud register -n Armite --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Armite && az config set core.instance_discovery=false
az login --identity
```

Known: `az role assignment list -o table` fails (no Graph for principal
names); use `-o json` or `--query`. `az ad …` commands do not work.
Create vaults with `--enable-rbac-authorization`.

## Node (@azure/identity, @azure/keyvault-secrets, @azure/arm-\*)

```bash
export AZURE_AUTHORITY_HOST=https://login.localhost:8443
export AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111
export AZURE_CLIENT_ID=33333333-3333-3333-3333-333333333333
export AZURE_CLIENT_SECRET=armite-secret
export NODE_EXTRA_CA_CERTS=$HOME/.armite/ca.pem   # must be in the process environment, not an env file
```

```js
const cred = new ClientSecretCredential(tenant, client, secret, {
  disableInstanceDiscovery: true,
});
const secrets = new SecretClient("https://kv-demo.vault.localhost:8443", cred);
```

Management-plane clients (`@azure/arm-resources` and friends) take the
endpoint as `{ endpoint: "https://management.localhost:8443" }` in their
options. Managed identity: `new ManagedIdentityCredential()` with
`AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081` set.
`scripts/sdk-smoke/` has complete runnable examples.

## Python (azure-identity, azure-keyvault-secrets, azure-mgmt-\*)

```bash
export AZURE_AUTHORITY_HOST=https://login.localhost:8443
export REQUESTS_CA_BUNDLE=$HOME/.armite/ca.pem
export AZURE_TENANT_ID=… AZURE_CLIENT_ID=… AZURE_CLIENT_SECRET=…   # as above
```

```python
cred = ClientSecretCredential(tenant, client, secret, disable_instance_discovery=True)
# or, for the production code path: DefaultAzureCredential(disable_instance_discovery=True)
# with AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081 and no secret set
SecretClient("https://kv-demo.vault.localhost:8443", cred).get_secret("db-pass")
```

Management clients take `base_url="https://management.localhost:8443"`
and `credential_scopes=["https://management.azure.com/.default"]`.

## Terraform (azurerm)

```hcl
provider "azurerm" {
  features {}
  metadata_host                   = "management.localhost:8443"
  subscription_id                 = "22222222-2222-2222-2222-222222222222"
  tenant_id                       = "11111111-1111-1111-1111-111111111111"
  client_id                       = "33333333-3333-3333-3333-333333333333"
  client_secret                   = "armite-secret"
  use_cli                         = false
  use_msi                         = false
  resource_provider_registrations = "none"
}
```

```bash
export SSL_CERT_FILE=$HOME/.armite/ca.pem    # Terraform is a Go program
```

A complete example with the 403 demo is in `examples/terraform`.
Creating a public vault waits about two minutes for the provider's
availability poll; `public_network_access_enabled = false` skips it.

## Docker

The image binds all interfaces and publishes on 127.0.0.1; the CA comes
out of the container's `/data` volume. See [docker.md](docker.md).

## Troubleshooting

| Symptom                                                                       | Cause                                                                                |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `AADSTS50049` or a TLS error against `login.microsoftonline.com`              | instance discovery not disabled                                                      |
| `unable to get local issuer certificate`, `endpoints_resolution_error` (msal) | CA not trusted by that client; for Node the variable must be in the real environment |
| `connection refused` on port 443                                              | a client still pointing at the real cloud, or a stale `az cloud` registration        |
| `VaultNotFound`                                                               | the vault does not exist on this server (a new state directory starts empty)         |
| `401` with `WWW-Authenticate` on a vault                                      | expected first request of the challenge flow; the SDK retries with a token           |
| `403 ForbiddenByRbac`                                                         | working as intended: assign a data-plane role at the vault                           |
