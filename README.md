# Provisio

A local Azure emulator with a real identity plane and real RBAC. Your
application, the Azure CLI, the Azure SDKs and Terraform talk to
Provisio exactly as they talk to Azure: tokens are minted and verified,
role assignments are evaluated on both the management plane and the
data plane, and a principal without the right role gets the same 403 it
would get in production.

```text
$ az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2
(Forbidden) Caller is not authorized to perform action on resource.
Caller: appid=33333333-...;oid=44444444-...
Action: 'Microsoft.KeyVault/vaults/secrets/setSecret/action'
Resource: '/subscriptions/.../vaults/kv-demo/secrets/db-pass'
DecisionReason: 'DeniedWithNoValidRBAC'
Inner error: {"code": "ForbiddenByRbac"}
```

That caller is **Owner** of the subscription. Owner carries every
management-plane action and not one data-plane action, so on an
RBAC-mode vault it cannot read or write a secret until a data role such
as Key Vault Secrets Officer is assigned. "But I'm Owner?!" is one of
Azure's most common surprises; with Provisio it happens on your laptop
and in CI instead of in production.

## What is inside

| Area                    | Served                                                                                                                                          |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Identity                | Entra ID token endpoint (client credentials), OpenID discovery, JWKS, IMDS for managed identity                                                 |
| RBAC                    | All 934 built-in roles; Actions, NotActions, DataActions, NotDataActions with Azure's glob semantics; assignments at any scope; deny by default |
| ARM                     | Subscriptions, tenants, resource groups, generic resource listing, the resource-provider catalogue, cloud discovery (`/metadata/endpoints`)     |
| Microsoft.Authorization | Role definitions (read), role assignments (create, read, list, delete)                                                                          |
| Microsoft.KeyVault      | Vaults (management plane); secrets with versions, soft delete, recover and purge (data plane, one hostname per vault, challenge authentication) |
| Microsoft.Storage       | Storage accounts, keys and containers; a blob data plane with RBAC on every call, served by Azurite behind it; key, SAS and user delegation SAS |
| Persistence             | Everything created through the API survives restarts and crashes: an encrypted journal in your data directory, no database to run               |
| Operations              | One log line per request under the `x-ms-request-id` the client got back, text or JSON; secrets never logged                                    |

Verified end to end with `az` 2.89, `@azure/identity`,
`@azure/keyvault-secrets` and `@azure/storage-blob`, `azure-identity` for
Python, Terraform 1.16 with the unmodified azurerm provider, and curl.

## Quickstart

```bash
go run ./cmd/provisio          # or: docker compose up -d  (see docs/docker.md)
```

The server generates a private CA in `~/.provisio/` at first boot, keeps what you create in your data directory (`~/.local/share/provisio` on Linux), and serves `https://management.localhost:8443` (ARM), `https://login.localhost:8443` (Entra), `https://{vault}.vault.localhost:8443` (Key Vault data
plane) and `https://{account}.blob.core.localhost:8443` (blobs), plus
IMDS on `http://127.0.0.1:8081`. Storage accounts need `azurite-blob` on
your PATH (`npm install -g azurite`; the Docker image has it) and are
otherwise off. Two things every client needs:

1. **Hostnames** resolving to 127.0.0.1. Linux with systemd-resolved
   does it already; WSL2 and macOS need a one-time resolver fix or the
   `/etc/hosts` lines `provisio hosts` prints — see [docs/dns.md](docs/dns.md).
2. **The CA.** `~/.provisio/ca.pem`, passed per client (`curl --cacert`,
   `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`).

Then the demo with the CLI, in a config directory of its own so your
real Azure login is untouched:

```bash
export AZURE_CONFIG_DIR=$HOME/.azure-provisio REQUESTS_CA_BUNDLE=$HOME/.provisio/ca.pem
az cloud set -n AzureCloud 2>/dev/null; az cloud unregister -n Provisio 2>/dev/null
az cloud register -n Provisio --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Provisio
az config set core.instance_discovery=false
az login --service-principal -u 33333333-3333-3333-3333-333333333333 \
  -p provisio-secret --tenant 11111111-1111-1111-1111-111111111111

az group create -n kv-rg -l eastus
az keyvault create -n kv-demo -g kv-rg -l eastus --enable-rbac-authorization
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2   # 403
az role assignment create --role "Key Vault Secrets Officer" \
  --assignee-object-id 44444444-4444-4444-4444-444444444444 \
  --assignee-principal-type ServicePrincipal \
  --scope $(az keyvault show -n kv-demo -g kv-rg --query id -o tsv)
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2   # 200
```

The same demo through the SDK is `scripts/sdk-smoke/keyvault-smoke.mjs`,
and through Terraform `examples/terraform`. The storage twin — Owner
creates a container and cannot upload a blob — is in
[docs/storage.md](docs/storage.md). Client setup for every tool is in
[docs/clients.md](docs/clients.md).

## Built-in identities

Provisio is one tenant with one subscription and two principals, all
fixed and documented, so nothing needs registering:

|                                                    | value                                                                                                                  |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Tenant                                             | `11111111-1111-1111-1111-111111111111`                                                                                 |
| Subscription                                       | `22222222-2222-2222-2222-222222222222`                                                                                 |
| Service principal (Owner of the subscription)      | client `33333333-3333-3333-3333-333333333333`, secret `provisio-secret`, object `44444444-4444-4444-4444-444444444444` |
| Managed identity (Contributor of the subscription) | client `55555555-5555-5555-5555-555555555555`, object `66666666-6666-6666-6666-666666666666`, via IMDS                 |

The managed identity is the one your production code path uses:
`DefaultAzureCredential` with `AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081`
and no secret anywhere, exactly as on a VM, and its roles are enforced.

## What is different from Azure

Provisio is faithful where clients look and deliberately simple
elsewhere. The complete list is in
[docs/divergences.md](docs/divergences.md); the ones you will meet first:

- One process, one tenant, one subscription; what you create persists in your data directory across restarts, encrypted [docs/persistence.md](docs/persistence.md).
- Clients must skip Entra instance discovery (`disableInstanceDiscovery`,
  `az config set core.instance_discovery=false`); the authority is not
  in Microsoft's instance metadata.
- No Microsoft Graph: `az ad …` does not work, and `az role assignment list` needs `-o json` or `--query` (the table view wants principal
  names only Graph can supply).
- A principal is one object ID; there are no groups to expand, no ABAC
  conditions, no deny assignments.
- Key Vault soft delete is the minimum the SDKs' pollers need; vaults
  themselves are deleted at once; Key Vault keys and certificates are not
  served yet.
- Storage is blobs only, held by Azurite: no queues, tables or files;
  creating an account restarts Azurite for about two seconds.

## Why another emulator

Every local Azure tool is either a data-plane emulator with no identity
(Azurite, the Cosmos and Service Bus emulators), a management-plane mock
that accepts any bearer token, or an RBAC implementation scoped to one
service. Provisio's centre is a general RBAC engine over Azure's own
role definitions, fed by tokens it mints and verifies itself, with
services attached behind it. The wager is that the expensive part of
Azure to get right locally is the authorization model, not any single
service, and that once it is right, services are providers behind one
gateway. The next ones planned are Storage (Azurite behind the RBAC
layer), then compute.

## Legal

Provisio implements publicly documented HTTP APIs so that unmodified
clients work against it, the same way LocalStack does for AWS. It ships
none of Microsoft's code or data except the public built-in role
definitions (obtainable by anyone with `az role definition list`) and,
for tests only, files from the MIT-licensed
[azure-rest-api-specs](https://github.com/Azure/azure-rest-api-specs)
repository, credited in their `testdata` directories. Azure, Entra and
Key Vault are Microsoft trademarks; Provisio is not affiliated with or
endorsed by Microsoft.

Licensed under the [Apache License 2.0](LICENSE).
