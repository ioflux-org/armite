# Storage accounts and blobs

Provisio serves `Microsoft.Storage` storage accounts on the management
plane and their **blob** service on the data plane, with the data held by
[Azurite](https://github.com/Azure/Azurite), Microsoft's own storage
emulator, behind Provisio's identity and RBAC. The division of labour:

- **Provisio**: accounts, keys and containers as ARM resources; bearer
  tokens; RBAC on every data-plane call; user delegation keys and the
  SAS tokens signed with them; the `allowSharedKeyAccess` switch.
- **Azurite**: the blobs themselves, and the validation of Shared Key
  and key-signed SAS requests, which pass through untouched.

## The demo

```bash
az storage account create -n stdemo -g st-rg -l eastus --sku Standard_LRS
az storage container create -n demo --account-name stdemo --auth-mode login
az storage blob upload -f hello.txt -c demo -n hello.txt --account-name stdemo --auth-mode login
```

The container is created and the upload is refused: _You do not have the
required permissions needed to perform this operation. … you may need to
be assigned one of the following roles: "Storage Blob Data Owner",
"Storage Blob Data Contributor", …_ — az's own words, because that is
the error Azure sends. The caller is Owner of the subscription; Owner
holds every management action, and container operations are management
actions (`…/blobServices/containers/write`), but blob operations are
data actions (`…/containers/blobs/write`), which Owner does not hold.
Grant a data role and the upload works:

```bash
az role assignment create --role "Storage Blob Data Contributor" \
  --assignee-object-id 44444444-4444-4444-4444-444444444444 \
  --assignee-principal-type ServicePrincipal \
  --scope $(az storage account show -n stdemo -g st-rg --query id -o tsv)
```

The same demo through the SDK is `scripts/sdk-smoke/blob-smoke.mjs`, and
through Terraform `examples/terraform`.

## Hostnames

An account's blob endpoint is `https://{account}.blob.core.localhost:8443/`
(configuration key `blob_host`, default `blob.core.localhost`; the suffix
clients learn from the cloud's `suffixes.storage` is `core.localhost:8443`).
The `.blob.core.` part is deliberate: the Python SDK, hence az, finds the
account name only in a host that contains it. How such names resolve on
your machine is in [dns.md](dns.md).

## Who runs Azurite

| `azurite.mode` | what happens                                                                                                                                                                                                                                                                                                         |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `managed`      | Provisio starts `azurite-blob` (from `npm install -g azurite`, on PATH; bundled in the Docker image) under `state/azurite`, with the accounts it has created, and restarts it when an account is created, deleted or has a key regenerated — about two seconds, during which other accounts answer 502. The default. |
| `byo`          | Provisio forwards to `azurite.upstream`, an Azurite you run; `azurite.accounts` lists the names and keys it was started with (`AZURITE_ACCOUNTS`), and only those names can be created.                                                                                                                              |
| `off`          | No storage. Any `Microsoft.Storage` call gets `MissingSubscriptionRegistration`, as a subscription without the provider would.                                                                                                                                                                                       |

Managed mode without `azurite-blob` on PATH logs one line at boot and
behaves as `off`; everything else keeps working.

Azurite reads its accounts at start-up only, which is why a changed
account set means a restart. Its data lives under the state directory,
so "delete `state/` to start over" and `docker compose down -v` take
the blobs with them; it is not encrypted, unlike Provisio's own state.

## Authentication on the data plane

| the request carries                 | what Provisio does                                                                                                                                                                            |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a bearer token                      | verifies it (audience `https://storage.azure.com` or the account's own endpoint), names the operation, checks RBAC at the container or account scope, re-signs with the account key, forwards |
| `Authorization: SharedKey …`        | forwards as it is; Azurite validates the signature. Refused with `KeyBasedAuthenticationNotPermitted` when the account's `allowSharedKeyAccess` is false                                      |
| a service or account SAS (`sig=` …) | forwards as it is; Azurite validates it. Refused when `allowSharedKeyAccess` is false, like the key it was signed with                                                                        |
| a user delegation SAS (`skoid=` …)  | validates it (every layout from 2018-11-09 to 2026-04-06), then checks the **delegating principal's** RBAC for the operation at that moment, re-signs, forwards                               |
| nothing                             | 401 with the storage challenge                                                                                                                                                                |

Azure's 403 says only "This request is not authorized to perform this
operation using this permission."; Provisio's adds the operation, the
action, the scope and the caller, which is what you need to fix it:

```text
<Code>AuthorizationPermissionMismatch</Code><Message>This request is not authorized …
Operation: Put Blob
Action: 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
Scope: '/subscriptions/…/storageAccounts/stdemo/blobServices/default/containers/demo'
Caller: oid=44444444-4444-4444-4444-444444444444
```

### User delegation SAS

```bash
az storage blob generate-sas -c demo -n hello.txt --account-name stdemo \
  --permissions r --expiry "$(date -u -d '+1 day' +%Y-%m-%dT%H:%MZ)" \
  --auth-mode login --as-user      # macOS: date -u -v+1d +%Y-%m-%dT%H:%MZ
```

The key is issued by Provisio to the calling principal (action
`…/blobServices/generateUserDelegationKey/action`, up to seven days),
derived from its fields with a secret, nothing stored. A SAS signed with
it is authorized as that principal: revoke the principal's data role and
every SAS it issued stops working at once — the property Azure gives
these tokens and a key-signed SAS cannot have, since a key does not know
who holds it.

## What is served

| management plane                                                                                                                          | data plane                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `storageAccounts` create, update, patch, get, list, delete; `checkNameAvailability`; `listKeys`; `regenerateKey`                          | containers: create, properties, metadata, ACL, lease, list, delete; blobs: put (block, append, page), get, properties, metadata, tags, lease, snapshot, copy, tier, delete; find by tags; service properties |
| `blobServices/default` get and set (kept, not enforced); `blobServices/default/containers` create, get, list, delete, served from Azurite | user delegation key                                                                                                                                                                                          |
| `fileServices`, `queueServices`, `tableServices` answer defaults (Terraform reads them)                                                   | the queue and table hosts answer the service-properties probe Terraform makes and refuse everything else                                                                                                     |

Refused rather than guessed: batch requests, immutability policies and
legal holds, Data Lake (hierarchical namespace) paths, SAS tokens bound
to request headers or parameters, stored access policies with a user
delegation SAS. Not advertised: queue, table, file and static-website
endpoints; `primaryEndpoints` carries `blob` only.

## Terraform

`azurerm_storage_account` takes about a minute to create: after the PUT
the provider waits for the blob, queue, file, static-website and table
services in turn, ten seconds each, before it reports success. Set
`storage_use_azuread = true` in the provider block so the container and
blob resources use the principal's token and RBAC applies to them;
without it they use the account key and bypass RBAC, as in Azure.

## Configuration

| key                  | default               | meaning                                                         |
| -------------------- | --------------------- | --------------------------------------------------------------- |
| `blob_host`          | `blob.core.localhost` | accounts are `{name}.blob_host`; must start with `blob.`        |
| `azurite.mode`       | `managed`             | `managed`, `byo` or `off`                                       |
| `azurite.command`    | `azurite-blob`        | the executable managed mode runs, resolved on PATH              |
| `azurite.port`       | `10000`               | where managed mode listens, on the loopback interface           |
| `azurite.upstream`   |                       | byo: the URL of your Azurite, e.g. `http://127.0.0.1:10000`     |
| `azurite.accounts[]` |                       | byo: `name` and base64 `key` of each account your Azurite knows |

Azurite's own port stays reachable on the machine without Provisio in
front of it; anyone with an account key can bypass RBAC there, as they
could with the key against Azure itself.
