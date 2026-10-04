# Where Provisio differs from Azure

Every deliberate difference, grouped by what you touch. Tags:
_simplification_ (modelled, less faithfully), _deferred_ (not modelled
yet), _environment_ (a consequence of running locally), _accepted
limitation_ (unverified against a live subscription), _invention_
(something Azure has no equivalent for).

## Environment

- **Hostnames and port.** `management.localhost:8443`,
  `login.localhost:8443` and `{vault}.vault.localhost:8443` instead of
  Microsoft's hosts on 443. Every client needs endpoint configuration;
  `*.vault.localhost` resolves under systemd-resolved but needs a hosts
  entry per vault on WSL2, macOS and Windows. _environment_
- **Private CA.** Clients trust `certs/ca.pem` explicitly. _environment_
- **Instance discovery must be disabled** in every client; the authority
  is not in Entra's instance metadata and MSAL would otherwise ask
  `login.microsoftonline.com` (AADSTS50049). _environment_
- **IMDS** is plain HTTP on `127.0.0.1:8081`, reached through
  `AZURE_POD_IDENTITY_AUTHORITY_HOST`, not the link-local
  `169.254.169.254`. _environment_
- **One process, fixed world.** One tenant, one subscription, two
  principals. State persists across restarts in a local, encrypted
  journal (see [persistence.md](persistence.md)), not in a database:
  one server per state directory. _simplification_

## Identity

- Grants: client credentials and IMDS only; no interactive, device-code
  or authorization-code flows, so `az login` works only with
  `--service-principal` or `--identity`. _deferred_
- One static RSA signing key with a stable `kid`; no rotation.
  _simplification_
- Minimal claims: `oid`, `tid`, `aud`, `iss`, `exp`, `appid`; no
  groups, roles or `xms_*` claims. _simplification_
- IMDS tokens are v2-shaped (real IMDS issues v1); the envelope keeps
  IMDS's string-typed `expires_in`. _simplification_
- No app registrations or consent: any configured client with the
  matching secret gets a token for any audience it asks for.
  _simplification_
- No revocation or continuous access evaluation. _deferred_
- ARM accepts two audiences: `https://management.azure.com` (az, SDKs)
  and its own origin `https://management.localhost:8443` (Terraform's
  go-azure-sdk derives the audience from the endpoint). Real ARM accepts
  `management.azure.com` and `management.core.windows.net`. _accepted
  limitation_

## RBAC

- Built-in roles are a snapshot of the real 934 definitions (captured
  2026-08-30); definition IDs are tenant-level. _simplification_
- A principal is one object ID: no group expansion, no distinction
  between user, service principal and managed identity. _simplification_
- Not evaluated: ABAC conditions, deny assignments, PIM eligible
  assignments, classic administrators. _deferred_
- Custom role definitions cannot be created; the built-in set is
  returned at every scope. _deferred_
- Assignment principals must be one of the configured identities;
  anything else is `PrincipalNotFound`. Assignment names are not
  validated as GUIDs. _simplification_
- `$filter` support is the subset az uses: `roleName eq`, `type eq`,
  `atScopeAndBelow()`, `atScope()`, `principalId eq`, `assignedTo()`,
  combinable with `and`. _simplification_
- No Microsoft Graph: `az ad …` fails, and `az role assignment list -o
table` fails because the table wants principal names; use `-o json`
  or `--query`. _deferred_

## ARM

- `api-version` is required but any well-formed value is accepted; real
  ARM enforces per-provider version sets. _simplification_
- Operations complete synchronously; SDK and Terraform pollers accept
  that. The one long-running operation, purging a deleted vault, is
  reported as already finished. _simplification_
- Locations are stored verbatim with no region catalogue; real ARM
  canonicalises them. _simplification_
- `GET /subscriptions` returns the one subscription to every
  authenticated principal. _simplification_
- The resource envelope carries `id`, `name`, `type`, `location`, `tags`
  and `properties`; no `systemData`, `etag`, `sku`, `identity`, `plan`,
  `zones` or `managedBy`. _simplification_
- Resource groups have no PATCH (az updates with GET and PUT; Terraform
  tag changes on a group would PATCH). Group delete cascades
  synchronously. _deferred_
- The provider catalogue lists Provisio's namespaces as "Registered"
  with the types and api-versions it serves; registration is not
  modelled and locations are nominal. _simplification_
- The generic resource listing supports `$filter=resourceType eq '…'`
  and `name eq '…'`; `$expand` and `$top` are ignored. _simplification_
- The endpoints document carries what az and Terraform read; real ARM's
  has about thirty keys. `microsoftGraphResourceId` points at the ARM
  host so az can build its Graph client. _simplification_
- Not modelled at all: Azure Policy, activity log, resource locks,
  quotas and throttling, ETags. _deferred_
- Error codes are faithful in shape everywhere; exact codes and messages
  are guaranteed only where verified against live client traffic.
  _accepted limitation_
- Responses carry `x-ms-request-id` and echo `x-ms-client-request-id`
  on every plane; no `x-ms-correlation-request-id` or
  `x-ms-routing-request-id`, and a proxied blob response carries
  Provisio's id, not Azurite's. _simplification_

## Key Vault

- Vaults are deleted at once: no vault soft delete, no purge protection,
  names reusable immediately. `deletedVaults` is always empty and a
  purge succeeds instantly. _simplification_
- Access policies and `networkAcls` are stored and echoed, never
  enforced; authorization is RBAC only. Create vaults with
  `--enable-rbac-authorization` (the access-policy path needs Graph).
  _simplification_
- Secrets: versions, soft delete, recover and purge are served; the
  retention window never expires; `nbf` and `exp` are stored, not
  enforced (`enabled` is). Listings are one page. _simplification_
- Not served: keys, certificates, secret backup and restore, managed
  HSMs, `checkNameAvailability`, private endpoints. _deferred_
- An unknown vault hostname answers 404 `VaultNotFound`; in Azure the
  name would simply not resolve. _invention_
- Secret values are held in process memory in plain text; on disk they
  are encrypted with a key kept next to the CA key. _accepted
  limitation_
- The vault URI carries the port (`https://kv-demo.vault.localhost:8443/`)
  because az builds it from the DNS suffix by concatenation.
  _environment_

## Storage

- **Azurite holds the blobs and validates key-based auth.** Bearer
  requests are verified and RBAC-checked by Provisio, then re-signed with
  the account key and forwarded; Shared Key and key-signed SAS requests
  pass through and Azurite validates them. _simplification_
- **Creating, deleting or re-keying an account restarts Azurite** (about
  two seconds, other accounts answer 502 meanwhile): Azurite reads its
  accounts at start-up only. _environment_
- **Bring-your-own Azurite serves only the accounts listed in
  `azurite.accounts`**; another name is refused with 400
  `StorageAccountNotConfigured`. _invention_
- **The blob host is `blob.core.localhost`**, not `blob.localhost`: the
  Python SDK, hence az, finds the account name only in a host containing
  `.blob.core.`. _environment_
- **`PUT storageAccounts` answers 200, never 201 or 202**: the account is
  ready synchronously and the SDK pollers accept only 200 and 202.
  _simplification_
- **Only the blob endpoint is advertised**; the queue and table hosts
  answer the service-properties probe Terraform makes and refuse all
  else (`FeatureNotSupported`); `fileServices`, `queueServices` and
  `tableServices` on the management plane return defaults and echo
  PUTs. _deferred_
- **403 messages carry the operation, action, scope and caller** after
  Azure's standard first line. _invention_
- **Unknown blob operations are refused (400 `UnsupportedOperation`)**
  rather than forwarded: batch, immutability policies, legal holds, Data
  Lake paths; SAS tokens bound to request headers or parameters, or to a
  stored access policy with a user delegation key. _deferred_
- **User delegation keys are derived, not stored**: the value is an HMAC
  of the key's own fields with a server secret, so a SAS can be checked
  without lookup. _simplification_
- **`checkNameAvailability` is authorized as `…/action`**; Azure grants it
  as `…/checknameavailability/read`, so Reader could call it there, not
  here yet. _simplification_
- **Deleting an account deletes its containers upstream** (best effort),
  so a re-created name starts empty. _simplification_
- **Azurite's own port (`10000`, loopback) stays reachable** without
  Provisio in front: anyone on the machine with an account key bypasses
  RBAC there, as the key would anywhere. _accepted limitation_
- **Blob data is not encrypted at rest** (`state/azurite`), unlike
  Provisio's own state. _accepted limitation_
- **Listings keep Azurite's `ServiceEndpoint` value**, not the account's
  URL; no client we ran reads it. _deferred_

## Client caveats (not Provisio's)

- `az keyvault update --set tags.x=y` is broken in az 2.89.1 against
  any cloud; use the explicit flags.
- The azurerm provider waits about two minutes after creating a public
  vault, polling its hostname; that is the provider, not Provisio.
