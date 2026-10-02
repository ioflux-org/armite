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

## Client caveats (not Provisio's)

- `az keyvault update --set tags.x=y` is broken in az 2.89.1 against
  any cloud; use the explicit flags.
- The azurerm provider waits about two minutes after creating a public
  vault, polling its hostname; that is the provider, not Provisio.
