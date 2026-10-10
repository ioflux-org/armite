# SDK smoke tests

End-to-end checks that the **real Azure JS SDK** works against Armite:
the SDK acquires a token from the mock Entra endpoint, then calls the ARM
gateway over TLS - no Go test doubles involved.

| Script               | What it proves                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `smoke.mjs`          | `ClientSecretCredential` obtains a token from `login.localhost`; prints the decoded claims and verifies the second `getToken` is served from the SDK's cache                                                                                                                                                                                                                                                                                     |
| `arm-smoke.mjs`      | The token is accepted by the gateway at `management.localhost`: authenticated request passes authn and reaches the ARM pipeline                                                                                                                                                                                                                                                                                                                  |
| `keyvault-smoke.mjs` | The full RBAC demo through `@azure/keyvault-secrets`: Owner creates a vault, is refused a secret (403 `ForbiddenByRbac`), grants itself Key Vault Secrets Officer, runs the secret lifecycle incl. soft-delete pollers, revokes the grant and is refused again; exits non-zero on any mismatch                                                                                                                                                   |
| `blob-smoke.mjs`     | The storage twin through `@azure/storage-blob`: Owner creates an account and a container, is refused a blob (403 `AuthorizationPermissionMismatch`), grants itself Storage Blob Data Contributor, uploads, downloads and lists; the account key and a service SAS pass through to Azurite; a user delegation SAS is issued by Armite and dies with the grant; `allowSharedKeyAccess=false` refuses key and SAS; exits non-zero on any mismatch |

## One-time setup

1. **Install dependencies**

   ```bash
   npm ci
   ```

2. **Hosts entries** - `/etc/hosts` must resolve the two virtual hosts
   (see the repo README if these are missing):

   ```text
   127.0.0.1  management.localhost
   127.0.0.1  login.localhost
   127.0.0.1  kv-demo.vault.localhost
   127.0.0.1  stdemo.blob.core.localhost
   ```

   (or the one-time resolver fix in `docs/dns.md`). `blob-smoke.mjs`
   also needs `azurite-blob` on the server's PATH: `npm install -g azurite`.

3. **CA certificate** - the server generates `~/.armite/ca.pem` on first run.
   Node ignores the system trust store and ships its own CA bundle, so the
   CA must be passed explicitly via `NODE_EXTRA_CA_CERTS` (already included
   in the commands below).

## Running

Terminal A - start the server (from the repo root):

```bash
go run ./cmd/armite
```

Terminal B - run a script (from the repo root):

```bash
AZURE_AUTHORITY_HOST=https://login.localhost:8443 \
AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111 \
AZURE_CLIENT_ID=33333333-3333-3333-3333-333333333333 \
AZURE_CLIENT_SECRET=armite-secret \
NODE_EXTRA_CA_CERTS=~/.armite/ca.pem \
node scripts/sdk-smoke/arm-smoke.mjs
```

(Substitute `smoke.mjs` to test token acquisition alone.)

The tenant, client id and secret are Armite's fixed built-in principals
from `config.Default()` - they are a documented contract, not placeholders
to fill in.

Alternatively, put the five variables in `scripts/sdk-smoke/.env`
(`KEY=value`, one per line; the file is git-ignored) and run:

```bash
NODE_EXTRA_CA_CERTS=~/.armite/ca.pem node --env-file=scripts/sdk-smoke/.env scripts/sdk-smoke/arm-smoke.mjs
NODE_EXTRA_CA_CERTS=~/.armite/ca.pem node --env-file=scripts/sdk-smoke/.env scripts/sdk-smoke/keyvault-smoke.mjs
NODE_EXTRA_CA_CERTS=~/.armite/ca.pem node --env-file=scripts/sdk-smoke/.env scripts/sdk-smoke/blob-smoke.mjs
```

`blob-smoke.mjs` takes `ARMITE_ARM` and `ARMITE_STORAGE_SUFFIX` for a
server on other ports or hostnames (defaults
`https://management.localhost:8443` and `core.localhost:8443`).

## Expected output

`smoke.mjs` - the token's claims as JSON (`iss` pointing at
`login.localhost`, `aud` = `https://management.azure.com`), the expiry
timestamp, and `cached: true`.

`arm-smoke.mjs` - `200` and the subscription listing, one entry for the
built-in subscription. A `401` means authentication regressed; a `403`
means the seeded Owner assignment is missing.

## Troubleshooting

| Symptom                                                    | Likely cause                                                                                                                                                         |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ERR_MODULE_NOT_FOUND` on some `@azure`/`@typespec` module | Torn `node_modules` - run `npm ci` (not `npm install`, which trusts the stale manifest)                                                                              |
| `fetch failed` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE`         | `NODE_EXTRA_CA_CERTS` missing or wrong path (`~/.armite/ca.pem`)                                                                                                   |
| `ENOTFOUND management.localhost`                           | Hosts entries missing (or eaten by WSL regeneration - see repo README)                                                                                               |
| `ECONNREFUSED`                                             | Server not running in Terminal A                                                                                                                                     |
| `401 InvalidAuthenticationTokenAudience`                   | Token requested for the wrong scope - the SDK must ask for `https://management.azure.com/.default` (the audience is Azure's logical id, not the emulator's hostname) |
