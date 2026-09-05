# SDK smoke tests

End-to-end checks that the **real Azure JS SDK** works against Provisio:
the SDK acquires a token from the mock Entra endpoint, then calls the ARM
gateway over TLS - no Go test doubles involved.

| Script | What it proves |
|---|---|
| `smoke.mjs` | `ClientSecretCredential` obtains a token from `login.localhost`; prints the decoded claims and verifies the second `getToken` is served from the SDK's cache |
| `arm-smoke.mjs` | The token is accepted by the gateway at `management.localhost`: authenticated request passes authn and reaches the ARM pipeline |

## One-time setup

1. **Install dependencies**

   ```bash
   npm ci
   ```

2. **Hosts entries** - `/etc/hosts` must resolve the two virtual hosts
   (see the repo README if these are missing):

   ```
   127.0.0.1  management.localhost
   127.0.0.1  login.localhost
   ```

3. **CA certificate** - the server generates `certs/ca.pem` on first run.
   Node ignores the system trust store and ships its own CA bundle, so the
   CA must be passed explicitly via `NODE_EXTRA_CA_CERTS` (already included
   in the commands below).

## Running

Terminal A - start the server (from the repo root):

```bash
go run ./cmd/provisio
```

Terminal B - run a script (from the repo root, so `certs/ca.pem` resolves):

```bash
AZURE_AUTHORITY_HOST=https://login.localhost:8443 \
AZURE_TENANT_ID=11111111-1111-1111-1111-111111111111 \
AZURE_CLIENT_ID=33333333-3333-3333-3333-333333333333 \
AZURE_CLIENT_SECRET=provisio-secret \
NODE_EXTRA_CA_CERTS=certs/ca.pem \
node scripts/sdk-smoke/arm-smoke.mjs
```

(Substitute `smoke.mjs` to test token acquisition alone.)

The tenant, client id and secret are Provisio's fixed built-in principals
from `config.Default()` - they are a documented contract, not placeholders
to fill in.

Alternatively, put the five variables in `scripts/sdk-smoke/.env`
(`KEY=value`, one per line; the file is git-ignored) and run:

```bash
node --env-file=scripts/sdk-smoke/.env scripts/sdk-smoke/arm-smoke.mjs
```

## Expected output

`smoke.mjs` - the token's claims as JSON (`iss` pointing at
`login.localhost`, `aud` = `https://management.azure.com`), the expiry
timestamp, and `cached: true`.

`arm-smoke.mjs` - currently:

```
404 ResourceNotFound
{"error":{"code":"ResourceNotFound","message":"Provisio has no handler for '/subscriptions' yet."}}
```

The 404 is the passing grade for now: it means the SDK's token cleared
authentication and fell through to the not-yet-implemented ARM dispatch.
A `401` means authentication regressed. This section will change as ARM
providers land.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `ERR_MODULE_NOT_FOUND` on some `@azure`/`@typespec` module | Torn `node_modules` - run `npm ci` (not `npm install`, which trusts the stale manifest) |
| `fetch failed` / `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | `NODE_EXTRA_CA_CERTS` missing or wrong path - run from the repo root |
| `ENOTFOUND management.localhost` | Hosts entries missing (or eaten by WSL regeneration - see repo README) |
| `ECONNREFUSED` | Server not running in Terminal A |
| `401 InvalidAuthenticationTokenAudience` | Token requested for the wrong scope - the SDK must ask for `https://management.azure.com/.default` (the audience is Azure's logical id, not the emulator's hostname) |
