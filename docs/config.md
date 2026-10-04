# Configuration

Provisio runs with no configuration file. To change anything, generate
the commented template and edit it:

```bash
provisio config init          # writes ./provisio.yaml with every key and its default
provisio config show          # the effective configuration, secrets masked
provisio config show --secrets
provisio config check         # validate the file without starting the server
```

With `go run`, replace `provisio` by `go run ./cmd/provisio`.

The server reads the file named by `PROVISIO_CONFIG`, else `./provisio.yaml`
when it exists, else it runs on the defaults; the boot log says which.
Every key is optional: delete the ones you do not change and their
defaults apply.

Three rules to know:

- A list you keep (`clients`, `role_assignments`) replaces the default
  list; it does not add to it. To add a client, keep the built-in one in
  the list too.
- An unknown key stops the boot, with the line and the offending text.
  So does an invalid value; every problem in the file is reported at once.
- The environment variables from the Docker image (`PROVISIO_LISTEN_ADDR`,
  `PROVISIO_IMDS_ADDR`, `PROVISIO_CERT_DIR`, `PROVISIO_STATE_DIR`, `PROVISIO_STATE_KEY`,
  `PROVISIO_LOG_FORMAT`) apply after the file.

## Keys

| key                                                          | default                                                                 | meaning                                                                                                                                           |
| ------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tenant_id`, `subscription_id`                               | `1111…`, `2222…`                                                        | the one tenant and subscription                                                                                                                   |
| `subscription_name`, `tenant_name`, `default_resource_group` | `Provisio Subscription`, `Provisio`, `default-rg`                       | names shown by `az account`                                                                                                                       |
| `listener_addr`                                              | `127.0.0.1:8443`                                                        | ARM, login and every vault; the port is part of every URL                                                                                         |
| `arm_host`, `login_host`, `vault_host`                       | `management.localhost`, `login.localhost`, `vault.localhost`            | bare hostnames; vaults are `{name}.vault_host`                                                                                                    |
| `blob_host`                                                  | `blob.core.localhost`                                                   | storage accounts are `{name}.blob_host`; must start with `blob.` (see [storage.md](storage.md))                                                   |
| `arm_audience`                                               | `https://management.azure.com`                                          | the ARM token audience clients ask for                                                                                                            |
| `clients[]`                                                  | one built-in principal                                                  | `id`, `secret`, `object_id`: service principals that can log in                                                                                   |
| `imds_addr`                                                  | `127.0.0.1:8081`                                                        | the managed identity endpoint                                                                                                                     |
| `managed_identity`                                           | `client_id` `5555…`, `object_id` `6666…`                                | the principal IMDS issues tokens for; it has no secret                                                                                            |
| `role_assignments[]`                                         | Owner for the client, Contributor for the identity, at the subscription | granted at boot; `principal_id` must be a client's or the identity's `object_id`; `role_definition_id` is a built-in role GUID or a full ARM path |
| `state.dir`                                                  | `state`                                                                 | where resources, assignments and secrets persist; `""` keeps them in memory (see [persistence.md](persistence.md))                                |
| `state.compact_after_mb`                                     | `8`                                                                     | journal size past which it is folded into the snapshot; `0` never                                                                                 |
| `state.key`                                                  | `""` (generated into `certs/`)                                          | base64 32-byte key the state files are encrypted with (`openssl rand -base64 32`)                                                                 |
| `azurite.mode`                                               | `managed`                                                               | who runs the blob store: `managed` (Provisio starts `azurite-blob`), `byo` (yours) or `off`                                                       |
| `azurite.command`, `azurite.port`                            | `azurite-blob`, `10000`                                                 | managed mode: the executable (on PATH) and its loopback port                                                                                      |
| `azurite.upstream`, `azurite.accounts[]`                     |                                                                         | byo mode: your Azurite's URL, and the `name` + base64 `key` of each account it knows                                                              |
| `log.format`                                                 | `text`                                                                  | `text` for a terminal, `json` for a collector; one line per request either way (see below)                                                        |

Role GUIDs are Azure's fixed built-in ones:
`az role definition list --query "[].{name:roleName,id:name}"`.

## A common tweak

Owner carries no data-plane actions, so the demo principal cannot use a
vault until it is granted a data role. Seeding that role at boot removes
the assignment step:

```yaml
role_assignments:
  - principal_id: 44444444-4444-4444-4444-444444444444
    role_definition_id: 8e3af657-a8ff-443c-a75c-2fe8c4bcb635 # Owner
    scope: /subscriptions/22222222-2222-2222-2222-222222222222
  - principal_id: 44444444-4444-4444-4444-444444444444
    role_definition_id: b86a8fe4-44ce-4948-aee5-eccb2c155cd7 # Key Vault Secrets Officer
    scope: /subscriptions/22222222-2222-2222-2222-222222222222
```

The first entry keeps Owner, because the list replaces the defaults. If
you change a principal's `object_id`, update `role_assignments` too: a
seed naming an unknown principal is refused at boot.

## Logs and request ids

Every response carries an `x-ms-request-id`, as Azure's do, and every
request is one log line under that id:

```text
2026/10/04 16:35:06 INFO request id=2655f423-3e08-4301-b9bf-6ed5107f0710 plane=blob method=PUT host=stdemo.blob.core.localhost:8443 path=/demo/hello.txt status=403 bytes=595 duration=182µs error=AuthorizationPermissionMismatch client_request_id=7456ec8f-…
```

`plane` is `arm`, `entra`, `vault`, `blob` or `imds`; `error` is the
`x-ms-error-code` of a refused request; `client_request_id` is the
`x-ms-client-request-id` the client sent (az and the SDKs send one per
call), echoed on the response too. A SAS signature in the query is
logged as `sig=REDACTED`.

To find the line for an error a client shows: `curl -i` prints the
header; `az --debug` prints it for management-plane calls
(`'X-Ms-Request-Id'`); storage errors carry `RequestId:` in the message,
as Azure's do. Then `grep` the id in the server's output.

`log.format: json` (or `PROVISIO_LOG_FORMAT=json`) writes one JSON
object per line instead, for a log collector — every line, the boot
messages included; `duration` is then in nanoseconds:

```text
{"time":"2026-10-04T16:36:12.98+05:30","level":"INFO","msg":"request","id":"865ece34-df15-461b-8bb8-45d289b6d026","plane":"arm","method":"GET","host":"management.localhost:8443","path":"/subscriptions?api-version=2022-12-01","status":401,"bytes":154,"duration":176395,"error":"AuthenticationFailed"}
```

## What a bad file looks like

```text
config: provisio.yaml:
line 12: field vault_hots not found
    12 | vault_hots: kv.local
clients[0].secret: must not be empty
```
