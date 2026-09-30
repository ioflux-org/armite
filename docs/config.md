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
  `PROVISIO_IMDS_ADDR`, `PROVISIO_CERT_DIR`) apply after the file.

## Keys

| key                                                          | default                                                                 | meaning                                                                                                                                           |
| ------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tenant_id`, `subscription_id`                               | `1111…`, `2222…`                                                        | the one tenant and subscription                                                                                                                   |
| `subscription_name`, `tenant_name`, `default_resource_group` | `Provisio Subscription`, `Provisio`, `default-rg`                       | names shown by `az account`                                                                                                                       |
| `listener_addr`                                              | `127.0.0.1:8443`                                                        | ARM, login and every vault; the port is part of every URL                                                                                         |
| `arm_host`, `login_host`, `vault_host`                       | `management.localhost`, `login.localhost`, `vault.localhost`            | bare hostnames; vaults are `{name}.vault_host`                                                                                                    |
| `arm_audience`                                               | `https://management.azure.com`                                          | the ARM token audience clients ask for                                                                                                            |
| `clients[]`                                                  | one built-in principal                                                  | `id`, `secret`, `object_id`: service principals that can log in                                                                                   |
| `imds_addr`                                                  | `127.0.0.1:8081`                                                        | the managed identity endpoint                                                                                                                     |
| `managed_identity`                                           | `client_id` `5555…`, `object_id` `6666…`                                | the principal IMDS issues tokens for; it has no secret                                                                                            |
| `role_assignments[]`                                         | Owner for the client, Contributor for the identity, at the subscription | granted at boot; `principal_id` must be a client's or the identity's `object_id`; `role_definition_id` is a built-in role GUID or a full ARM path |

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

## What a bad file looks like

```text
config: provisio.yaml:
line 12: field vault_hots not found
    12 | vault_hots: kv.local
clients[0].secret: must not be empty
```
