# Terraform against Provisio

The azurerm provider, unmodified, creating a resource group, a Key Vault,
a storage account, two role assignments, a secret, a container and a
blob in Provisio - and being refused the secret and the blob until the
role assignments exist.

## Prerequisites

1. **Provisio running** from the repository root: `go run ./cmd/provisio`.
2. **Hosts entries** (`/etc/hosts`; WSL2 regenerates the file unless
   `generateHosts = false` is set in `/etc/wsl.conf`):

   ```text
   127.0.0.1  management.localhost
   127.0.0.1  login.localhost
   127.0.0.1  kv-demo.vault.localhost
   127.0.0.1  stdemo.blob.core.localhost
   127.0.0.1  stdemo.queue.core.localhost
   127.0.0.1  stdemo.table.core.localhost
   ```

   (or the one-time resolver fix in `docs/dns.md`, after which every
   `*.localhost` name resolves). The queue and table names exist only
   because the provider probes them when it creates the account.

3. **Trust the CA.** Terraform is a Go program and honours `SSL_CERT_FILE`,
   so no system-wide install is needed:

   ```bash
   export SSL_CERT_FILE=$HOME/.provisio/ca.pem
   ```

4. **Terraform 1.5 or newer** (`terraform version`).

## The demo

From this directory (`examples/terraform`):

```bash
terraform init

# 1. The Owner of the subscription creates the vault but cannot write a
#    secret in it: Owner carries no Key Vault data actions.
terraform apply -var grant_secrets_officer=false
#   ... Error: ... GetSecret ... Status=403 Code="Forbidden"
#   ... Action: 'Microsoft.KeyVault/vaults/secrets/getSecret/action'
#   ... InnerError={"code":"ForbiddenByRbac"}

# 2. Grant Key Vault Secrets Officer on the vault; the secret follows.
terraform apply
#   azurerm_role_assignment.officer[0]: Creation complete
#   azurerm_key_vault_secret.db: Creation complete
#   Outputs: secret_id = "https://kv-demo.vault.localhost:8443/secrets/db-pass/..."

# 3. The same story on storage: the Owner creates the account and the
#    container (management actions) and cannot upload the blob (a data
#    action) until Storage Blob Data Contributor is granted.
terraform apply -var grant_blob_contributor=false
#   ... Error: ... hello.txt ... 403 ... AuthorizationPermissionMismatch
#   ... Action: 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
terraform apply
#   azurerm_storage_blob.hello: Creation complete
#   Outputs: blob_url = "https://stdemo.blob.core.localhost:8443/demo/hello.txt"

terraform destroy
```

The applies that exit non-zero do so on purpose and leave what succeeded
in the state; the next apply adds the assignment and the secret or the
blob. `terraform destroy` removes everything, purging the vault on the
way as the provider does by default.

## How the provider is pointed at Provisio

`metadata_host` makes the provider read `https://management.localhost:8443/
metadata/endpoints`, the same document `az cloud register` reads, and
learn the login endpoint, the ARM endpoint and the vault DNS suffix from
it. The credentials in `main.tf` are Provisio's built-in principal
(`config.Default()`), a documented contract. `use_cli = false` stops the
provider from consulting an az login; `resource_provider_registrations =
"none"` stops it from registering providers, which Provisio does not
model (they are all reported as registered).

## Timing

Provisio answers every call at once; the durations are the provider's
own pollers: about 20 s for the resource group and each role
assignment, about 20 s to soft-delete and purge the secret, about a
minute for the storage account (the provider waits for the blob, queue,
file, static-website and table services in turn, ten seconds each). A
vault with `public_network_access_enabled = true` (`-var
public_vault=true`) adds the provider's availability poll, ten checks
ten seconds apart after a 30 s delay, about 2 min 10 s - the same wait
as against real Azure.

## State and lock file

`terraform.tfstate` is local and ignored by git. `.terraform.lock.hcl` is
committed with checksums for Linux, macOS and Windows so `init` verifies
the provider on any machine; regenerate it with

```bash
terraform providers lock -platform=linux_amd64 -platform=linux_arm64 \
  -platform=darwin_amd64 -platform=darwin_arm64 -platform=windows_amd64
```
