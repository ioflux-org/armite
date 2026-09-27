# Terraform against Provisio

The azurerm provider, unmodified, creating a resource group, a Key Vault,
a role assignment and a secret in Provisio - and being refused the secret
until the role assignment exists.

## Prerequisites

1. **Provisio running** from the repository root: `go run ./cmd/provisio`.
2. **Hosts entries** (`/etc/hosts`; WSL2 regenerates the file unless
   `generateHosts = false` is set in `/etc/wsl.conf`):

   ```text
   127.0.0.1  management.localhost
   127.0.0.1  login.localhost
   127.0.0.1  kv-demo.vault.localhost
   ```

3. **Trust the CA.** Terraform is a Go program and honours `SSL_CERT_FILE`,
   so no system-wide install is needed:

   ```bash
   export SSL_CERT_FILE=$PWD/certs/ca.pem   # from the repository root
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

terraform destroy
```

The first apply exits non-zero on purpose and leaves the resource group
and the vault in the state; the second apply adds the assignment and the
secret. `terraform destroy` removes all four, purging the vault on the
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
own pollers: about 20 s for the resource group and the role assignment,
about 20 s to soft-delete and purge the secret. A vault with
`public_network_access_enabled = true` (`-var public_vault=true`) adds
the provider's availability poll, ten checks ten seconds apart after a
30 s delay, about 2 min 10 s - the same wait as against real Azure.

## State and lock file

`terraform.tfstate` is local and ignored by git. `.terraform.lock.hcl` is
committed with checksums for Linux, macOS and Windows so `init` verifies
the provider on any machine; regenerate it with

```bash
terraform providers lock -platform=linux_amd64 -platform=linux_arm64 \
  -platform=darwin_amd64 -platform=darwin_arm64 -platform=windows_amd64
```
