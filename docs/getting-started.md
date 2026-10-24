# Getting started

Armite is a single Go program, with Azurite beside it for storage
accounts. Three ways to run it:

```bash
# The image: Azurite inside, nothing to install (see Running in Docker)
docker run -d --name armite -p 127.0.0.1:8443:8443 -p 127.0.0.1:8081:8081 \
  -v armite:/data ghcr.io/ioflux-org/armite

# A binary: Go 1.26, or the archive for your platform from the releases page
go install github.com/ioflux-org/armite/cmd/armite@latest && armite

# A clone
git clone https://github.com/ioflux-org/armite && cd armite && go run ./cmd/armite
```

Every route, with the archive for each platform and its checksum, is
on [Install](./install.md).

The server generates a private CA in `~/.armite/` at first boot, keeps
what you create in your data directory (`~/.local/share/armite` on
Linux), and serves `https://management.localhost:8443` (ARM),
`https://login.localhost:8443` (Entra), `https://{vault}.vault.localhost:8443`
(Key Vault data plane) and `https://{account}.blob.core.localhost:8443`
(blobs), plus IMDS on `http://127.0.0.1:8081`.
Storage accounts need Azurite: with Node.js on the machine, `armite
azurite install` puts a pinned copy where the server finds it (the
Docker image has it built in; `npm install -g azurite` works too) and
they are otherwise off. See [Running in Docker](./docker.md) for
the container route.

Two things every client needs:

1. **Hostnames** resolving to 127.0.0.1. Linux with systemd-resolved
   does it already; WSL2 and macOS need a one-time resolver fix or the
   `/etc/hosts` lines `armite hosts` prints — see [Hostnames](./dns.md).
2. **The CA.** `~/.armite/ca.pem`, passed per client (`curl --cacert`,
   `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`).

`armite doctor` checks both, plus the ports and Azurite, and says what
to fix; `armite reset` starts over with an empty state and the same CA.

## The demo

<video controls muted playsinline preload="metadata" style="width:100%;border-radius:8px"
  src="/demo/hero.mp4"></video>

The Azure CLI, in a config directory of its own so your real Azure login
is untouched:

```bash
export AZURE_CONFIG_DIR=$HOME/.azure-armite REQUESTS_CA_BUNDLE=$HOME/.armite/ca.pem
az cloud set -n AzureCloud 2>/dev/null; az cloud unregister -n Armite 2>/dev/null
az cloud register -n Armite --endpoint-resource-manager https://management.localhost:8443
az cloud set -n Armite
az config set core.instance_discovery=false
az login --service-principal -u 33333333-3333-3333-3333-333333333333 \
  -p armite-secret --tenant 11111111-1111-1111-1111-111111111111

az group create -n kv-rg -l eastus
az keyvault create -n kv-demo -g kv-rg -l eastus --enable-rbac-authorization
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2   # 403
az role assignment create --role "Key Vault Secrets Officer" \
  --assignee-object-id 44444444-4444-4444-4444-444444444444 \
  --assignee-principal-type ServicePrincipal \
  --scope $(az keyvault show -n kv-demo -g kv-rg --query id -o tsv)
az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2   # 200
```

The same demo through the SDK is
[`scripts/sdk-smoke/keyvault-smoke.mjs`](https://github.com/ioflux-org/armite/blob/main/scripts/sdk-smoke/keyvault-smoke.mjs),
and through Terraform
[`examples/terraform`](https://github.com/ioflux-org/armite/tree/main/examples/terraform).
The storage twin — Owner creates a container and cannot upload a blob —
is in [Storage accounts and blobs](./storage.md). Client setup for every
tool is in [Client setup](./clients.md).

## Built-in identities

Armite is one tenant with one subscription and two principals, all
fixed and documented, so nothing needs registering:

|                                                    | value                                                                                                                |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Tenant                                             | `11111111-1111-1111-1111-111111111111`                                                                               |
| Subscription                                       | `22222222-2222-2222-2222-222222222222`                                                                               |
| Service principal (Owner of the subscription)      | client `33333333-3333-3333-3333-333333333333`, secret `armite-secret`, object `44444444-4444-4444-4444-444444444444` |
| Managed identity (Contributor of the subscription) | client `55555555-5555-5555-5555-555555555555`, object `66666666-6666-6666-6666-666666666666`, via IMDS               |

The managed identity is the one your production code path uses:
`DefaultAzureCredential` with `AZURE_POD_IDENTITY_AUTHORITY_HOST=http://127.0.0.1:8081`
and no secret anywhere, exactly as on a VM, and its roles are enforced.
