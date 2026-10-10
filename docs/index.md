---
layout: home
title: Armite
titleTemplate: A local Azure emulator with real identity and RBAC

hero:
  name: Lab-grown Azure.
  text: Real identity. Real RBAC. On your machine.
  tagline: A local Azure emulator. Your application, the Azure CLI, the SDKs and Terraform talk to Armite exactly as they talk to Azure, and a principal without the right role gets the same 403 it would get in production.
  image:
    light: /armite-symbol.svg
    dark: /armite-symbol-dark.svg
    alt: The Armite crystal
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: How it differs from Azure
      link: /divergences
    - theme: alt
      text: GitHub
      link: https://github.com/ioflux-org/armite

features:
  - title: A real identity plane
    details: An Entra ID token endpoint, OpenID discovery, JWKS and IMDS for managed identity. Tokens are minted and verified.
  - title: Real RBAC
    details: All 934 built-in roles with Azure's glob semantics, assignments at any scope and deny by default, on the management plane and the data plane.
  - title: Key Vault and Storage
    details: Vaults and secrets with versions, soft delete, recover and purge. Storage accounts with a blob data plane, served by Azurite behind the RBAC layer.
  - title: Unmodified clients
    details: Verified end to end with az, the Azure SDKs for JavaScript and Python, Terraform's azurerm provider and curl.
---

## "But I'm Owner?!"

```text
$ az keyvault secret set --vault-name kv-demo -n db-pass --value hunter2
(Forbidden) Caller is not authorized to perform action on resource.
Caller: appid=33333333-...;oid=44444444-...
Action: 'Microsoft.KeyVault/vaults/secrets/setSecret/action'
Resource: '/subscriptions/.../vaults/kv-demo/secrets/db-pass'
DecisionReason: 'DeniedWithNoValidRBAC'
Inner error: {"code": "ForbiddenByRbac"}
```

That caller is **Owner** of the subscription. Owner carries every
management-plane action and not one data-plane action, so on an
RBAC-mode vault it cannot read or write a secret until a data role such
as Key Vault Secrets Officer is assigned. It is one of Azure's most
common surprises; with Armite it happens on your laptop and in CI
instead of in production.

[Run this demo yourself →](./getting-started.md#the-demo)
