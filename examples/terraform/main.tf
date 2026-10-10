# Armite's built-in principal and subscription (config.Default()): a
# documented contract, not placeholders. The principal is Owner of the
# subscription on the management plane and holds nothing on the data
# plane until a role assignment says so.
provider "azurerm" {
  features {}

  # Cloud discovery: the provider reads /metadata/endpoints from this host
  # and learns the login endpoint, the ARM endpoint and the vault suffix.
  metadata_host                   = "management.localhost:8443"
  subscription_id                 = "22222222-2222-2222-2222-222222222222"
  tenant_id                       = "11111111-1111-1111-1111-111111111111"
  client_id                       = "33333333-3333-3333-3333-333333333333"
  client_secret                   = "armite-secret"
  use_cli                         = false
  use_msi                         = false
  resource_provider_registrations = "none"

  # Storage data-plane calls (the container and the blob below) with the
  # principal's token instead of the account key, so RBAC applies to them.
  storage_use_azuread = true
}

resource "azurerm_resource_group" "demo" {
  name     = "kv-rg"
  location = "eastus"
}

resource "azurerm_key_vault" "demo" {
  # The vault's hostname must resolve: 127.0.0.1 kv-demo.vault.localhost
  name                       = "kv-demo"
  resource_group_name        = azurerm_resource_group.demo.name
  location                   = azurerm_resource_group.demo.location
  tenant_id                  = "11111111-1111-1111-1111-111111111111"
  sku_name                   = "standard"
  rbac_authorization_enabled = true

  # With public access on, the provider polls the vault host for about two
  # minutes after creation before it calls the vault available - the same
  # wait as against real Azure. Off skips it; Armite enforces neither.
  public_network_access_enabled = var.public_vault
}

# The grant that makes the secret possible. Apply once with
# -var grant_secrets_officer=false to watch the Owner get a 403.
resource "azurerm_role_assignment" "officer" {
  count                = var.grant_secrets_officer ? 1 : 0
  scope                = azurerm_key_vault.demo.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = "44444444-4444-4444-4444-444444444444"
  principal_type       = "ServicePrincipal"
}

resource "azurerm_key_vault_secret" "db" {
  name         = "db-pass"
  value        = "demo-password"
  key_vault_id = azurerm_key_vault.demo.id
  depends_on   = [azurerm_role_assignment.officer]
}

# Storage: the account is a management-plane resource; the container is
# created through ARM too (storage_account_id), the blob through the
# data plane, where only a data role lets the Owner write. Creation takes
# about a minute: the provider probes each data-plane service in turn.
resource "azurerm_storage_account" "demo" {
  # The account's hostname must resolve: 127.0.0.1 stdemo.blob.core.localhost
  name                     = "stdemo"
  resource_group_name      = azurerm_resource_group.demo.name
  location                 = azurerm_resource_group.demo.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# Apply once with -var grant_blob_contributor=false to watch the blob
# upload get a 403 while the container creation succeeds.
resource "azurerm_role_assignment" "blob" {
  count                = var.grant_blob_contributor ? 1 : 0
  scope                = azurerm_storage_account.demo.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = "44444444-4444-4444-4444-444444444444"
  principal_type       = "ServicePrincipal"
}

resource "azurerm_storage_container" "demo" {
  name               = "demo"
  storage_account_id = azurerm_storage_account.demo.id
}

resource "azurerm_storage_blob" "hello" {
  name                   = "hello.txt"
  storage_account_name   = azurerm_storage_account.demo.name
  storage_container_name = azurerm_storage_container.demo.name
  type                   = "Block"
  source_content         = "hello from terraform"
  depends_on             = [azurerm_role_assignment.blob]
}
