output "vault_uri" {
  value = azurerm_key_vault.demo.vault_uri
}

output "secret_id" {
  value = azurerm_key_vault_secret.db.id
}

output "blob_endpoint" {
  value = azurerm_storage_account.demo.primary_blob_endpoint
}

output "blob_url" {
  value = azurerm_storage_blob.hello.url
}
