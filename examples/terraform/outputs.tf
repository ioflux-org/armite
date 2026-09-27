output "vault_uri" {
  value = azurerm_key_vault.demo.vault_uri
}

output "secret_id" {
  value = azurerm_key_vault_secret.db.id
}
