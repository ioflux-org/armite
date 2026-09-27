variable "grant_secrets_officer" {
  description = "Grant the Owner 'Key Vault Secrets Officer' on the vault. false = watch the 403."
  type        = bool
  default     = true
}

variable "public_vault" {
  description = "Vault public_network_access_enabled. true costs the provider's ~2 minute wait."
  type        = bool
  default     = false
}
