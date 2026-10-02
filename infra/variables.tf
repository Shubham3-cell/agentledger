variable "resource_group_name" {
  type        = string
  description = "Resource group for the AgentLedger SOC infrastructure."
  default     = "rg-agentledger-soc"
}

variable "location" {
  type        = string
  description = "Azure region."
  default     = "australiaeast"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique storage account name."
  default     = "stagentledgeraudit01"
}

variable "key_vault_name" {
  type        = string
  description = "Key Vault name for the audit signing key."
  default     = "kv-agentledger-01"
}

variable "tenant_id" {
  type        = string
  description = "Entra tenant id for Key Vault access (supplied at apply time)."
  default     = "00000000-0000-0000-0000-000000000000"
}
