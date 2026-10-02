#############################################
# AgentLedger — hardened reference infrastructure
#
# Authored and scanned (Checkov) as a secure baseline. NOT deployed in this
# project: there is no `terraform apply`, so it incurs no Azure cost. The value
# is the hardened, policy-checked IaC itself.
#############################################

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.100"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "soc" {
  name     = var.resource_group_name
  location = var.location
}

# User-assigned managed identity — the gateway/agent authenticates with this,
# so there are no client secrets to leak (replaces the app secret used in S7).
resource "azurerm_user_assigned_identity" "agent" {
  name                = "id-agentledger"
  resource_group_name = azurerm_resource_group.soc.name
  location            = azurerm_resource_group.soc.location
}

# Hardened storage account — audit log / Terraform state backend.
resource "azurerm_storage_account" "audit" {
  name                              = var.storage_account_name
  resource_group_name               = azurerm_resource_group.soc.name
  location                          = azurerm_resource_group.soc.location
  account_tier                      = "Standard"
  account_replication_type          = "GRS"
  min_tls_version                   = "TLS1_2"
  enable_https_traffic_only         = true
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false
  infrastructure_encryption_enabled = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
    container_delete_retention_policy {
      days = 7
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  sas_policy {
    expiration_period = "00.01:00:00"
  }
}

# Hardened Key Vault — holds the Ed25519 audit signing key.
resource "azurerm_key_vault" "kv" {
  name                          = var.key_vault_name
  resource_group_name           = azurerm_resource_group.soc.name
  location                      = azurerm_resource_group.soc.location
  tenant_id                     = var.tenant_id
  sku_name                      = "standard"
  enable_rbac_authorization     = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 7
  public_network_access_enabled = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

# Network security group — default deny; no inbound SSH/RDP from the internet.
resource "azurerm_network_security_group" "soc" {
  name                = "nsg-agentledger"
  resource_group_name = azurerm_resource_group.soc.name
  location            = azurerm_resource_group.soc.location

  security_rule {
    name                       = "deny-all-inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# Azure Policy — enforce that storage accounts restrict network access.
resource "azurerm_resource_group_policy_assignment" "restrict_storage" {
  name                 = "restrict-storage-network"
  resource_group_id    = azurerm_resource_group.soc.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c"
  description          = "Storage accounts should restrict network access"
}
