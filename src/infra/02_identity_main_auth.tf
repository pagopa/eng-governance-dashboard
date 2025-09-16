# resource "azurerm_role_assignment" "main_authorization_reader" {
#   scope                = data.azurerm_management_group.pagopa.id
#   role_definition_name = "Reader"
#   principal_id         = azurerm_user_assigned_identity.main.principal_id
# }

resource "azurerm_role_assignment" "main_authorization_pagopa_policy_reader" {
  scope                = data.azurerm_management_group.pagopa.id
  role_definition_name = "PagoPA Policy Reader"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}

resource "azurerm_role_assignment" "main_authorization_advisor_review_readers" {
  scope                = data.azurerm_management_group.pagopa.id
  role_definition_name = "Advisor Reviews Reader"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}

# assegnare ruolo RBAC alla managed identity azure con ruoli 
# “Storage Account Contributor, Log Analytics Reader, Advisor Review Reader e PagoPA Policy Reader”

resource "azurerm_role_assignment" "storage_account_contributor" {
  scope                = azurerm_storage_account.data.id
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}

resource "azurerm_role_assignment" "log_analytics_contributor" {
  scope                = azurerm_log_analytics_workspace.data.id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}