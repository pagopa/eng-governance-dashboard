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

resource "azurerm_role_assignment" "storage_account_contributor" {
  scope                = azurerm_storage_account.data.id
  role_definition_name = "Storage Account Contributor"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}

resource "azurerm_role_assignment" "storage_account_blob_contributor" {
  scope                = azurerm_storage_account.data.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}

resource "azurerm_role_assignment" "log_analytics_contributor" {
  scope                = azurerm_log_analytics_workspace.data.id
  role_definition_name = "Log Analytics Contributor"
  principal_id         = azurerm_user_assigned_identity.main.principal_id
}
