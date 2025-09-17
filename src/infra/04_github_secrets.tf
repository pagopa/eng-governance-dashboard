resource "github_repository_environment" "prod_cd" {
  environment = "prod-cd"
  repository  = var.github.repository
  # prevent_self_review = true
  # reviewers {
  #   users = [data.github_user.current.id]
  # }
  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }
}

resource "github_actions_environment_secret" "azure_cd_tenant_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_TENANT_ID"
  plaintext_value = data.azurerm_client_config.current.tenant_id
}

#tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
resource "github_actions_environment_secret" "azure_cd_subscription_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_SUBSCRIPTION_ID"
  plaintext_value = data.azurerm_subscription.current.subscription_id
}

#tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
resource "github_actions_environment_secret" "azure_cd_client_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_CLIENT_ID"
  plaintext_value = azurerm_user_assigned_identity.main.client_id
}

#tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
resource "github_actions_environment_secret" "azure_cd_workspace_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_WORKSPACE_ID"
  plaintext_value = azurerm_log_analytics_workspace.data.workspace_id
}

#tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
resource "github_actions_environment_secret" "azure_cd_workspace_key" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_WORKSPACE_KEY"
  plaintext_value = azurerm_log_analytics_workspace.data.primary_shared_key
}

#tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
resource "github_actions_environment_secret" "azure_cd_storageaccount_name" {
  repository      = var.github.repository
  environment     = github_repository_environment.prod_cd.environment
  secret_name     = "AZURE_STORAGE_ACCOUNT_NAME"
  plaintext_value = azurerm_storage_account.data.name
}

# #tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
# resource "github_actions_environment_secret" "azure_cd_workspace_dcr_id" {
#   repository      = var.github.repository
#   environment     = github_repository_environment.prod_cd.environment
#   secret_name     = "AZURE_WORKSPACE_DCR_ID"
#   plaintext_value = azurerm_monitor_data_collection_rule.data.immutable_id
# }

# #tfsec:ignore:github-actions-no-plain-text-action-secrets # not real secret
# resource "github_actions_environment_secret" "azure_cd_workspace_dce_id" {
#   repository      = var.github.repository
#   environment     = github_repository_environment.prod_cd.environment
#   secret_name     = "AZURE_WORKSPACE_DCE_ID"
#   plaintext_value = azurerm_monitor_data_collection_endpoint.data.immutable_id
# }
