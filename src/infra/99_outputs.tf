output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "logicapp_id" {
  value = azurerm_logic_app_workflow.this.id
}

output "logicapp_endpoint" {
  value = azurerm_logic_app_workflow.this.access_endpoint
}
