output "logicapp_id" {
  value = azurerm_logic_app_workflow.this.id
}

output "logicapp_endpoint" {
  value = azurerm_logic_app_workflow.this.access_endpoint
}
