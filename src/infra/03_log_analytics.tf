resource "azurerm_log_analytics_workspace" "data" {
  name                = "${local.project}-govd-law"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  sku                 = "PerGB2018"
  retention_in_days   = 360

  # tags = var.tags
}