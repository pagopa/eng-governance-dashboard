resource "azurerm_log_analytics_workspace" "data" {
  name                = "${local.project}-govd-law"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  sku                 = "PerGB2018"
  retention_in_days   = 360

  # tags = var.tags
}

# resource "azurerm_monitor_data_collection_endpoint" "data" {
#   name                = "${local.project}-govd-dce"
#   location            = azurerm_resource_group.data.location
#   resource_group_name = azurerm_resource_group.data.name
# }

# resource "azurerm_monitor_data_collection_rule" "data" {
#   name                = "${local.project}-govd-dcr"
#   location            = azurerm_resource_group.data.location
#   resource_group_name = azurerm_resource_group.data.name
#   data_collection_endpoint_id = azurerm_monitor_data_collection_endpoint.data.id

#   destinations {
#     log_analytics {
#       name                = "law-destination"
#       workspace_resource_id = azurerm_log_analytics_workspace.data.id
#     }
#   }

#   # data_flow {
#   #   streams = ["Custom-Alert"]
#   #   destinations = ["law-destination"]
#   # }

#   data_flow {
#     streams      = ["Microsoft-InsightsMetrics", "Microsoft-WindowsEvent", "Microsoft-Perf"]
#     destinations = ["law-destination"]
#   }

#   identity {
#     type = "SystemAssigned"
#   }
# }
