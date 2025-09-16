resource "azurerm_storage_account" "data" {
    name                     = replace("${local.project}govd-st", "-", "")
    resource_group_name      = azurerm_resource_group.data.name
    location                 = azurerm_resource_group.data.location
    account_tier             = "Standard"
    account_replication_type = "ZRS"
    allow_nested_items_to_be_public = false
    
    identity {
        type = "SystemAssigned"
    }
    
    # tags = var.tags
}