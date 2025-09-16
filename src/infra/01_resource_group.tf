resource "azurerm_resource_group" "data" {
  name     = "${local.project}-govd-rg"
  location = var.location
}