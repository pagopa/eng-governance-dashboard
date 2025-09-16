data "azurerm_management_group" "pagopa" {
  name = "pagopa"
}

data "azurerm_resource_group" "identity" {
  name     = "${local.project}-identity-rg"
}