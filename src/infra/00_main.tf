terraform {
  required_version = ">= 1.7.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "3.4.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "4.35.0"
    }
    github = {
      source  = "integrations/github"
      version = "6.6.0"
    }
  }

  backend "azurerm" {}
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "github" {
  owner = var.github.org
}

data "azurerm_subscription" "current" {}

data "azurerm_client_config" "current" {}
