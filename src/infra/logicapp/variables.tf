variable "subscription_id" {
  type        = string
  description = "Azure Subscription ID"
  default     = "ac17914c-79bf-48fa-831e-1359ef74c1d5"
}

variable "resource_group_name" {
  type        = string
  description = "Nome del Resource Group"
  default     = "exportadvisorpolicyalert-dev-itn-rg"
}

variable "location" {
  type        = string
  description = "Location Azure (es: westeurope)"
  default     = "italynorth"
}

variable "logicapp_name" {
  type        = string
  description = "Nome della Logic App"
  default     = "export-alert-dev-itn-rg-terraform"
}

variable "googlesheet_dataset_id" {
  type        = string
  description = "ID del dataset di Google Sheet"
}

variable "googlesheet_table_id" {
  type        = string
  description = "ID della tabella di Google Sheet"
}
