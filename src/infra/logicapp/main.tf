terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">=3.70.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

#resource "azurerm_resource_group" "rg" {
#  name     = var.resource_group_name
#  location = var.location
#}

# Logic App con identità gestita
resource "azurerm_logic_app_workflow" "this" {
  name                = var.logicapp_name
  location            = var.location
  resource_group_name = var.resource_group_name
  workflow_schema     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
  workflow_version    = "1.0.0.0"
  #workflow_parameters = {"$connections" = <<JSON
  #{"value": {"azureblob": {"id": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/providers/Microsoft.Web/locations/italynorth/managedApis/azureblob", "connectionId": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/resourceGroups/exportadvisorpolicyalert-dev-itn-rg/providers/Microsoft.Web/connections/azureblob", "connectionName": "azureblob", "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}}}, "googledrive": {"id": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/providers/Microsoft.Web/locations/italynorth/managedApis/googledrive", "connectionId": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/resourceGroups/exportadvisorpolicyalert-dev-itn-rg/providers/Microsoft.Web/connections/googledrive", "connectionName": "googledrive"}, "googlesheet": {"id": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/providers/Microsoft.Web/locations/italynorth/managedApis/googlesheet", "connectionId": "/subscriptions/ac17914c-79bf-48fa-831e-1359ef74c1d5/resourceGroups/exportadvisorpolicyalert-dev-itn-rg/providers/Microsoft.Web/connections/googlesheet", "connectionName": "googlesheet"}}}
  #JSON
  #}


  identity {
    type = "SystemAssigned"
  }

  #parameters = {
  #  "$connections" = jsonencode({
  #    azureblob = {
  #      connectionId   = azurerm_api_connection.azureblob.id
  #      connectionName = azurerm_api_connection.azureblob.name
  #      id             = azurerm_api_connection.azureblob.managed_api_id
  #    }
  #   googledrive = {
  #      connectionId   = azurerm_api_connection.googledrive.id
  #     connectionName = azurerm_api_connection.googledrive.name
  #     id             = azurerm_api_connection.googledrive.managed_api_id
  #   }
  #   googlesheet = {
  #     connectionId   = azurerm_api_connection.googlesheet.id
  #    connectionName = azurerm_api_connection.googlesheet.name
  #     id             = azurerm_api_connection.googlesheet.managed_api_id
  #   }
  #  })
  #}

  depends_on = [
    azurerm_api_connection.azureblob,
    azurerm_api_connection.googledrive,
    azurerm_api_connection.googlesheet
  ]

}

# Connections

resource "azurerm_api_connection" "azureblob" {
  name                = "azureblob-terraform"
  resource_group_name = var.resource_group_name
  managed_api_id      = "/subscriptions/${var.subscription_id}/providers/Microsoft.Web/locations/${var.location}/managedApis/azureblob"

}


resource "azurerm_api_connection" "googledrive" {
  name                = "googledrive-terraform"
  resource_group_name = var.resource_group_name
  managed_api_id      = "/subscriptions/${var.subscription_id}/providers/Microsoft.Web/locations/${var.location}/managedApis/googledrive"
}

resource "azurerm_api_connection" "googlesheet" {
  name                = "googlesheet-terraform"
  resource_group_name = var.resource_group_name
  managed_api_id      = "/subscriptions/${var.subscription_id}/providers/Microsoft.Web/locations/${var.location}/managedApis/googlesheet"
}

resource "azurerm_logic_app_action_custom" "get_blob_content_all_alert" {
  name         = "Get_blob_content_ALL_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['azureblob']['connectionId']"
        }
      },
      "method" : "get",
      "path" : "/v2/datasets/@{encodeURIComponent(encodeURIComponent('https://exportalertdevitnrg.blob.core.windows.net/'))}/files/@{encodeURIComponent(encodeURIComponent('JTJmY3N2JTJmbG9nX2FuYWx5dGljc19sYXN0MzBkYXlzLmNzdg=='))}/content",
      "queries" : {
        "inferContentType" : true
      }
    },
    "runAfter" : {}
  })
}


resource "azurerm_logic_app_action_custom" "create_file_all_alert" {
  name         = "Create_file_ALL_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['googledrive']['connectionId']"
        }
      },
      "method" : "post",
      "body" : "@body('Get_blob_content_ALL_Alert')",
      "path" : "/datasets/default/files",
      "queries" : {
        "folderPath" : "/csv/",
        "name" : "log_analytics_last30days.csv",
        "queryParametersSingleEncoded" : true
      }
    },
    "runAfter" : {
      "Get_blob_content_ALL_Alert" : [
        "Succeeded"
      ]
    }
  })
}


resource "azurerm_logic_app_action_custom" "get_blob_content_sintetico_alert" {
  name         = "Get_blob_content_Sintetico_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['azureblob']['connectionId']"
        }
      },
      "method" : "get",
      "path" : "/v2/datasets/@{encodeURIComponent(encodeURIComponent('https://exportalertdevitnrg.blob.core.windows.net/'))}/files/@{encodeURIComponent(encodeURIComponent('JTJmY3N2JTJmc2ludGVzaV9sYXN0MzBkYXlzLmNzdg=='))}/content",
      "queries" : {
        "inferContentType" : true
      }
    },
    "runAfter" : {}
  })
}


resource "azurerm_logic_app_action_custom" "create_file_sintetico_alert" {
  name         = "Create_file_Sintetico_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['googledrive']['connectionId']"
        }
      },
      "method" : "post",
      "body" : "@body('Get_blob_content_Sintetico_Alert')",
      "path" : "/datasets/default/files",
      "queries" : {
        "folderPath" : "/csv/",
        "name" : "sintesi_last30days.csv",
        "queryParametersSingleEncoded" : true
      }
    },
    "runAfter" : {
      "Get_blob_content_Sintetico_Alert" : [
        "Succeeded"
      ]
    }
  })
}


resource "azurerm_logic_app_action_custom" "update_file_all" {
  name         = "Update_file_ALL"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['googledrive']['connectionId']"
        }
      },
      "method" : "put",
      "body" : "@body('Get_blob_content_ALL_Alert')",
      "path" : "/datasets/default/files/@{encodeURIComponent(encodeURIComponent('1QMoMHXZZQ3XAdZJdnmLNPKCs9PKB5jNu'))}"
    },
    "runAfter" : {
      "Create_file_ALL_Alert" : [
        "Failed",
        "Succeeded"
      ]
    }
  })
  depends_on = [
    azurerm_logic_app_action_custom.create_file_all_alert
  ]
}


resource "azurerm_logic_app_action_custom" "update_file_sintetico" {
  name         = "Update_file_Sintetico"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['googledrive']['connectionId']"
        }
      },
      "method" : "put",
      "body" : "@body('Get_blob_content_Sintetico_Alert')",
      "path" : "/datasets/default/files/@{encodeURIComponent(encodeURIComponent('1UJEPSY1ZeLaxNJ_xDOPIOecXUBvIcVET'))}"
    },
    "runAfter" : {
      "Create_file_Sintetico_Alert" : [
        "Succeeded",
        "Failed"
      ]
    }
  })
  depends_on = [
    azurerm_logic_app_action_custom.create_file_sintetico_alert
  ]
}


resource "azurerm_logic_app_action_custom" "get_blob_content_sintetico_json" {
  name         = "Get_blob_content_Sintetico_Json"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
        "connection" : {
          "name" : "@parameters('$connections')['azureblob']['connectionId']"
        }
      },
      "method" : "get",
      "path" : "/v2/datasets/@{encodeURIComponent(encodeURIComponent('https://exportalertdevitnrg.blob.core.windows.net'))}/files/@{encodeURIComponent(encodeURIComponent('JTJmY3N2JTJmc2ludGVzaV9sYXN0MzBkYXlzLmpzb24='))}/content",
      "queries" : {
        "inferContentType" : true
      }
    },
    "runAfter" : {}
  })
}


resource "azurerm_logic_app_action_custom" "parse_json" {
  name         = "Parse_JSON"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ParseJson",
    "inputs" : {
      "content" : "@json(body('Get_blob_content_Sintetico_Json'))",
      "schema" : {
        "type" : "array",
        "items" : {
          "type" : "object",
          "properties" : {
            "prodotto" : {
              "type" : "string"
            },
            "data" : {
              "type" : "string"
            },
            "issue_totali" : {
              "type" : "integer"
            },
            "issue_high" : {
              "type" : "integer"
            },
            "issue_medium" : {
              "type" : "integer"
            },
            "issue_low" : {
              "type" : "integer"
            },
            "issue_dismissed" : {
              "type" : "integer"
            },
            "change_last_12_month" : {
              "type" : "integer"
            },
            "change_last_month" : {
              "type" : "integer"
            }
          },
          "required" : [
            "prodotto",
            "data",
            "issue_totali",
            "issue_high",
            "issue_medium",
            "issue_low",
            "issue_dismissed",
            "change_last_12_month",
            "change_last_month"
          ]
        }
      }
    },
    "runAfter" : {
      "Get_blob_content_Sintetico_Json" : [
        "Succeeded"
      ]
    }
  })
  depends_on = [
    azurerm_logic_app_action_custom.get_blob_content_sintetico_json
  ]
}


resource "azurerm_logic_app_action_custom" "for_each" {
  name         = "For_each"
  logic_app_id = azurerm_logic_app_workflow.this.id

  body = jsonencode({
    type    = "Foreach",
    foreach = "@body('Parse_JSON')",
    actions = {
      Insert_row = {
        type = "ApiConnection",
        inputs = {
          host = {
            connection = {
              name = "@parameters('$connections')['googlesheet']['connectionId']"
            }
          },
          method = "post",
          body = {
            prodotto             = "@item()['prodotto']",
            data                 = "@item()['data']",
            issue_totali         = "@int(item()['issue_totali'])",
            issue_high           = "@item()['issue_high']",
            issue_medium         = "@item()['issue_medium']",
            issue_low            = "@item()['issue_low']",
            issue_dismissed      = "@item()['issue_dismissed']",
            change_last_12_month = "@item()['change_last_12_month']",
            change_last_month    = "@item()['change_last_month']"
          },
          path = "/datasets/@{encodeURIComponent(encodeURIComponent('1ydzkrPsJ8TBO87plq0pGJWVdsBI_gd2xWkEiiMzVYI4'))}/tables/@{encodeURIComponent(encodeURIComponent('602137759'))}/items"
        },
        operationOptions = "DisableAsyncPattern, DisableAutomaticDecompression",
        metadata = {
          "1ydzkrPsJ8TBO87plq0pGJWVdsBI_gd2xWkEiiMzVYI4" = "/csv/Dahsboard_Update"
        }
      }
    },
    runAfter = {
      Parse_JSON = ["Succeeded"]
    },
    runtimeConfiguration = {
      concurrency = {
        repetitions = 1
      }
    }
  })
  depends_on = [
    azurerm_logic_app_action_custom.parse_json
  ]
}


resource "azurerm_logic_app_trigger_http_request" "manual" {
  name         = "http-trigger"
  logic_app_id = azurerm_logic_app_workflow.this.id
  schema       = "{}"
}
