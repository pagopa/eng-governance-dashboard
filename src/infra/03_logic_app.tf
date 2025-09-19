resource "azurerm_logic_app_workflow" "this" {
  name                = "${local.project}-govd-law"
  location            = azurerm_resource_group.data.location
  resource_group_name = azurerm_resource_group.data.name
  workflow_schema     = "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#"
  workflow_version    = "1.0.0.0"

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_logic_app_action_custom" "get_blob_content_all_alert" {
  name         = "Get_blob_content_ALL_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
      },
      "method" : "get",
      "path" : "",
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
  depends_on = [
    azurerm_logic_app_action_custom.get_blob_content_all_alert
  ]
}


resource "azurerm_logic_app_action_custom" "get_blob_content_sintetico_alert" {
  name         = "Get_blob_content_Sintetico_Alert"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
      },
      "method" : "get",
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
  depends_on = [
    azurerm_logic_app_action_custom.get_blob_content_sintetico_alert
  ]
}


resource "azurerm_logic_app_action_custom" "update_file_all" {
  name         = "Update_file_ALL"
  logic_app_id = azurerm_logic_app_workflow.this.id
  body = jsonencode({
    "type" : "ApiConnection",
    "inputs" : {
      "host" : {
      },
      "method" : "put",
      "body" : "@body('Get_blob_content_ALL_Alert')",
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
      },
      "method" : "put",
      "body" : "@body('Get_blob_content_Sintetico_Alert')",
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
      },
      "method" : "get",
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
        },
        operationOptions = "DisableAsyncPattern, DisableAutomaticDecompression",
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
