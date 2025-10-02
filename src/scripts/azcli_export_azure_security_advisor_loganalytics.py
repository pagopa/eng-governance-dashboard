#!/usr/bin/env python3
import subprocess
import sys
import csv
import json
import datetime
import hashlib
import hmac
import base64
import requests
import os

# ===== Log Analytics Config =====
workspace_id = os.getenv("AZURE_WORKSPACE_ID")
primary_key = os.getenv("AZURE_WORKSPACE_KEY")

if not workspace_id or not primary_key:
    print("Errore: variabili d'ambiente AZURE_WORKSPACE_ID e AZURE_WORKSPACE_KEY devono essere settate.")
    sys.exit(1)

log_type = "DashboardGovernance_CL"

# ===== Utility: Signature builder =====
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{str(content_length)}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"
    
def get_resource_location(resource_id):
    if not resource_id:
        return "N/A"
    try:
        result = subprocess.run(
            ["az", "resource", "show", "--ids", resource_id, "--query", "location", "-o", "tsv"],
            capture_output=True,
            text=True,
            check=True
        )
        location = result.stdout.strip()
        return location if location else "N/A"
    except subprocess.CalledProcessError as e:
        return "N/A"


# ===== Utility: POST data to Log Analytics =====
def post_data(customer_id, shared_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = f"https://{customer_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"

    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date
    }

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 200 and response.status_code <= 299:
        return True
    else:
        print(f"[!] Failed to send data: {response.status_code} {response.text}")
        return False

# ===== Check dependency =====
def check_dependency(command):
    if subprocess.call(f"command -v {command}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"{command} not found. Install {command}.")
        sys.exit(1)

check_dependency("az")

# ===== Config =====
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
outfile = f"azure_advisor_recommendations_{timestamp}.csv"

# ===== CSV Header =====
header = [
    "account_name",
    "account_id",
    "resource_id",
    "issue",
    "recommendationId",
    "severity",
    "description",
    "source",
    "csp",
    "region",
    "category",
    "date"
]

data_rows = []

with open(outfile, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(header)

    print("Finding subscriptions...")
    subs_output = subprocess.run(
        ["az", "account", "list", "-o", "json"],
        capture_output=True, text=True
    )

    try:
        subs_data = json.loads(subs_output.stdout)
    except json.JSONDecodeError:
        print("Error decoding subscription list JSON.")
        sys.exit(1)

    if not subs_data:
        print("No subscriptions found.")
        sys.exit(0)

    total = 0

    for sub in subs_data:
        sub_id = sub.get("id", "")
        sub_name = sub.get("name", "")

        print(f"==> Subscription: {sub_name}")
        subprocess.run(["az", "account", "set", "--subscription", sub_id], check=True)

        advisor_output = subprocess.run(
            ["az", "advisor", "recommendation", "list", "-o", "json"],
            capture_output=True, text=True
        )

        try:
            recommendations = json.loads(advisor_output.stdout)
        except json.JSONDecodeError:
            print(f"Error parsing recommendations for subscription {sub_id}")
            continue

        print(f"    Alerts found: {len(recommendations)}")

        for rec in recommendations:
            name = rec.get("name", "")
            severity = rec.get("impact", "").lower()
            resource_id = rec.get("resourceMetadata", {}).get("resourceId")
            issue = rec.get("shortDescription", {}).get("problem", "").replace("\n", " ").replace('"', '""')
            date = datetime.datetime.now().strftime("%Y-%m-%d")
            source = "Azure_Advisor"
            description = rec.get("shortDescription", {}).get("solution", "").replace("\n", " ").replace('"', '""')
            csp = "Azure"
            category = rec.get("category", "")
            if resource_id:
                #region = get_resource_location(resource_id)
                region = "N/A"
            else:
                region = "N/A"
            

            row = [
                sub_name,
                sub_id,
                resource_id,
                issue,
                name,
                severity,
                description,
                source,
                csp,
                region,
                category,
                date
            ]
            writer.writerow(row)

            data_rows.append({
                "account_name": sub_name,
                "account_id": sub_id,
                "resource_id": resource_id,
                "issue": issue,
                "recommendationId": name,
                "severity": severity,
                "description": description,
                "source": source,
                "csp": csp,
                "region": region,
                "category": category,
                "date": date
            })
            total += 1

# ===== Send to Log Analytics =====
if data_rows:
    json_body = json.dumps(data_rows)
    if post_data(workspace_id, primary_key, json_body, log_type):
        print(f"✅ Successfully sent {total} records to Log Analytics workspace '{workspace_id}'")
    else:
        print("❌ Failed to send data to Log Analytics.")
else:
    print("No data to send to Log Analytics.")

print(f"CSV file generated: {outfile}")



