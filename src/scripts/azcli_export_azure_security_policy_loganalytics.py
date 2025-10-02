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
from datetime import timezone

# ===== Configuration =====
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
execution_time = datetime.datetime.now().strftime("%Y-%m-%d")
outfile = f"azure_policy_noncompliant_{timestamp}.csv"

# Optional time range filter
FROM = ""  # e.g., "2025-06-24T00:00:00Z"
TO = ""

# --- Log Analytics Workspace details ---
workspace_id = os.getenv("AZURE_WORKSPACE_ID")
primary_key = os.getenv("AZURE_WORKSPACE_KEY")

if not workspace_id or not primary_key:
    print("Error: var AZURE_WORKSPACE_ID and AZURE_WORKSPACE_KEY not found")
    sys.exit(1)

log_type = "DashGov_CL"

# ===== Functions =====
def check_dependency(command):
    if subprocess.call(f"command -v {command}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        print(f"Error: {command} not found.")
        sys.exit(1)

def run_az_command(command_args):
    result = subprocess.run(command_args, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error executing command: {' '.join(command_args)}")
        print(result.stderr)
        sys.exit(result.returncode)
    return result.stdout

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8") 
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = hmac.new(decoded_key, bytes_to_hash, hashlib.sha256).digest()
    encoded_hash = base64.b64encode(encoded_hash).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization

def post_data_to_log_analytics(workspace_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(workspace_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = f'https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01'

    headers = {
        'Content-Type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date,
        'time-generated-field': 'lastUpdated'
    }

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 200 and response.status_code <= 299:
        return True
    else:
        print(f"Failed to send data to Log Analytics: {response.status_code} {response.text}")
        return False

# ===== Dependency Check =====
check_dependency("az")

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
    "date",
    "dismissed"
]

rows_to_send = []

with open(outfile, mode="w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(header)

    print("Fetching enabled subscriptions...")
    subs_raw = run_az_command(["az", "account", "list", "-o", "json"])

    try:
        subs_data = json.loads(subs_raw)
    except json.JSONDecodeError:
        print("Failed to parse subscriptions JSON.")
        sys.exit(1)

    enabled_subs = [sub for sub in subs_data if sub.get("state") == "Enabled"]

    if not enabled_subs:
        print("No enabled subscriptions found.")
        sys.exit(0)

    total = 0

    for sub in enabled_subs:
        sub_id = sub.get("id", "")
        sub_name = sub.get("name", "")

        print(f"==> Subscription: {sub_name}")
        run_az_command(["az", "account", "set", "--subscription", sub_id])

        cmd = [
            "az", "policy", "state", "list",
            "--filter", "complianceState eq 'NonCompliant'",
            "-o", "json"
        ]
        if FROM:
            cmd += ["--from", FROM]
        if TO:
            cmd += ["--to", TO]

        policy_json = run_az_command(cmd)

        try:
            policy_data = json.loads(policy_json)
        except json.JSONDecodeError:
            print(f"Failed to parse policy data for {sub_id}")
            continue

        filtered = [
            entry for entry in policy_data
            if not any(x in entry.get("policyAssignmentName", "").lower() for x in ["pagopaasc", "pagopatags"])
        ]

        print(f"    NonCompliant items kept after filtering: {len(filtered)}")

        for entry in filtered:
            row = [
                sub_name,
                sub_id,
                entry.get("resourceId", "").replace("\n", " ").replace('"', '""'),
                f"{entry.get('policyDefinitionName', '')} - {entry.get('policySetDefinitionCategory', '')}".strip().replace("\n", " ").replace('"', '""'),
                entry.get("policyDefinitionId", "").replace("\n", " ").replace('"', '""'),
                "medium",
                entry.get("policyDefinitionReferenceId", "").replace("\n", " ").replace('"', '""'),
                "Azure_Policy",
                "Azure",
                entry.get("resourceLocation", "").replace("\n", " ").replace('"', '""'),
                "Policy",
                execution_time,
                "no"
            ]
            writer.writerow(row)
            total += 1

            record = {
                "account_name": sub_name,
                "account_id": sub_id,
                "resource_id": entry.get("resourceId", "").replace("\n", " ").replace('"', '""'),
                "issue": f"{entry.get('policyDefinitionName', '')} - {entry.get('policySetDefinitionCategory', '')}".strip().replace("\n", " ").replace('"', '""'),
                "recommendationId": entry.get("policyDefinitionId", "").replace("\n", " ").replace('"', '""'),
                "severity": "medium",
                "description": entry.get("policyDefinitionReferenceId", "").replace("\n", " ").replace('"', '""'),
                "source": "Azure_Policy",
                "csp": "Azure",
                "region": entry.get("resourceLocation", "").replace("\n", " ").replace('"', '""'),
                "category": "Policy",
                "date": execution_time,
                "dismissed": "no"
            }
            rows_to_send.append(record)

print()
print(f"Done! Total NonCompliant entries exported: {total}")
print(f"CSV file generated: {outfile}")

# Send to Log Analytics
if rows_to_send:
    body = json.dumps(rows_to_send)
    success = post_data_to_log_analytics(workspace_id, primary_key, body, log_type)
    if success:
        print(f"Successfully sent {len(rows_to_send)} records to Log Analytics workspace '{workspace_id}'.")
    else:
        print("Failed to send data to Log Analytics.")


