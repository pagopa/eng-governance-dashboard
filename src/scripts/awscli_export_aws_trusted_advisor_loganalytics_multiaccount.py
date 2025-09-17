import boto3
import csv
import os
import json
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timezone

# === CONFIGURATION ===
OUTPUT_FILE = 'aws_trusted_advisor_findings.csv'
timestamp = datetime.now().strftime('%Y-%m-%d')

# Azure Log Analytics
AZURE_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
AZURE_PRIMARY_KEY = os.getenv("AZURE_WORKSPACE_KEY")
AZURE_LOG_TYPE = "Alert_CL"
role_name = os.getenv("IAM_ROLE")

# === Azure Signature ===
def build_signature(workspace_id, key, date, content_length, method, content_type, resource):
    x_headers = f'x-ms-date:{date}'
    string_to_hash = f'{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}'
    bytes_to_hash = bytes(string_to_hash, encoding='utf-8')
    decoded_key = base64.b64decode(key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    return f'SharedKey {workspace_id}:{encoded_hash}'

def post_to_log_analytics(workspace_id, key, log_type, body):
    body_json = json.dumps(body)
    rfc1123date = datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    resource = '/api/logs'
    content_type = 'application/json'
    content_length = len(body_json)
    signature = build_signature(workspace_id, key, rfc1123date, content_length, 'POST', content_type, resource)
    uri = f'https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01'

    headers = {
        'Content-Type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri, data=body_json, headers=headers)
    if 200 <= response.status_code < 300:
        print(f"✅ Sent {len(body)} records to Azure Log Analytics")
    else:
        print(f"❌ Azure Log upload failed: {response.status_code} - {response.text}")

# === Assume Role ===
def assume_role(account_id, role_name):
    sts_client = boto3.client("sts")
    #role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_arn = role_name
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="TrustedAdvisorSession"
        )
        creds = response["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        return session
    except Exception as e:
        print(f"❌ Failed to assume role for {account_id}: {e}")
        return None

# === Trusted Advisor ===
def get_trusted_advisor_checks(support_client):
    response = support_client.describe_trusted_advisor_checks(language="en")
    return response["checks"]

def collect_issues(checks, support_client, account_id, account_name):
    CATEGORY_MAPPING = {
        "fault_tolerance": "HighAvailability",
        "security": "Security",
        "cost_optimizing": "Cost",
        "operational_excellence": "OperationalExcellence",
        "performance": "Performance"
    }
    
    issues = []
    for check in checks:
        try:
            result = support_client.describe_trusted_advisor_check_result(
                checkId=check["id"],
                language="en"
            )["result"]
        except Exception as e:
            print(f"⚠️ Failed to get result for check '{check['name']}' in {account_id}: {e}")
            continue

        flagged = [
            res for res in result.get("flaggedResources", [])
            if res.get("status") in ["warning", "error"]
        ]

        for res in flagged:
            issues.append({
                "account_name": account_name,
                "account_id": str(account_id),
                "resource_id": res.get("arn") or res.get("resourceId") or "N/A",
                "issue": check["name"],
                "recommendationId": check["id"],
                "severity": "high" if res.get("status") == "error" else "medium" if res.get("status") == "warning" else "low",
                "description": check.get("description", "N/A"),
                "source": "AWS_TrustedAdvisor",
                "csp": "AWS",
                "region": res.get("region", "N/A"),
                "category": CATEGORY_MAPPING.get(check.get("category", "").lower(), check.get("category", "N/A")),
                "date": timestamp
            })
    return issues

def write_to_csv(rows, output_file):
    fieldnames = [
        "account_name", "account_id", "resource_id", "issue",
        "recommendationId", "severity", "description",
        "source", "csp", "region", "category", "date"
    ]

    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

# === Main ===
if __name__ == "__main__":
    try:
        with open("src/scripts/account.json") as f:
            accounts = json.load(f)

        all_issues = []

        for account_name, acc in accounts.items():
            account_id = acc["id"]
            print(f"🔍 Checking Trusted Advisor for {account_name} ({account_id})...")

            session = assume_role(account_id,role_name)
            if not session:
                continue

            support_client = session.client("support", region_name="us-east-1")  # Trusted Advisor only in us-east-1
            iam_client = session.client("iam")

            try:
                aliases = iam_client.list_account_aliases()["AccountAliases"]
                alias_name = aliases[0] if aliases else account_name
            except Exception:
                alias_name = account_name

            checks = get_trusted_advisor_checks(support_client)
            issues = collect_issues(checks, support_client, account_id, alias_name)
            all_issues.extend(issues)

        if all_issues:
            write_to_csv(all_issues, OUTPUT_FILE)
            print(f"✅ Exported {len(all_issues)} issues to {OUTPUT_FILE}")

            if AZURE_PRIMARY_KEY and AZURE_WORKSPACE_ID:
                post_to_log_analytics(AZURE_WORKSPACE_ID, AZURE_PRIMARY_KEY, AZURE_LOG_TYPE, all_issues)
            else:
                print("⚠️ Azure credentials not set. Skipping upload.")
        else:
            print("✅ No actionable issues found.")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
