#!/usr/bin/env python3
import boto3
import csv
import os
import json
import hmac
import hashlib
import base64
import requests
import time
import math
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.exceptions import ClientError, EndpointConnectionError

# === CONFIGURATION / ENV ===
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "aws_trusted_advisor_findings.csv")
timestamp = datetime.now().strftime('%Y-%m-%d')

AZURE_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
AZURE_WORKSPACE_KEY = os.getenv("AZURE_WORKSPACE_KEY")
AZURE_LOG_TYPE = os.getenv("AZURE_LOG_TYPE", "Alert_CL")

# role_name should be either a full ARN or a pattern depending how you use it.
ROLE_ARN = os.getenv("IAM_ROLE")  # Keep same behavior as before (was role_name)

# Performance tunables
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "6"))          # threads for accounts
CHECK_WORKERS = int(os.getenv("CHECK_WORKERS", "4"))      # threads per account for fetching problematic checks (bounded)
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "500"))          # Azure batch size
AWS_API_RETRIES = int(os.getenv("AWS_API_RETRIES", "3"))  # retries for AWS calls
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))       # seconds for HTTP requests

# Behavior
OUTPUT_DETAIL_PER_RESOURCE = os.getenv("OUTPUT_DETAIL_PER_RESOURCE", "true").lower() in ("1","true","yes")

# AWS STS client used to assume roles
sts_client = boto3.client('sts')

# === Helpers ===
def retry(func, retries=3, initial_delay=1, backoff=2, exceptions=(Exception,)):
    """Simple retry wrapper: call func() and retry on specified exceptions."""
    delay = initial_delay
    for attempt in range(1, retries + 1):
        try:
            return func()
        except exceptions as e:
            if attempt == retries:
                raise
            print(f"⚠️ Retry {attempt}/{retries} for {func.__name__} due to: {e}. Sleeping {delay}s")
            time.sleep(delay)
            delay *= backoff

# === Azure Signature / Post ===
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
    if not (workspace_id and key):
        print("⚠️ Azure credentials not set. Skipping upload.")
        return
    if not body:
        print("ℹ️ No records to post to Azure.")
        return

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

    def _post():
        return requests.post(uri, data=body_json, headers=headers, timeout=HTTP_TIMEOUT)

    resp = retry(_post, retries=3, initial_delay=2, backoff=2, exceptions=(requests.RequestException,))
    if 200 <= resp.status_code < 300:
        print(f"✅ Sent {len(body)} records to Azure Log Analytics (status {resp.status_code})")
    else:
        print(f"❌ Azure Log upload failed: {resp.status_code} - {resp.text}")

def post_in_batches(records, batch_size=BATCH_SIZE):
    for i in range(0, len(records), batch_size):
        batch = records[i:i+batch_size]
        post_to_log_analytics(AZURE_WORKSPACE_ID, AZURE_WORKSPACE_KEY, AZURE_LOG_TYPE, batch)

# === Assume Role ===
def assume_role(account_id, role_arn):
    # If role_arn is a template or full ARN, adjust here. Original script expected role_name to be full ARN.
    if not role_arn:
        print("❌ IAM role ARN not provided in IAM_ROLE env.")
        return None

    def _assume():
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=f"TASession-{account_id}")

    try:
        resp = retry(_assume, retries=AWS_API_RETRIES, initial_delay=1, backoff=2, exceptions=(ClientError, EndpointConnectionError))
        creds = resp["Credentials"]
        session = boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"]
        )
        return session
    except Exception as e:
        print(f"❌ Failed to assume role for {account_id}: {e}")
        return None

# === Trusted Advisor helpers ===
def get_trusted_advisor_checks(support_client):
    def _call():
        return support_client.describe_trusted_advisor_checks(language="en")
    resp = retry(_call, retries=AWS_API_RETRIES, initial_delay=1, backoff=2, exceptions=(ClientError, EndpointConnectionError))
    return resp.get("checks", [])

def get_summaries_for_checks(support_client, check_ids):
    # Batch by chunk size if necessary (API allows many, but be safe)
    CHUNK = 50
    summaries = []
    for i in range(0, len(check_ids), CHUNK):
        chunk = check_ids[i:i+CHUNK]
        def _call():
            return support_client.describe_trusted_advisor_check_summaries(checkIds=chunk)
        resp = retry(_call, retries=AWS_API_RETRIES, initial_delay=1, backoff=2, exceptions=(ClientError, EndpointConnectionError))
        summaries.extend(resp.get("summaries", []))
    return summaries

def get_check_result(support_client, check_id):
    def _call():
        return support_client.describe_trusted_advisor_check_result(checkId=check_id, language="en")
    resp = retry(_call, retries=AWS_API_RETRIES, initial_delay=1, backoff=2, exceptions=(ClientError, EndpointConnectionError))
    return resp.get("result", {})

# Mapping category cleanup
CATEGORY_MAPPING = {
    "fault_tolerance": "HighAvailability",
    "security": "Security",
    "cost_optimizing": "Cost",
    "operational_excellence": "OperationalExcellence",
    "performance": "Performance"
}

def collect_issues_for_account(session, account_id, account_name):
    support_client = session.client("support", region_name="us-east-1")
    iam_client = session.client("iam")

    # account alias optionally fetch once
    try:
        aliases = iam_client.list_account_aliases().get("AccountAliases", [])
        alias_name = aliases[0] if aliases else account_name
    except Exception:
        alias_name = account_name

    checks = get_trusted_advisor_checks(support_client)
    if not checks:
        print(f"ℹ️ No TA checks found for {account_name} ({account_id})")
        return []

    check_id_map = {c["id"]: c for c in checks}
    check_ids = list(check_id_map.keys())

    summaries = get_summaries_for_checks(support_client, check_ids)
    problematic_check_ids = [s["checkId"] for s in summaries if s.get("resourcesSummary", {}).get("resourcesFlagged", 0) > 0]

    if not problematic_check_ids:
        print(f"✅ No flagged resources for {account_name} ({account_id})")
        return []

    issues = []

    # Function to process a single check (we can parallelize limited)
    def _process_check(check_id):
        try:
            res = get_check_result(support_client, check_id)
        except Exception as e:
            print(f"⚠️ Failed to get result for check {check_id} in {account_id}: {e}")
            return []

        flagged = [
            r for r in res.get("flaggedResources", [])
            if r.get("status") in ("warning", "error")
        ]
        check = check_id_map.get(check_id, {})
        check_name = check.get("name", "N/A")
        category = CATEGORY_MAPPING.get(check.get("category", "").lower(), check.get("category", "N/A"))
        description = check.get("description", "N/A")

        # If the user wants a single row per check (with resource count)
        if not OUTPUT_DETAIL_PER_RESOURCE:
            severity = "high" if any(r.get("status") == "error" for r in flagged) else "medium"
            return [{
                "account_name": alias_name,
                "account_id": str(account_id),
                "resource_id": "N/A",
                "issue": check_name,
                "recommendationId": check_id,
                "severity": severity,
                "description": description,
                "source": "AWS_TrustedAdvisor",
                "csp": "AWS",
                "region": "N/A",
                "category": category,
                "affected_resources": len(flagged),
                "date": timestamp
            }]

        # Default behavior: one row per flagged resource (detailed)
        rows = []
        for r in flagged:
            rows.append({
                "account_name": alias_name,
                "account_id": str(account_id),
                "resource_id": r.get("arn") or r.get("resourceId") or "N/A",
                "issue": check_name,
                "recommendationId": check_id,
                "severity": "high" if r.get("status") == "error" else "medium" if r.get("status") == "warning" else "low",
                "description": description,
                "source": "AWS_TrustedAdvisor",
                "csp": "AWS",
                "region": r.get("region", "N/A"),
                "category": category,
                "date": timestamp
            })
        return rows

    # parallelize processing of problematic checks, but bounded
    results = []
    with ThreadPoolExecutor(max_workers=min(CHECK_WORKERS, max(1, len(problematic_check_ids)))) as executor:
        future_to_check = {executor.submit(_process_check, cid): cid for cid in problematic_check_ids}
        for fut in as_completed(future_to_check):
            try:
                res_rows = fut.result()
                if res_rows:
                    results.extend(res_rows)
            except Exception as e:
                cid = future_to_check[fut]
                print(f"⚠️ Error processing check {cid} for account {account_id}: {e}")

    return results

# === CSV writer ===
def write_to_csv(rows, output_file):
    # determine fieldnames dynamically (support optional 'affected_resources')
    base_fields = [
        "account_name", "account_id", "resource_id", "issue",
        "recommendationId", "severity", "description",
        "source", "csp", "region", "category", "date"
    ]
    if not OUTPUT_DETAIL_PER_RESOURCE:
        base_fields.append("affected_resources")

    with open(output_file, mode="w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=base_fields)
        writer.writeheader()
        writer.writerows(rows)

# === Main ===
def main():
    try:
        with open("src/scripts/account.json") as f:
            accounts = json.load(f)
    except Exception as e:
        print(f"❌ Unable to load src/scripts/account.json: {e}")
        return

    all_issues = []

    def process_account_item(item):
        account_name, acc = item
        account_id = acc.get("id")
        print(f"🔍 Starting {account_name} ({account_id})")

        session = assume_role(account_id, ROLE_ARN)
        if not session:
            print(f"⚠️ Skipping {account_name} due to assume role failure")
            return []

        try:
            rows = collect_issues_for_account(session, account_id, account_name)
            print(f"ℹ️ Collected {len(rows)} rows for {account_name}")
            return rows
        except Exception as e:
            print(f"❌ Error processing account {account_name}: {e}")
            return []

    # Parallelize accounts
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, len(accounts)))) as executor:
        futures = {executor.submit(process_account_item, item): item for item in accounts.items()}
        for fut in as_completed(futures):
            try:
                rows = fut.result()
                if rows:
                    all_issues.extend(rows)
            except Exception as e:
                acct = futures[fut]
                print(f"⚠️ Error in future for {acct}: {e}")

    # Write CSV
    if all_issues:
        write_to_csv(all_issues, OUTPUT_FILE)
        print(f"✅ Exported {len(all_issues)} issues to {OUTPUT_FILE}")
        # Post to Azure in batches
        if AZURE_WORKSPACE_ID and AZURE_WORKSPACE_KEY:
            # If OUTPUT_DETAIL_PER_RESOURCE is False, our records are smaller, but still batch
            post_in_batches(all_issues, batch_size=BATCH_SIZE)
        else:
            print("⚠️ Azure credentials not set. Skipping upload.")
    else:
        print("✅ No actionable issues found.")

if __name__ == "__main__":
    main()
