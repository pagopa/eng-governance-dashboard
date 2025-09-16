import boto3
import csv
import os
import json
import hmac
import hashlib
import base64
import requests
from datetime import datetime, timezone, timedelta


# === CONFIGURATION ===
OUTPUT_FILE = 'aws_health_events.csv'
timestamp = datetime.now().strftime('%Y-%m-%d')
now = datetime.now(timezone.utc)

# Azure Log Analytics
AZURE_WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
AZURE_PRIMARY_KEY = os.getenv("AZURE_PRIMARY_KEY")
AZURE_LOG_TYPE = "Alert_CL"

# AWS Clients
role_name = os.getenv("IAM_ROLE")
sts_client = boto3.client('sts')


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
    #role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    role_arn = role_name
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="HealthCheckSession"
        )
        credentials = response['Credentials']
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        return session.client('health', region_name='us-east-1'), session.client('iam'), account_id
    except Exception as e:
        print(f"❌ Failed to assume role for account {account_id}: {e}")
        return None, None, account_id


# === Fetch AWS Health Events ===
def get_health_events(health_client):
    try:
        all_events = []
        next_token = None
        while True:
            params = {
                'filter': {
                    'eventTypeCategories': ['issue', 'scheduledChange', 'accountNotification'],
                    'eventStatusCodes': ['open', 'upcoming'],
                },
                'maxResults': 100
            }
            if next_token:
                params['nextToken'] = next_token

            response = health_client.describe_events(**params)
            all_events.extend(response.get('events', []))
            next_token = response.get('nextToken')
            if not next_token:
                break
        return all_events
    except Exception as e:
        print(f"❌ Failed to fetch AWS Health events: {e}")
        return []


# === Determine severity for scheduledChange events ===
def calculate_scheduled_severity(start_time):
    if not start_time:
        return "low"

    days_diff = (start_time - now).days

    if days_diff < 0:
        return "high"
    elif days_diff <= 90:
        return "high"
    elif days_diff <= 365:
        return "medium"
    else:
        return "low"


# === Collect and process event details ===
def collect_health_issues(events, health_client, account_id, account_name):
    findings = []
    for event in events:
        try:
            details = health_client.describe_event_details(eventArns=[event['arn']])
            event_detail = details['successfulSet'][0]
            description = event_detail.get('eventDescription', {}).get('latestDescription', 'N/A')

            affected_entities_resp = health_client.describe_affected_entities(filter={'eventArns': [event['arn']]})
            entities = affected_entities_resp.get('entities', [])
            affected_resource_ids = [entity.get('entityValue', 'N/A') for entity in entities]
            resource_id = '; '.join(affected_resource_ids) if affected_resource_ids else 'N/A'

            start_time = event.get('startTime', None)

        except Exception as e:
            description = f"⚠️ Could not retrieve description: {e}"
            resource_id = "N/A"
            start_time = None

        category = event.get('eventTypeCategory')
        if category == 'issue':
            severity = 'high'
        elif category == "scheduledChange":
            severity = calculate_scheduled_severity(start_time)
        elif category == 'accountNotification':
            severity = 'low'
        else:
            severity = 'low'

        findings.append({
            'account_name': account_name,
            'account_id': account_id,
            'resource_id': resource_id,
            'issue': event.get('eventTypeCode', 'N/A'),
            'recommendationId': event.get('arn'),
            'severity': severity,
            'description': description,
            'source': 'AWS_HealthDashboard',
            'csp': 'AWS',
            'region': event.get('region', 'N/A'),
            'category': "Service Retirement",
            'date': timestamp
        })
    return findings


# === Export to CSV ===
def write_to_csv(rows, output_file):
    fieldnames = ['account_name', 'account_id', 'resource_id', 'issue',
                  'recommendationId', 'severity', 'description', 'source', 'csp', 'region', 'category', 'date']

    with open(output_file, mode='w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# === Main Execution ===
if __name__ == '__main__':
    try:
        with open('src/scripts/account.json') as f:
            accounts = json.load(f)

        all_findings = []

        for account_name, acc in accounts.items():
            account_id = acc['id']

            health_client, iam_client, assumed_account_id = assume_role(account_id, role_name)
            if not health_client:
                continue

            try:
                aliases = iam_client.list_account_aliases()["AccountAliases"]
                account_name_alias = aliases[0] if aliases else account_name
            except Exception:
                account_name_alias = account_name

            print(f"🔍 Fetching events for account {assumed_account_id} ({account_name_alias})...")
            events = get_health_events(health_client)
            findings = collect_health_issues(events, health_client, assumed_account_id, account_name_alias)
            all_findings.extend(findings)

        if all_findings:
            write_to_csv(all_findings, OUTPUT_FILE)
            print(f"✅ Exported {len(all_findings)} health events to {OUTPUT_FILE}")

            if AZURE_PRIMARY_KEY and AZURE_WORKSPACE_ID:
                post_to_log_analytics(AZURE_WORKSPACE_ID, AZURE_PRIMARY_KEY, AZURE_LOG_TYPE, all_findings)
            else:
                print("⚠️ Azure credentials not set. Skipping upload.")
        else:
            print("✅ No relevant health events found.")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
