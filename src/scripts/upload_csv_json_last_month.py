import csv
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.storage.blob import BlobServiceClient


WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
TABLE_NAME = "Dashboard_CL"
DAYS = 30
PAGE_SIZE = 50000

CONTAINER_NAME = "csv"
STORAGE_ACCOUNT_NAME = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")

# Client Azure
credential = DefaultAzureCredential()
account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
client = LogsQueryClient(credential)

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=DAYS)

all_rows = []
columns = None
last_time = start_time

def to_kql_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# Query Log Analytics
while True:
    query = f"""
    {TABLE_NAME}
    | where TimeGenerated >= datetime({to_kql_datetime(last_time)}) and TimeGenerated < datetime({to_kql_datetime(end_time)})
    | order by TimeGenerated asc
    | take {PAGE_SIZE}
    """
    response = client.query_workspace(workspace_id=WORKSPACE_ID, query=query, timespan=None)

    if response.status != LogsQueryStatus.SUCCESS:
        print("❌ Error:", response.error)
        break

    table = response.tables[0]
    if columns is None:
        columns = table.columns if isinstance(table.columns[0], str) else [col.name for col in table.columns]

    rows = table.rows
    if not rows:
        break

    all_rows.extend(rows)
    last_time = rows[-1][columns.index("TimeGenerated")] + timedelta(microseconds=1)
    print(f"➡️  Fetched {len(rows)} rows, total so far {len(all_rows)}")
    if len(rows) < PAGE_SIZE:
        break


output_file = f"log_analytics_last{DAYS}days.csv"
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(columns)
    writer.writerows(all_rows)

print(f"✅ File CSV saved: {output_file} ({len(all_rows)} rows)")

# Index
idx_account_s = columns.index("account_id_s") if "account_id_s" in columns else None
idx_account_g = columns.index("account_id_g") if "account_id_g" in columns else None
idx_time = columns.index("TimeGenerated")
idx_severity = columns.index("severity_s")
idx_account_name_s = columns.index("account_name_s")

# Count monthly
now = datetime.now(timezone.utc)
summary = defaultdict(lambda: {
    "total": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "dismissed": 0,
    "change_last_12m": 0,
    "change_last_1m": 0
})
monthly_counts = defaultdict(lambda: Counter())

for row in all_rows:
    account = None
    if idx_account_s is not None and row[idx_account_s]:
        account = row[idx_account_name_s]
    elif idx_account_g is not None and row[idx_account_g]:
        account = row[idx_account_name_s]
    else:
        continue

    time = row[idx_time]
    severity = row[idx_severity].lower() if row[idx_severity] else ""

    summary[account]["total"] += 1
    if severity == "high":
        summary[account]["high"] += 1
    elif severity == "medium":
        summary[account]["medium"] += 1
    elif severity == "low":
        summary[account]["low"] += 1

    month_key = time.strftime("%Y-%m")
    monthly_counts[account][month_key] += 1

def percent_change(current, previous):
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / previous) * 100, 2)

for account in summary:
    current_month = now.strftime("%Y-%m")
    previous_month = (now - timedelta(days=30)).strftime("%Y-%m")
    last_12_months = [(now - timedelta(days=30 * i)).strftime("%Y-%m") for i in range(1, 13)]

    current_count = monthly_counts[account][current_month]
    previous_count = monthly_counts[account][previous_month]
    last_12_total = sum(monthly_counts[account][m] for m in last_12_months)
    last_12_avg = last_12_total / 12 if last_12_total > 0 else 0

    summary[account]["change_last_1m"] = percent_change(current_count, previous_count)
    summary[account]["change_last_12m"] = percent_change(current_count, last_12_avg)


# Save JSON
with open("sintesi_last30days.json", "w", encoding="utf-8") as f:
    json.dump([
        {
            "prodotto": account,
            "data": now.strftime("%d/%m/%Y"),
            "issue_totali": stats["total"],
            "issue_high": stats["high"],
            "issue_medium": stats["medium"],
            "issue_low": stats["low"],
            "issue_dismissed": stats["dismissed"],
            "change_last_12_month": stats["change_last_12m"],
            "change_last_month": stats["change_last_1m"]
        }
        for account, stats in summary.items()
    ], f, ensure_ascii=False, indent=4)

# Save CSV
with open("sintesi_last30days.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "prodotto", "data", "issue_totali", "issue_high", "issue_medium",
        "issue_low", "issue_dismissed", "change_last_12_month", "change_last_month"
    ])
    for account, stats in summary.items():
        writer.writerow([
            account,
            now.strftime("%d/%m/%Y"),
            stats["total"],
            stats["high"],
            stats["medium"],
            stats["low"],
            stats["dismissed"],
            stats["change_last_12m"],
            stats["change_last_1m"]
        ])

print("✅ Script completed. File sintesi_last30days.csv and sintesi_last30days.json updated.")

blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

def upload_file(local_file_path, remote_file_name):
    with open(local_file_path, "rb") as data:
        container_client.upload_blob(name=remote_file_name, data=data, overwrite=True)
    print(f"✅ Upload completed: {remote_file_name}")

upload_file("log_analytics_last30days.csv", "log_analytics_last30days.csv")
upload_file("sintesi_last30days.csv", "sintesi_last30days.csv")
upload_file("sintesi_last30days.json", "sintesi_last30days.json")
