import csv
from azure.storage.blob import BlobServiceClient
from collections import defaultdict
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
import os
from datetime import datetime, timedelta, timezone

WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")

TABLE_NAME = "Alert_CL"
DAYS = 30
PAGE_SIZE = 50000

STORAGE_ACCOUNT_NAME = "exportalertdevitnrg"
CONTAINER_NAME = "csv"

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=DAYS)

all_rows = []
columns = None
last_time = start_time

def to_kql_datetime(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

while True:
    query = f"""
    {TABLE_NAME}
    | where TimeGenerated >= datetime({to_kql_datetime(last_time)}) and TimeGenerated < datetime({to_kql_datetime(end_time)})
    | order by TimeGenerated asc
    | take {PAGE_SIZE}
    """

    response = client.query_workspace(
        workspace_id=WORKSPACE_ID,
        query=query,
        timespan=None
    )

    if response.status != LogsQueryStatus.SUCCESS:
        print("❌ Error:", response.error)
        break

    table = response.tables[0]

    if columns is None:
        if isinstance(table.columns[0], str):
            columns = table.columns
        else:
            columns = [getattr(col, "name", getattr(col, "column_name", str(col))) for col in table.columns]

    rows = table.rows

    if not rows:
        break

    all_rows.extend(rows)

    last_time = rows[-1][columns.index("TimeGenerated")]
    last_time = last_time + timedelta(microseconds=1)  # per evitare duplicati

    print(f"➡️  Fetched {len(rows)} rows, total so far {len(all_rows)}")

    if len(rows) < PAGE_SIZE:
        break

output_file = f"log_analytics_last{DAYS}days.csv"
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(columns)
    writer.writerows(all_rows)

print(f"✅ File CSV saved: {output_file} ({len(all_rows)} rows)")



summary = defaultdict(lambda: {
    "total": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "dismissed": 0,
    "change_last_12m": 0,
    "change_last_1m": 0
})

now = datetime.now(timezone.utc)
one_month_ago = now - timedelta(days=30)
twelve_months_ago = now - timedelta(days=365)


idx_account_s = columns.index("account_id_s") if "account_id_s" in columns else None
idx_account_g = columns.index("account_id_g") if "account_id_g" in columns else None
idx_time = columns.index("TimeGenerated")
idx_severity = columns.index("severity_s")
idx_account_name_s = columns.index("account_name_s")
default_status = "open"

for row in all_rows:
    account = None
    if idx_account_s is not None and row[idx_account_s]:
        account = row[idx_account_s]
        account = row[idx_account_name_s]
    elif idx_account_g is not None and row[idx_account_g]:
        account = row[idx_account_g]
        account = row[idx_account_name_s]
    else:
        continue

    time = row[idx_time]
    severity = row[idx_severity].lower() if row[idx_severity] else ""
    status = default_status.lower()

    summary[account]["total"] += 1
    if severity == "high":
        summary[account]["high"] += 1
    elif severity == "medium":
        summary[account]["medium"] += 1
    elif severity == "low":
        summary[account]["low"] += 1

    if status == "dismissed":
        summary[account]["dismissed"] += 1

    if time >= twelve_months_ago:
        summary[account]["change_last_12m"] += 1
    if time >= one_month_ago:
        summary[account]["change_last_1m"] += 1


summary_file = "sintesi_last30days.csv"
with open(summary_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "prodotto",
        "data",
        "issue_totali",
        "issue_high",
        "issue_medium",
        "issue_low",
        "issue_dismissed",
        "change_last_12_month",
        "change_last_month"
    ])
    for account, stats in summary.items():
        writer.writerow([
            account,
            now.strftime("%Y-%m-%d"),
            stats["total"],
            stats["high"],
            stats["medium"],
            stats["low"],
            stats["dismissed"],
            stats["change_last_12m"],
            stats["change_last_1m"]
        ])

print(f"✅ Sintesi CSV saved: {summary_file} ({len(summary)} accounts)")


conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
if not conn_str:
    raise ValueError("Variable AZURE_STORAGE_CONNECTION_STRING not found")

blob_service_client = BlobServiceClient.from_connection_string(conn_str)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

def upload_file(local_file_path, remote_file_name):
    with open(local_file_path, "rb") as data:
        container_client.upload_blob(name=remote_file_name, data=data, overwrite=True)
    print(f"✅ Upload completed: {remote_file_name}")

upload_file("log_analytics_last30days.csv", "log_analytics_last30days.csv")
upload_file("sintesi_last30days.csv", "sintesi_last30days.csv")
