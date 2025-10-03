import csv
import json
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient, LogsQueryStatus
from azure.storage.blob import BlobServiceClient

WORKSPACE_ID = os.getenv("AZURE_WORKSPACE_ID")
TABLE_NAME = "DashGov_CL"
DELTA_TIME = 2  # in hours
PAGE_SIZE = 50000

CONTAINER_NAME = "csv"
STORAGE_ACCOUNT_NAME = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")

# Load product->accounts mapping from JSON config file
script_dir = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(script_dir, "config_prodotti.json")
with open(config_path, "r", encoding="utf-8") as f:
    prodotti_config = json.load(f)

# Invert mapping to get account -> product
account_to_prodotto = {}
for prodotto, accounts in prodotti_config.items():
    for acc in accounts:
        account_to_prodotto[acc] = prodotto

# Azure client setup
credential = DefaultAzureCredential()
account_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
client = LogsQueryClient(credential)

end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(hours=DELTA_TIME)

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

# Output detailed CSV
output_file = f"log_analytics_last30days.csv"
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(columns)
    writer.writerows(all_rows)

print(f"✅ CSV file saved: {output_file} ({len(all_rows)} rows)")

# Get column index
idx_account_s = columns.index("account_id_s") if "account_id_s" in columns else None
idx_account_g = columns.index("account_id_g") if "account_id_g" in columns else None
idx_time = columns.index("TimeGenerated")
idx_severity = columns.index("severity_s")
idx_account_name_s = columns.index("account_name_s")
idx_csp = columns.index("csp_s") if "csp_s" in columns else None
idx_dismissed = columns.index("dismissed_s") if "dismissed_s" in columns else None

# Summarize data by account and CSP
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

    csp = row[idx_csp] if idx_csp is not None else "n/a"
    time = row[idx_time]
    severity = row[idx_severity].lower() if row[idx_severity] else ""
    dismissed_value = row[idx_dismissed].lower() if idx_dismissed is not None else "no"

    key = (account, csp)

    if dismissed_value == "yes":
        summary[key]["dismissed"] += 1
    else:
        summary[key]["total"] += 1
        if severity == "high":
            summary[key]["high"] += 1
        elif severity == "medium":
            summary[key]["medium"] += 1
        elif severity == "low":
            summary[key]["low"] += 1

        month_key = time.strftime("%Y-%m")
        monthly_counts[key][month_key] += 1

def percent_change(current, previous):
    if previous == 0:
        return 100.0 if current > 0 else 0.0
    return round(((current - previous) / previous) * 100, 2)

now = datetime.now(timezone.utc)
for key in summary:
    current_month = now.strftime("%Y-%m")
    previous_month = (now - timedelta(days=30)).strftime("%Y-%m")
    last_12_months = [(now - timedelta(days=30 * i)).strftime("%Y-%m") for i in range(1, 13)]

    current_count = monthly_counts[key][current_month]
    previous_count = monthly_counts[key][previous_month]
    last_12_total = sum(monthly_counts[key][m] for m in last_12_months)
    last_12_avg = last_12_total / 12 if last_12_total > 0 else 0

    summary[key]["change_last_1m"] = percent_change(current_count, previous_count)
    summary[key]["change_last_12m"] = percent_change(current_count, last_12_avg)

# Save JSON summary
with open("sintesi_last30days.json", "w", encoding="utf-8") as f:
    json.dump([
        {
            "account": account,
            "product": account_to_prodotto.get(account, ""),
            "provider": csp,
            "date": now.strftime("%d/%m/%Y"),
            "total_issues": stats["total"],
            "high_issues": stats["high"],
            "medium_issues": stats["medium"],
            "low_issues": stats["low"],
            "dismissed_issues": stats["dismissed"],
            "change_last_12_month": stats["change_last_12m"],
            "change_last_month": stats["change_last_1m"]
        }
        for (account, csp), stats in summary.items()
    ], f, ensure_ascii=False, indent=4)

# Save CSV summary
with open("sintesi_last30days.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "account", "product", "provider", "date", "total_issues", "high_issues", "medium_issues",
        "low_issues", "dismissed_issues", "change_last_12_month", "change_last_month"
    ])
    for (account, csp), stats in summary.items():
        prodotto = account_to_prodotto.get(account, "")
        writer.writerow([
            account,
            prodotto,
            csp,
            now.strftime("%d/%m/%Y"),
            stats["total"],
            stats["high"],
            stats["medium"],
            stats["low"],
            stats["dismissed"],
            stats["change_last_12m"],
            stats["change_last_1m"]
        ])

print("✅ Script completed. Files sintesi_last30days.csv and sintesi_last30days.json updated.")

# Upload to Azure Blob Storage
blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)
container_client = blob_service_client.get_container_client(CONTAINER_NAME)

def upload_file(local_file_path, remote_file_name):
    with open(local_file_path, "rb") as data:
        container_client.upload_blob(name=remote_file_name, data=data, overwrite=True)
    print(f"✅ Upload completed: {remote_file_name}")

upload_file(f"log_analytics_last30days.csv", f"log_analytics_last30days.csv")
upload_file("sintesi_last30days.csv", "sintesi_last30days.csv")
upload_file("sintesi_last30days.json", "sintesi_last30days.json")
