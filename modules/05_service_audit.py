import subprocess
import datetime

print("=" * 65)
print("Windows Startup Service Auditor")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 65)

# Use PowerShell to get all services — works on all Python versions
result = subprocess.run(
    ["powershell", "-Command",
     "Get-Service | Select-Object Name, Status, StartType | ConvertTo-Csv -NoTypeInformation"],
    capture_output=True, text=True
)

lines = result.stdout.strip().split("\n")
lines = [l.strip().strip('"') for l in lines if l.strip()]

all_services = []

print(f"\n{'Service Name':<40} {'Status':<12} {'Start Type'}")
print("-" * 70)

for line in lines[1:]:  # skip header
    parts = line.replace('"', '').split(",")
    if len(parts) >= 3:
        name   = parts[0].strip()
        status = parts[1].strip()
        start  = parts[2].strip()
        all_services.append({
            'name': name, 'status': status, 'start': start
        })
        print(f"{name:<40} {status:<12} {start}")

print(f"\nTotal services found: {len(all_services)}")

# Suspicious detection
SUSPICIOUS_NAMES = [
    "helper", "agent32", "svchost32",
    "windowsupdate32", "securityscan",
    "microsoftupdate", "service32"
]

alerts = []

print("\nAuditing for suspicious services...")
print("-" * 65)

for svc in all_services:
    name  = svc['name'].lower()
    start = svc['start']

    for sn in SUSPICIOUS_NAMES:
        if sn in name:
            alert = (f"[MEDIUM] Suspicious auto-start service: "
                     f"{svc['name']} | Start: {start}")
            alerts.append(alert)
            print(alert)
            break

if not alerts:
    print("No suspicious services detected.")

# Save log
log_path = r"D:\Projects\WindowsMonitorAgent\logs\service_audit.txt"

with open(log_path, "w") as f:
    f.write("Day 5 - Windows Service Audit Log\n")
    f.write(f"Scan Time: {datetime.datetime.now()}\n")
    f.write(f"Total Services: {len(all_services)}\n")
    f.write("=" * 65 + "\n\n")

    for svc in all_services:
        f.write(f"Name   : {svc['name']}\n")
        f.write(f"Status : {svc['status']}\n")
        f.write(f"Start  : {svc['start']}\n\n")

    f.write("\nSUSPICIOUS ALERTS:\n")
    f.write("-" * 65 + "\n")
    if alerts:
        for a in alerts:
            f.write(a + "\n\n")
    else:
        f.write("No suspicious services found.\n")

    f.write(f"\nTotal alerts: {len(alerts)}\n")

print(f"\nLog saved to: {log_path}")
print(f"Total services scanned: {len(all_services)}")
print(f"Total alerts: {len(alerts)}")
print("\nscan complete!")