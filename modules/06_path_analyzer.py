import psutil
import datetime

print("=" * 65)
print("Suspicious Path Analyzer")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 65)

# Trusted safe locations
TRUSTED_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

# Suspicious locations malware uses
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\recycle.bin\\",
    "\\desktop\\", "\\Desktop\\Powershell",
]

results = {"trusted": 0, "suspicious": 0, "unknown": 0}
alerts = []
all_results = []

print(f"\n{'PID':<7} {'Name':<25} {'Category':<12} {'Path'}")
print("-" * 90)

for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        pid      = proc.info['pid']
        name     = proc.info['name']
        exe      = proc.info['exe']

        if not exe:
            continue

        exe_lower = exe.lower()
        category  = "Unknown"

        # check trusted first
        for tp in TRUSTED_PATHS:
            if exe_lower.startswith(tp):
                category = "Trusted"
                results['trusted'] += 1
                break

        # check suspicious
        if category == "Unknown":
            for sp in SUSPICIOUS_PATHS:
                if sp in exe_lower:
                    category = "SUSPICIOUS"
                    results['suspicious'] += 1
                    alert = (f"[HIGH] Process in suspicious path:\n"
                             f"       {name} (PID:{pid})\n"
                             f"       Path: {exe}")
                    alerts.append(alert)
                    break

        # still unknown
        if category == "Unknown":
            results['unknown'] += 1

        all_results.append({
            'pid': pid, 'name': name,
            'exe': exe, 'category': category
        })

        print(f"{pid:<7} {name:<25} {category:<12} {exe}")

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# Summary
print("\n" + "=" * 65)
print("SCAN SUMMARY")
print("=" * 65)
print(f"Trusted    : {results['trusted']} processes")
print(f"Unknown    : {results['unknown']} processes")
print(f"Suspicious : {results['suspicious']} processes")
print(f"Total      : {sum(results.values())} processes scanned")

# Alerts
print("\nALERTS:")
print("-" * 65)
if alerts:
    for alert in alerts:
        print(alert)
        print()
else:
    print("No suspicious paths detected. System looks clean.")

# Save log
log_path = r"D:\Projects\WindowsMonitorAgent\logs\path_analysis.txt"

with open(log_path, "w") as f:
    f.write("Suspicious Path Analysis Log\n")
    f.write(f"Scan Time: {datetime.datetime.now()}\n")
    f.write("=" * 65 + "\n\n")

    f.write("ALL PROCESS PATHS:\n")
    f.write("-" * 65 + "\n")
    for r in all_results:
        f.write(f"PID:{r['pid']} | {r['name']} | "
                f"{r['category']} | {r['exe']}\n")

    f.write("\n\nSUSPICIOUS PATH ALERTS:\n")
    f.write("-" * 65 + "\n")
    if alerts:
        for a in alerts:
            f.write(a + "\n\n")
    else:
        f.write("No suspicious paths found.\n")

    f.write("\nSUMMARY:\n")
    f.write(f"Trusted    : {results['trusted']}\n")
    f.write(f"Unknown    : {results['unknown']}\n")
    f.write(f"Suspicious : {results['suspicious']}\n")
    f.write(f"Total      : {sum(results.values())}\n")

print(f"\nLog saved to: {log_path}")
print(f"Total alerts: {len(alerts)}")
print("\nscan complete!")