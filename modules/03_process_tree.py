import psutil
import datetime
from collections import defaultdict

print("=" * 60)
print("Process Tree Builder - Day 3")
print(f"Time: {datetime.datetime.now()}")
print("=" * 60)

# Step 1: collect all processes
all_procs = {}
for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe']):
    try:
        all_procs[proc.info['pid']] = {
            'name' : proc.info['name'],
            'ppid' : proc.info['ppid'],
            'exe'  : proc.info['exe'] or "N/A"
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# Step 2: build parent → children map
tree = defaultdict(list)
for pid, info in all_procs.items():
    tree[info['ppid']].append(pid)

# Step 3: print tree function
def print_tree(pid, level=0):
    if pid not in all_procs:
        return
    name = all_procs[pid]['name']
    indent = "    " * level
    connector = "└── " if level > 0 else ""
    print(f"{indent}{connector}{name} (PID:{pid})")
    for child_pid in tree.get(pid, []):
        print_tree(child_pid, level + 1)

# Step 4: find root processes and print tree
print("\nProcess Tree:")
print("-" * 50)
roots = [pid for pid, info in all_procs.items()
         if info['ppid'] not in all_procs]
for root_pid in roots:
    print_tree(root_pid)

# Step 5: suspicious parent-child pairs
SUSPICIOUS_PAIRS = [
    ("winword.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("acrord32.exe", "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
    ("mspaint.exe",  "cmd.exe"),
]

alerts = []

print("\n\nScanning for suspicious relationships...")
print("-" * 50)

for pid, info in all_procs.items():
    parent_pid = info['ppid']
    child_name = info['name'].lower()

    if parent_pid in all_procs:
        parent_name = all_procs[parent_pid]['name'].lower()

        for sus_parent, sus_child in SUSPICIOUS_PAIRS:
            if parent_name == sus_parent and child_name == sus_child:
                alert = (f"[ALERT] Suspicious: {parent_name} "
                         f"(PID:{parent_pid}) → "
                         f"{child_name} (PID:{pid})")
                alerts.append(alert)
                print(alert)

if not alerts:
    print("No suspicious relationships found.")

# Step 6: save alerts to file
alert_path = r"D:\Projects\WindowsMonitorAgent\logs\alerts.txt"

with open(alert_path, "w") as f:
    f.write("Suspicious Process Alert Log\n")
    f.write(f"Scan Time: {datetime.datetime.now()}\n")
    f.write("=" * 60 + "\n\n")

    if alerts:
        for a in alerts:
            f.write(a + "\n")
    else:
        f.write("No suspicious relationships detected.\n")

    f.write(f"\nTotal alerts: {len(alerts)}\n")

print(f"\nAlerts saved to: {alert_path}")
print(f"Total alerts found: {len(alerts)}")
print("\nscan complete!")