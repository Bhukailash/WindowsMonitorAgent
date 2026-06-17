import psutil
import datetime

print("=" * 65)
print("Alert System with Severity Levels")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 65)

# Alert severity levels
HIGH   = "HIGH"
MEDIUM = "MEDIUM"
LOW    = "LOW"

alerts = []

def add_alert(level, message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    alert = f"[{level}] [{timestamp}] {message}"
    alerts.append({"level": level, "message": alert})
    print(alert)

# ── Rule 1: Suspicious parent-child pairs ──
SUSPICIOUS_PAIRS = [
    ("winword.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
]

print("\n[CHECK 1] Scanning parent-child relationships...")
print("-" * 65)

all_procs = {}
for proc in psutil.process_iter(['pid', 'name', 'ppid']):
    try:
        all_procs[proc.info['pid']] = {
            'name': proc.info['name'],
            'ppid': proc.info['ppid']
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

for pid, info in all_procs.items():
    parent_pid  = info['ppid']
    child_name  = info['name'].lower()
    if parent_pid in all_procs:
        parent_name = all_procs[parent_pid]['name'].lower()
        for sp, sc in SUSPICIOUS_PAIRS:
            if parent_name == sp and child_name == sc:
                add_alert(HIGH,
                    f"Suspicious pair: {parent_name} → {child_name} "
                    f"(PID:{pid})")

# ── Rule 2: Processes in suspicious paths ──
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",
    "\\users\\public\\", "\\appdata\\local\\temp\\"
]

print("\n[CHECK 2] Scanning for suspicious path processes...")
print("-" * 65)

for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        exe = proc.info['exe']
        if not exe:
            continue
        exe_lower = exe.lower()
        for sp in SUSPICIOUS_PATHS:
            if sp in exe_lower:
                add_alert(HIGH,
                    f"Process in suspicious path: "
                    f"{proc.info['name']} (PID:{proc.info['pid']})"
                    f"\n         Path: {exe}")
                break
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# ── Rule 3: High memory usage processes ──
print("\n[CHECK 3] Scanning for high memory usage...")
print("-" * 65)

for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
    try:
        mem = proc.info['memory_info']
        if mem and mem.rss > 500 * 1024 * 1024:  # over 500MB
            add_alert(MEDIUM,
                f"High memory usage: {proc.info['name']} "
                f"(PID:{proc.info['pid']}) "
                f"— {round(mem.rss/1024/1024)}MB")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

# ── Rule 4: Too many processes with same name ──
print("\n[CHECK 4] Scanning for duplicate process names...")
print("-" * 65)

name_count = {}
for proc in psutil.process_iter(['name']):
    try:
        n = proc.info['name'].lower()
        name_count[n] = name_count.get(n, 0) + 1
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

for name, count in name_count.items():
    if count > 10 and name not in ['svchost.exe', 'conhost.exe']:
        add_alert(LOW,
            f"Many instances of {name} running: {count} copies")

# ── Summary ──
high   = sum(1 for a in alerts if a['level'] == HIGH)
medium = sum(1 for a in alerts if a['level'] == MEDIUM)
low    = sum(1 for a in alerts if a['level'] == LOW)

print("\n" + "=" * 65)
print("ALERT SUMMARY")
print("=" * 65)
print(f"HIGH   alerts : {high}")
print(f"MEDIUM alerts : {medium}")
print(f"LOW    alerts : {low}")
print(f"TOTAL  alerts : {len(alerts)}")

# ── Save to file ──
log_path = r"D:\Projects\WindowsMonitorAgent\logs\alerts_02.txt"

with open(log_path, "w") as f:
    f.write("Day 7 - Alert System Log\n")
    f.write(f"Scan Time: {datetime.datetime.now()}\n")
    f.write("=" * 65 + "\n\n")
    for a in alerts:
        f.write(a['message'] + "\n")
    f.write(f"\nHIGH: {high} | MEDIUM: {medium} | LOW: {low}\n")
    f.write(f"Total alerts: {len(alerts)}\n")

print(f"\nAlerts saved to: {log_path}")
print("\n complete!")