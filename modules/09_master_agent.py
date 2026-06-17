import psutil
import datetime
import logging
import subprocess
import os

# ── Setup Logging ──
log_path = r"D:\Projects\WindowsMonitorAgent\logs\master_agent.log"
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("MasterAgent")

# ── Detection Rules ──
SUSPICIOUS_PAIRS = [
    ("winword.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
]

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",
    "\\users\\public\\", "\\appdata\\local\\temp\\"
]

WHITELIST = {
    "system", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "taskmgr.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "code.exe", "python.exe", "pythonw.exe",
    "notepad.exe", "cmd.exe", "powershell.exe",
    "conhost.exe", "dwm.exe", "winlogon.exe"
}

BLACKLIST = {
    "netcat.exe", "nc.exe", "mimikatz.exe",
    "pwdump.exe", "keylogger.exe", "trojan.exe",
    "ransomware.exe", "meterpreter.exe"
}

TRUSTED_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

all_alerts = []

def add_alert(level, module, message):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    alert = {
        "level"  : level,
        "module" : module,
        "message": message,
        "time"   : timestamp
    }
    all_alerts.append(alert)
    if level == "HIGH":
        logger.critical(f"[{module}] {message}")
    elif level == "MEDIUM":
        logger.warning(f"[{module}] {message}")
    else:
        logger.info(f"[{module}] {message}")

# ════════════════════════════════════════
print("=" * 65)
print("  WINDOWS MONITOR AGENT - MASTER SCRIPT")
print(f"  Scan Time: {datetime.datetime.now()}")
print("=" * 65)
logger.info("Master Agent started")

# ── MODULE 1: Collect Processes ──
print("\n[MODULE 1] Collecting processes...")
logger.info("MODULE 1: Process collection started")

all_procs = {}
for proc in psutil.process_iter(['pid','name','ppid','exe','memory_info','status']):
    try:
        all_procs[proc.info['pid']] = {
            'name'  : proc.info['name'],
            'ppid'  : proc.info['ppid'],
            'exe'   : proc.info['exe'] or "N/A",
            'mem'   : proc.info['memory_info'],
            'status': proc.info['status']
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

logger.info(f"MODULE 1: {len(all_procs)} processes collected")
print(f"  → {len(all_procs)} processes collected")

# ── MODULE 2: Parent-Child Detection ──
print("\n[MODULE 2] Scanning parent-child relationships...")
logger.info("MODULE 2: Parent-child scan started")
pc_alerts = 0

for pid, info in all_procs.items():
    parent_pid = info['ppid']
    child_name = info['name'].lower()
    if parent_pid in all_procs:
        parent_name = all_procs[parent_pid]['name'].lower()
        for sp, sc in SUSPICIOUS_PAIRS:
            if parent_name == sp and child_name == sc:
                add_alert("HIGH", "PARENT-CHILD",
                    f"{parent_name} → {child_name} (PID:{pid})")
                pc_alerts += 1

logger.info(f"MODULE 2: {pc_alerts} suspicious pairs found")
print(f"  → {pc_alerts} suspicious pairs found")

# ── MODULE 3: Whitelist/Blacklist ──
print("\n[MODULE 3] Running whitelist/blacklist check...")
logger.info("MODULE 3: Whitelist/Blacklist scan started")
bl_alerts = 0

for pid, info in all_procs.items():
    name = info['name'].lower()
    if name in BLACKLIST:
        add_alert("HIGH", "BLACKLIST",
            f"Blacklisted process: {name} (PID:{pid})")
        bl_alerts += 1

logger.info(f"MODULE 3: {bl_alerts} blacklisted processes found")
print(f"  → {bl_alerts} blacklisted processes found")

# ── MODULE 4: Suspicious Path Check ──
print("\n[MODULE 4] Scanning process paths...")
logger.info("MODULE 4: Path analysis started")
path_alerts = 0

for pid, info in all_procs.items():
    exe = info['exe'].lower()
    is_trusted = any(exe.startswith(tp) for tp in TRUSTED_PATHS)
    if not is_trusted:
        for sp in SUSPICIOUS_PATHS:
            if sp in exe:
                add_alert("HIGH", "PATH",
                    f"Suspicious path: {info['name']} "
                    f"(PID:{pid}) → {info['exe']}")
                path_alerts += 1
                break

logger.info(f"MODULE 4: {path_alerts} suspicious paths found")
print(f"  → {path_alerts} suspicious paths found")

# ── MODULE 5: High Memory Check ──
print("\n[MODULE 5] Checking memory usage...")
logger.info("MODULE 5: Memory scan started")
mem_alerts = 0

for pid, info in all_procs.items():
    mem = info['mem']
    if mem and mem.rss > 500 * 1024 * 1024:
        add_alert("MEDIUM", "MEMORY",
            f"High memory: {info['name']} "
            f"(PID:{pid}) — {round(mem.rss/1024/1024)}MB")
        mem_alerts += 1

logger.info(f"MODULE 5: {mem_alerts} high memory processes")
print(f"  → {mem_alerts} high memory processes found")

# ── MODULE 6: Service Audit ──
print("\n[MODULE 6] Auditing Windows services...")
logger.info("MODULE 6: Service audit started")

result = subprocess.run(
    ["powershell", "-Command",
     "Get-Service | Select-Object Name,Status,StartType | ConvertTo-Csv -NoTypeInformation"],
    capture_output=True, text=True
)
svc_lines = result.stdout.strip().split("\n")[1:]
svc_count = len([l for l in svc_lines if l.strip()])
logger.info(f"MODULE 6: {svc_count} services scanned")
print(f"  → {svc_count} services scanned")

# ── FINAL SUMMARY ──
high   = sum(1 for a in all_alerts if a['level'] == "HIGH")
medium = sum(1 for a in all_alerts if a['level'] == "MEDIUM")
low    = sum(1 for a in all_alerts if a['level'] == "LOW")

print("\n" + "=" * 65)
print("  MASTER AGENT SUMMARY")
print("=" * 65)
print(f"  Processes scanned : {len(all_procs)}")
print(f"  Services scanned  : {svc_count}")
print(f"  HIGH   alerts     : {high}")
print(f"  MEDIUM alerts     : {medium}")
print(f"  LOW    alerts     : {low}")
print(f"  TOTAL  alerts     : {len(all_alerts)}")

# ── Save Master Report ──
report_path = r"D:\Projects\WindowsMonitorAgent\reports\master_report.txt"
os.makedirs(os.path.dirname(report_path), exist_ok=True)

with open(report_path, "w") as f:
    f.write("WINDOWS MONITOR AGENT — MASTER REPORT\n")
    f.write(f"Scan Time : {datetime.datetime.now()}\n")
    f.write("=" * 65 + "\n\n")

    f.write("SCAN STATISTICS:\n")
    f.write(f"  Processes scanned : {len(all_procs)}\n")
    f.write(f"  Services scanned  : {svc_count}\n")
    f.write(f"  Total alerts      : {len(all_alerts)}\n\n")

    f.write("ALL ALERTS:\n")
    f.write("-" * 65 + "\n")
    if all_alerts:
        for a in all_alerts:
            f.write(f"[{a['level']}] [{a['time']}] "
                    f"[{a['module']}] {a['message']}\n")
    else:
        f.write("No threats detected.\n")

    f.write(f"\nHIGH: {high} | MEDIUM: {medium} | LOW: {low}\n")

print(f"\nMaster report saved to: {report_path}")
print(f"Log saved to          : {log_path}")
print("\nDay 9 Master Agent complete!")
logger.info("Master Agent finished successfully")