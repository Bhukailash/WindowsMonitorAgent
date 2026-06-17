import psutil
import datetime
import logging
import os

# Setup logging
log_path = r"D:\Projects\WindowsMonitorAgent\logs\system_log.log"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(log_path),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("WindowsMonitorAgent")

print("=" * 65)
print("Logging System ")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 65)

logger.info("Windows Monitor Agent started")
logger.info(f"Log file: {log_path}")

# Suspicious pairs
SUSPICIOUS_PAIRS = [
    ("winword.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
]

# Suspicious paths
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",
    "\\users\\public\\", "\\appdata\\local\\temp\\"
]

# Collect all processes
logger.info("Collecting all running processes...")
all_procs = {}
for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe']):
    try:
        all_procs[proc.info['pid']] = {
            'name': proc.info['name'],
            'ppid': proc.info['ppid'],
            'exe' : proc.info['exe'] or "N/A"
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

logger.info(f"Total processes collected: {len(all_procs)}")

# Check 1: parent-child
logger.info("Running Check 1 — Parent-child relationship scan")
for pid, info in all_procs.items():
    parent_pid = info['ppid']
    child_name = info['name'].lower()
    if parent_pid in all_procs:
        parent_name = all_procs[parent_pid]['name'].lower()
        for sp, sc in SUSPICIOUS_PAIRS:
            if parent_name == sp and child_name == sc:
                logger.critical(
                    f"SUSPICIOUS PAIR: {parent_name} → "
                    f"{child_name} (PID:{pid})")

# Check 2: suspicious paths
logger.info("Running Check 2 — Suspicious path scan")
for pid, info in all_procs.items():
    exe = info['exe'].lower()
    for sp in SUSPICIOUS_PATHS:
        if sp in exe:
            logger.warning(
                f"Suspicious path: {info['name']} "
                f"(PID:{pid}) → {info['exe']}")
            break

# Check 3: high memory
logger.info("Running Check 3 — High memory usage scan")
for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
    try:
        mem = proc.info['memory_info']
        if mem and mem.rss > 500 * 1024 * 1024:
            logger.warning(
                f"High memory: {proc.info['name']} "
                f"(PID:{proc.info['pid']}) "
                f"— {round(mem.rss/1024/1024)}MB")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

logger.info("All checks complete")
logger.info(f"Full log saved to: {log_path}")
print(f"\n complete! Log saved to: {log_path}")