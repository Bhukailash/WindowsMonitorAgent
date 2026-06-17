import psutil
import datetime
import os

print("=" * 60)
print("Whitelist / Blacklist Engine")
print(f"Time: {datetime.datetime.now()}")
print("=" * 60)

# Safe known processes - whitelist
WHITELIST = {
    "system", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "explorer.exe", "taskmgr.exe",
    "chrome.exe", "msedge.exe", "firefox.exe",
    "code.exe", "python.exe", "pythonw.exe",
    "notepad.exe", "cmd.exe", "powershell.exe",
    "conhost.exe", "dwm.exe", "sihost.exe",
    "winlogon.exe", "fontdrvhost.exe", "spoolsv.exe"
}

# Known dangerous processes - blacklist
BLACKLIST = {
    "netcat.exe", "nc.exe", "mimikatz.exe",
    "pwdump.exe", "fgdump.exe", "wce.exe",
    "psexec.exe", "nmap.exe", "metasploit.exe",
    "meterpreter.exe", "cobaltstrike.exe",
    "keylogger.exe", "ransomware.exe", "trojan.exe"
    "powershell.exe"
}

alerts = []
results = {"safe": 0, "danger": 0, "unknown": 0}

print(f"\n{'PID':<7} {'Name':<25} {'Status':<12} {'Category'}")
print("-" * 65)

for proc in psutil.process_iter(['pid', 'name', 'exe', 'status']):
    try:
        pid    = proc.info['pid']
        name   = proc.info['name'].lower()
        exe    = proc.info['exe'] or "N/A"
        status = proc.info['status']

        if name in BLACKLIST:
            results['danger'] += 1
            alert = (f"[HIGH]   BLACKLISTED process found: "
                     f"{name} (PID:{pid}) Path:{exe}")
            alerts.append(alert)
            print(f"{pid:<7} {name:<25} {status:<12} DANGER")

        elif name in WHITELIST:
            results['safe'] += 1
            print(f"{pid:<7} {name:<25} {status:<12} Safe")

        else:
            results['unknown'] += 1
            alert = (f"[MEDIUM] Unknown process: "
                     f"{name} (PID:{pid}) Path:{exe}")
            alerts.append(alert)
            print(f"{pid:<7} {name:<25} {status:<12} Unknown")

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print(f"\nSummary — Safe:{results['safe']} | "
      f"Unknown:{results['unknown']} | "
      f"Danger:{results['danger']}")

# Suspicious path detection
SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\", "\\recycle"
]

print("\nChecking for processes in suspicious paths...")
print("-" * 60)

found_sus = False
for proc in psutil.process_iter(['pid', 'name', 'exe']):
    try:
        exe = proc.info['exe']
        if not exe:
            continue
        exe_lower = exe.lower()
        for sus_path in SUSPICIOUS_PATHS:
            if sus_path in exe_lower:
                found_sus = True
                alert = (f"[HIGH]   Suspicious path: "
                         f"{proc.info['name']} "
                         f"(PID:{proc.info['pid']}) "
                         f"Path:{exe}")
                alerts.append(alert)
                print(alert)

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

if not found_sus:
    print("No processes found in suspicious paths.")

# Save all alerts
alert_path = r"D:\Projects\WindowsMonitorAgent\logs\alerts.txt"

with open(alert_path, "w") as f:
    f.write("Whitelist/Blacklist Alert Log\n")
    f.write(f"Scan Time: {datetime.datetime.now()}\n")
    f.write("=" * 60 + "\n\n")

    if alerts:
        for a in alerts:
            f.write(a + "\n")
    else:
        f.write("No threats detected.\n")

    f.write(f"\nTotal alerts: {len(alerts)}\n")
    f.write(f"Safe: {results['safe']} | "
            f"Unknown: {results['unknown']} | "
            f"Danger: {results['danger']}\n")

print(f"\nAlerts saved to: {alert_path}")
print(f"Total alerts: {len(alerts)}")
print("\n scan complete!")