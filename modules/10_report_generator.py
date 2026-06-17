import psutil
import datetime
import subprocess
import os

print("=" * 65)
print("  FINAL DETECTION REPORT GENERATOR")
print(f"  Generated: {datetime.datetime.now()}")
print("=" * 65)

# ── All Detection Rules ──
SUSPICIOUS_PAIRS = [
    ("winword.exe",  "powershell.exe"),
    ("winword.exe",  "cmd.exe"),
    ("excel.exe",    "powershell.exe"),
    ("excel.exe",    "cmd.exe"),
    ("outlook.exe",  "powershell.exe"),
    ("explorer.exe", "powershell.exe"),
]

BLACKLIST = {
    "netcat.exe", "nc.exe", "mimikatz.exe",
    "pwdump.exe", "keylogger.exe", "trojan.exe",
    "ransomware.exe", "meterpreter.exe"
}

SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\downloads\\",
    "\\users\\public\\", "\\appdata\\local\\temp\\"
]

TRUSTED_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

alerts = []
stats  = {
    "processes"   : 0,
    "services"    : 0,
    "high"        : 0,
    "medium"      : 0,
    "low"         : 0,
    "trusted"     : 0,
    "suspicious"  : 0,
    "unknown"     : 0,
}

def add_alert(level, category, message):
    alerts.append({
        "level"   : level,
        "category": category,
        "message" : message,
        "time"    : datetime.datetime.now().strftime("%H:%M:%S")
    })
    stats[level.lower()] += 1
    print(f"  [{level}] {message}")

# ── Collect Processes ──
print("\n[1/5] Collecting processes...")
all_procs = {}
for proc in psutil.process_iter(['pid','name','ppid','exe','memory_info']):
    try:
        all_procs[proc.info['pid']] = {
            'name': proc.info['name'],
            'ppid': proc.info['ppid'],
            'exe' : proc.info['exe'] or "N/A",
            'mem' : proc.info['memory_info']
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
stats['processes'] = len(all_procs)
print(f"  → {len(all_procs)} processes collected")

# ── Check 1: Parent-Child ──
print("\n[2/5] Checking parent-child relationships...")
for pid, info in all_procs.items():
    ppid       = info['ppid']
    child_name = info['name'].lower()
    if ppid in all_procs:
        parent_name = all_procs[ppid]['name'].lower()
        for sp, sc in SUSPICIOUS_PAIRS:
            if parent_name == sp and child_name == sc:
                add_alert("HIGH", "PARENT-CHILD",
                    f"{parent_name} → {child_name} (PID:{pid})")

# ── Check 2: Blacklist ──
print("\n[3/5] Running blacklist check...")
for pid, info in all_procs.items():
    if info['name'].lower() in BLACKLIST:
        add_alert("HIGH", "BLACKLIST",
            f"Blacklisted: {info['name']} (PID:{pid})")

# ── Check 3: Path Analysis ──
print("\n[4/5] Analyzing process paths...")
for pid, info in all_procs.items():
    exe = info['exe'].lower()
    is_trusted = any(exe.startswith(tp) for tp in TRUSTED_PATHS)
    if is_trusted:
        stats['trusted'] += 1
    else:
        for sp in SUSPICIOUS_PATHS:
            if sp in exe:
                stats['suspicious'] += 1
                add_alert("HIGH", "SUSP-PATH",
                    f"{info['name']} (PID:{pid}) → {info['exe']}")
                break
        else:
            stats['unknown'] += 1

# ── Check 4: High Memory ──
print("\n[5/5] Checking memory usage...")
for pid, info in all_procs.items():
    mem = info['mem']
    if mem and mem.rss > 500 * 1024 * 1024:
        add_alert("MEDIUM", "MEMORY",
            f"{info['name']} (PID:{pid}) "
            f"— {round(mem.rss/1024/1024)}MB")

# ── Service Audit ──
result = subprocess.run(
    ["powershell", "-Command",
     "Get-Service | Measure-Object | Select-Object -ExpandProperty Count"],
    capture_output=True, text=True
)
try:
    stats['services'] = int(result.stdout.strip())
except:
    stats['services'] = 0

# ── Generate HTML Report ──
report_path = r"D:\Projects\WindowsMonitorAgent\reports\final_report.html"

html = f"""<!DOCTYPE html>
<html>
<head>
<title>Windows Monitor Agent — Final Report</title>
<style>
  body {{ font-family: Arial, sans-serif; background:#0f0f0f;
          color:#e0e0e0; margin:0; padding:20px; }}
  h1   {{ color:#00d4aa; border-bottom:2px solid #00d4aa;
          padding-bottom:10px; }}
  h2   {{ color:#00d4aa; margin-top:30px; }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr);
                gap:15px; margin:20px 0; }}
  .stat-box  {{ background:#1a1a1a; border:1px solid #333;
                border-radius:8px; padding:15px; text-align:center; }}
  .stat-num  {{ font-size:32px; font-weight:bold; color:#00d4aa; }}
  .stat-lbl  {{ font-size:13px; color:#888; margin-top:5px; }}
  table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
  th {{ background:#1a1a1a; color:#00d4aa; padding:10px;
        text-align:left; border:1px solid #333; }}
  td {{ padding:9px 10px; border:1px solid #222; font-size:13px; }}
  tr:nth-child(even) {{ background:#141414; }}
  .HIGH   {{ color:#ff4444; font-weight:bold; }}
  .MEDIUM {{ color:#ffaa00; font-weight:bold; }}
  .LOW    {{ color:#44aaff; font-weight:bold; }}
  .footer {{ margin-top:40px; color:#555; font-size:12px;
             border-top:1px solid #333; padding-top:15px; }}
  .clean  {{ color:#00d4aa; font-size:18px; font-weight:bold; }}
</style>
</head>
<body>
<h1>🛡 Windows Monitor Agent — Final Detection Report</h1>
<p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Scan Statistics</h2>
<div class="stat-grid">
  <div class="stat-box">
    <div class="stat-num">{stats['processes']}</div>
    <div class="stat-lbl">Processes Scanned</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">{stats['services']}</div>
    <div class="stat-lbl">Services Scanned</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#ff4444">{stats['high']}</div>
    <div class="stat-lbl">HIGH Alerts</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#ffaa00">{stats['medium']}</div>
    <div class="stat-lbl">MEDIUM Alerts</div>
  </div>
</div>

<div class="stat-grid">
  <div class="stat-box">
    <div class="stat-num" style="color:#00d4aa">{stats['trusted']}</div>
    <div class="stat-lbl">Trusted Processes</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#888">{stats['unknown']}</div>
    <div class="stat-lbl">Unknown Processes</div>
  </div>
  <div class="stat-box">
    <div class="stat-num" style="color:#ff4444">{stats['suspicious']}</div>
    <div class="stat-lbl">Suspicious Processes</div>
  </div>
  <div class="stat-box">
    <div class="stat-num">{stats['high']+stats['medium']+stats['low']}</div>
    <div class="stat-lbl">Total Alerts</div>
  </div>
</div>

<h2>Alert Details</h2>
{"<p class='clean'>✓ No threats detected. System is clean.</p>" 
  if not alerts else ""}
"""

if alerts:
    html += """<table>
<tr>
  <th>Time</th>
  <th>Level</th>
  <th>Category</th>
  <th>Details</th>
</tr>"""
    for a in alerts:
        html += f"""<tr>
  <td>{a['time']}</td>
  <td class="{a['level']}">{a['level']}</td>
  <td>{a['category']}</td>
  <td>{a['message']}</td>
</tr>"""
    html += "</table>"

html += f"""
<div class="footer">
  <p>Report generated by Windows Monitor Agent</p>
  <p>Student Project | Scan completed: 
     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>
</body>
</html>"""

with open(report_path, "w", encoding="utf-8") as f:
    f.write(html)
    
# ── Also save TXT version ──
txt_path = r"D:\Projects\WindowsMonitorAgent\reports\final_report.txt"
with open(txt_path, "w", encoding="utf-8") as f:
    f.write("WINDOWS MONITOR AGENT — FINAL DETECTION REPORT\n")
    f.write(f"Generated: {datetime.datetime.now()}\n")
    f.write("=" * 65 + "\n\n")
    f.write("STATISTICS:\n")
    f.write(f"  Processes : {stats['processes']}\n")
    f.write(f"  Services  : {stats['services']}\n")
    f.write(f"  HIGH      : {stats['high']}\n")
    f.write(f"  MEDIUM    : {stats['medium']}\n")
    f.write(f"  LOW       : {stats['low']}\n")
    f.write(f"  Total     : {stats['high']+stats['medium']+stats['low']}\n\n")
    f.write("ALERTS:\n")
    f.write("-" * 65 + "\n")
    if alerts:
        for a in alerts:
            f.write(f"[{a['level']}] [{a['time']}] "
                    f"[{a['category']}] {a['message']}\n")
    else:
        f.write("No threats detected.\n")

print("\n" + "=" * 65)
print("  FINAL REPORT SUMMARY")
print("=" * 65)
print(f"  Processes : {stats['processes']}")
print(f"  Services  : {stats['services']}")
print(f"  HIGH      : {stats['high']}")
print(f"  MEDIUM    : {stats['medium']}")
print(f"  LOW       : {stats['low']}")
print(f"  Total     : {stats['high']+stats['medium']+stats['low']}")
print(f"\nHTML report : {report_path}")
print(f"TXT report  : {txt_path}")
print("\nReport fetching complete!")