import psutil
import datetime

print("=" * 60)
print("Windows Process Monitor - Day 1")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 60)

processes = psutil.process_iter(['pid', 'name', 'exe', 'ppid'])

print(f"\n{'PID':<8} {'PPID':<8} {'Process Name':<30} {'Path'}")
print("-" * 80)

for proc in processes:
    try:
        pid  = proc.info['pid']
        ppid = proc.info['ppid']
        name = proc.info['name']
        path = proc.info['exe'] or "N/A"
        print(f"{pid:<8} {ppid:<8} {name:<30} {path}")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print("\n\tScan complete!")