import psutil
import datetime

print("=" * 70)
print("Process Detail Scan - Day 2")
print(f"Scan Time: {datetime.datetime.now()}")
print("=" * 70)

fields = ['pid', 'name', 'exe', 'ppid','memory_info', 'status','username', 'create_time']

processes = psutil.process_iter(fields)

print(f"\n{'PID':<7} {'Name':<25} {'Status':<12} {'Memory(MB)':<14} {'User':<20} {'Started'}")
print("-" * 90)

for proc in processes:
    try:
        pid    = proc.info['pid']
        name   = proc.info['name']
        status = proc.info['status']
        mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
        user   = proc.info['username'] or "N/A"
        start  = datetime.datetime.fromtimestamp(
                 proc.info['create_time']).strftime("%H:%M:%S")

        print(f"{pid:<7} {name:<25} {status:<12} {mem_mb:<14.2f} {user:<20} {start}")

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

print("\nScan complete!")

# Save output to log file
log_path = r"D:\Projects\WindowsMonitorAgent\logs\scan_log.txt"

with open(log_path, "w") as log_file:
    log_file.write("Windows Process Scan Log\n")
    log_file.write(f"Scan Time: {datetime.datetime.now()}\n")
    log_file.write("=" * 70 + "\n\n")

    for proc in psutil.process_iter(fields):
        try:
            pid    = proc.info['pid']
            name   = proc.info['name']
            status = proc.info['status']
            mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
            user   = proc.info['username'] or "N/A"
            start  = datetime.datetime.fromtimestamp(
                     proc.info['create_time']).strftime("%H:%M:%S")

            line = f"PID:{pid:<6} | {name:<25} | {status:<12} | {mem_mb:<10.2f}MB | {user}\n"
            log_file.write(line)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    log_file.write("\nScan complete!\n")

print(f"\nLog saved to: {log_path}")