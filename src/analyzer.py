import re

def analyze_log(file_path):
    failed_logins = {}
    suspicious_ips = set()

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = re.search(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    failed_logins[ip] = failed_logins.get(ip, 0) + 1
                    if failed_logins[ip] >= 5:
                        suspicious_ips.add(ip)
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        with open("report.txt","w")as report:
            report.write("suspicious IPs (5+ failed logins):\n")
            for ip, count in suspicious_ips.items():
                report.write(f" - [ip] ({count} failed attempts)\n")
                print("\nReport saved to report.txt")
        return

    if suspicious_ips:
        print("\n Suspicious IPs (5+ failed logins):")
        for ip in suspicious_ips:
            print(f"  - {ip} ({failed_logins[ip]} failed attempts)")
    else:
        print("✅ No suspicious activity detected.")

# === MAIN ===
if __name__ == "__main__":
    log_path = input("Enter log file path (e.g., ../sample.log): ").strip()
    analyze_log(log_path)
