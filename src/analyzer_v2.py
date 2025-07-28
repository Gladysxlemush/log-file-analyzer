import re
import csv
import sys
import os
from collections import defaultdict, Counter
from datetime import datetime
from colorama import init, Fore

init(autoreset=True)

def parse_log(file_path):
    failed_logins = defaultdict(int)
    pattern = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] \".*?\" \d{3} .*? \"Failed login\"")

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    failed_logins[ip] += 1
    except FileNotFoundError:
        print(f"{Fore.RED}Log file not found: {file_path}")
        sys.exit(1)

    return failed_logins

def print_suspicious_ips(failed_logins):
    print(f"\n{Fore.YELLOW}Suspicious IPs (5+ failed logins):")
    for ip, count in failed_logins.items():
        if count >= 5:
            print(f"{Fore.RED}- {ip} ({count} failed attempts)")

def show_top_offenders(failed_logins, top_n=3):
    top_offenders = Counter(failed_logins).most_common(top_n)
    print(f"\n{Fore.CYAN}Top {top_n} Offending IPs:")
    for ip, count in top_offenders:
        print(f"- {ip}: {count} failed attempts")

def export_csv(failed_logins, output_file):
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Failed Attempts"])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])
    print(f"\n{Fore.GREEN}Report saved to {output_file}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python analyzer_v2.py <log_file_path>")
        sys.exit(1)

    log_file = sys.argv[1]
    print("Script started...")

    failed_logins = parse_log(log_file)
    print_suspicious_ips(failed_logins)
    show_top_offenders(failed_logins)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    export_csv(failed_logins, f"../reports/suspicious_report_{timestamp}.csv")

if __name__ == "__main__":
    main()
