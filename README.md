# 📊 Log File Analyzer

A Python-based tool designed to analyze server log files and detect suspicious behavior such as repeated failed login attempts.  
Ideal for showcasing skills in **log parsing**, **cybersecurity threat detection**, and **data analysis**.

---

## ✨ Features

- Parses Apache-style log files
- Detects suspicious IPs with **5+ failed login attempts**
- Highlights top offending IP addresses
- Exports a **CSV report** of failed login statistics
- Fully CLI-based for simple terminal usage

---

## 🧰 Technologies Used

- **Python 3**  
- `re` for log file parsing  
- `csv` for exporting reports  
- `collections.Counter` for offender ranking  
- `argparse` for command-line input  
- **Colorama** for clean console output (optional)

---

## 🧠 What I Learned
-Practical use of regex to parse unstructured logs

-How to detect brute-force behavior from log patterns

-Exporting structured data to CSV for reporting

-How to build a simple but useful SOC analyst tool

## 📁 Project Structure
---

## 🚧 Future Improvements
-Include parsing for multiple log formats (e.g., NGINX, Windows Event Logs)

-Integrate IP geolocation lookup for flagged IPs

-Create a GUI or web front-end for non-technical users

-Add support for scanning multiple log files in batch mode
---
## 📁 Project Structure

```bash
log-file-analyzer/
├── logs/
│   └── sample_apache.log          # Example Apache log file
├── reports/
│   └── suspicious_report_*.csv    # Output reports with timestamp
├── src/
│   └── analyzer_v2.py             # Main analyzer script (no emojis)
├── README.md                      # Project documentation






