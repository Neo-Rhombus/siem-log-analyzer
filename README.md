# SIEM Log Analyzer

## Overview
This project is a lightweight, regex-based log analyzer designed to parse unstructured web server logs and output structured JSON threat intelligence. It automates the detection of network anomalies, such as brute-force attacks and abnormal traffic spikes, to identify malicious IP addresses for proactive incident response.

## Methodology
To efficiently process large security datasets, this script utilizes an $O(N)$ linear parsing approach. By evaluating the log file line-by-line, the script handles massive log streams without loading the entire dataset into memory. 

The core detection engine relies on Security Information and Event Management (SIEM) methodologies:
* **Data Normalization:** Regular expressions (regex) extract critical network fields (Source IP, HTTP Method, URI, Status Code) from raw text strings.
* **Threshold Detection:** State-tracking dictionaries monitor request frequencies and failed authentications over time, flagging IPs that breach configurable security limits.

## Usage
Ensure you have Python installed. You can run the script from the command line and pass custom threshold limits dynamically.

**Basic Execution:**
```bash
python analyzer.py

**Advanced Execution (Custom Thresholds):**
You can specify the log file, the failed login threshold for brute-force detection, and the traffic spike threshold for DDoS/scraper detection.

```bash
python analyzer.py --file advanced_traffic.log --failed_logins 10 --traffic_spike 50

## Output:
The script generates an incident_report.json file containing the flagged IP addresses and their specific anomaly metrics, which can be ingested directly by a firewall API or SOAR platform.
