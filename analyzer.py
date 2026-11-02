import re
import json
from collections import Counter, defaultdict

# Regex for standard Apache/Nginx access logs
# Matches: IP - - [Timestamp] "METHOD URI HTTP/VER" STATUS SIZE
LOG_REGEX = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<timestamp>.*?)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>.*?) HTTP/.*?" (?P<status>\d{3}) (?P<size>\d+|-)'
)

# SIEM Anomaly Detection Thresholds
FAILED_LOGIN_THRESHOLD = 5
HIGH_TRAFFIC_THRESHOLD = 20

def parse_logs(file_path):
    parsed_events = []
    with open(file_path, 'r') as log_file:
        for line in log_file:
            match = LOG_REGEX.search(line)
            if match:
                parsed_events.append(match.groupdict())
    return parsed_events

def analyze_threats(parsed_logs):
    ip_request_counts = Counter()
    failed_auth_attempts = defaultdict(int)
    
    for event in parsed_logs:
        ip = event['ip']
        ip_request_counts[ip] += 1
        
        # Track 401 Unauthorized or 403 Forbidden for brute-force detection
        if event['status'] in ('401', '403') and 'login' in event['uri'].lower():
            failed_auth_attempts[ip] += 1
            
    # Identify malicious IPs based on thresholds
    anomalies = {
        "brute_force_suspects": [
            {"ip": ip, "failed_attempts": count}
            for ip, count in failed_auth_attempts.items() if count >= FAILED_LOGIN_THRESHOLD
        ],
        "ddos_or_scraper_suspects": [
            {"ip": ip, "total_requests": count}
            for ip, count in ip_request_counts.items() if count >= HIGH_TRAFFIC_THRESHOLD
        ]
    }
    return anomalies

def export_threat_intelligence(anomalies, output_file='incident_report.json'):
    with open(output_file, 'w') as out_file:
        json.dump(anomalies, out_file, indent=4)
    print(f"Analysis complete. Threat report exported to {output_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SIEM Log Anomaly Detector")
    parser.add_argument("--file", default="simulated_traffic.log", help="Path to the log file")
    parser.add_argument("--failed_logins", type=int, default=5, help="Threshold for brute force")
    parser.add_argument("--traffic_spike", type=int, default=20, help="Threshold for DDoS/Scraping")
    args = parser.parse_args()

    # Update global variables with user arguments
    FAILED_LOGIN_THRESHOLD = args.failed_logins
    HIGH_TRAFFIC_THRESHOLD = args.traffic_spike

    print(f"Parsing logs from {args.file}...")
    structured_data = parse_logs(args.file)
    detected_threats = analyze_threats(structured_data)
    export_threat_intelligence(detected_threats)