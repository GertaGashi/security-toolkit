"""
Module - Variant C: Monitoring & Alerting
Monitors a log file for NEW events only, avoids duplicate alerts
by tracking processed event timestamps, and generates alerts.json.
"""

import json
import os
import time
from datetime import datetime
from collections import Counter


# Path to track which events have already been processed
PROCESSED_LOG = "reports/processed_events.json"
ALERTS_FILE = "reports/alerts.json"

# Thresholds for alert generation
FAILED_LOGIN_THRESHOLD = 3   # alerts if a user/IP has >= this many failures in new batch


def load_processed_ids(processed_log=PROCESSED_LOG):
    """Load the set of already-processed event identifiers."""
    if not os.path.exists(processed_log):
        return set()
    with open(processed_log, "r") as f:
        data = json.load(f)
    return set(data.get("processed", []))


def save_processed_ids(processed_ids, processed_log=PROCESSED_LOG):
    """Save updated set of processed event identifiers."""
    os.makedirs(os.path.dirname(processed_log), exist_ok=True)
    with open(processed_log, "w") as f:
        json.dump({"processed": list(processed_ids)}, f, indent=2)


def make_event_id(event):
    """Create a unique ID for an event using timestamp + username + action."""
    return f"{event.get('timestamp','')}|{event.get('username','')}|{event.get('action','')}|{event.get('ip_address','')}"


def load_logs(filepath):
    """Load all log events from a JSON file."""
    if not os.path.exists(filepath):
        print(f"[!] Log file not found: '{filepath}'")
        return []
    with open(filepath, "r") as f:
        return json.load(f)


def get_new_events(all_events, processed_ids):
    """Return only events that have not been processed before."""
    new = []
    for event in all_events:
        eid = make_event_id(event)
        if eid not in processed_ids:
            new.append(event)
    return new


def generate_alerts(new_events):
    """
    Analyze new events and generate alerts for suspicious activity.
    Returns a list of alert dicts with severity levels.
    """
    alerts = []

    # Count failed logins by username and IP in the new batch
    failed_by_user = Counter()
    failed_by_ip = Counter()

    for event in new_events:
        if event.get("status", "").upper() == "FAILED":
            failed_by_user[event.get("username", "unknown")] += 1
            failed_by_ip[event.get("ip_address", "unknown")] += 1

    # Alert per user with too many failures
    for user, count in failed_by_user.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            alerts.append({
                "alert_id": f"ALERT-USER-{user}-{datetime.now().strftime('%H%M%S')}",
                "type": "BRUTE_FORCE_USER",
                "severity": severity,
                "description": f"User '{user}' had {count} failed login(s) in new events.",
                "subject": user,
                "count": count,
                "timestamp": datetime.now().isoformat(),
            })

    # Alert per IP with too many failures
    for ip, count in failed_by_ip.items():
        if count >= FAILED_LOGIN_THRESHOLD:
            severity = "HIGH" if count >= 5 else "MEDIUM"
            alerts.append({
                "alert_id": f"ALERT-IP-{ip.replace('.', '_')}-{datetime.now().strftime('%H%M%S')}",
                "type": "BRUTE_FORCE_IP",
                "severity": severity,
                "description": f"IP '{ip}' had {count} failed login(s) in new events.",
                "subject": ip,
                "count": count,
                "timestamp": datetime.now().isoformat(),
            })

    return alerts


def load_existing_alerts(alerts_file=ALERTS_FILE):
    """Load any previously saved alerts to avoid duplicates."""
    if not os.path.exists(alerts_file):
        return []
    with open(alerts_file, "r") as f:
        data = json.load(f)
    return data.get("alerts", [])


def save_alerts(alerts, alerts_file=ALERTS_FILE):
    """Append new alerts to alerts.json, keeping existing ones."""
    existing = load_existing_alerts(alerts_file)
    all_alerts = existing + alerts
    os.makedirs(os.path.dirname(alerts_file), exist_ok=True)
    with open(alerts_file, "w") as f:
        json.dump({"total": len(all_alerts), "alerts": all_alerts}, f, indent=2)
    print(f"[+] Alerts saved to '{alerts_file}' (total: {len(all_alerts)})")


def print_alert_summary(alerts):
    """Print a summary of alerts by type and severity."""
    if not alerts:
        print("  [OK] No new alerts generated.")
        return

    by_severity = Counter(a["severity"] for a in alerts)
    by_type = Counter(a["type"] for a in alerts)

    print(f"\n  New alerts generated: {len(alerts)}")
    print(f"  By severity : {dict(by_severity)}")
    print(f"  By type     : {dict(by_type)}")
    print("\n  Alert details:")
    for alert in alerts:
        print(f"    [{alert['severity']}] {alert['type']} - {alert['description']}")


def monitor_once(log_path):
    """
    Run one monitoring pass: load log, find new events, generate alerts.
    Marks new events as processed so they won't be re-alerted next time.
    """
    print(f"\n[*] Monitoring: '{log_path}'")
    all_events = load_logs(log_path)
    if not all_events:
        return

    processed_ids = load_processed_ids()
    new_events = get_new_events(all_events, processed_ids)

    print(f"  Total events in log : {len(all_events)}")
    print(f"  Already processed   : {len(processed_ids)}")
    print(f"  New events          : {len(new_events)}")

    if not new_events:
        print("  [OK] No new events since last check.")
        return

    print("\n  New events found:")
    for e in new_events:
        print(f"    {e.get('timestamp')} | {e.get('username')} | {e.get('action')} | {e.get('status')}")

    # Generate alerts for the new events
    alerts = generate_alerts(new_events)
    print_alert_summary(alerts)

    if alerts:
        save_alerts(alerts)

    # Mark new events as processed so they won't trigger again
    for event in new_events:
        processed_ids.add(make_event_id(event))
    save_processed_ids(processed_ids)

    # Save monitoring report
    save_monitoring_report(new_events, alerts)


def save_monitoring_report(new_events, alerts, report_path="reports/monitoring_report.txt"):
    """Save a monitoring report showing new events and generated alerts."""
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    by_type = Counter(a["type"] for a in alerts)
    by_severity = Counter(a["severity"] for a in alerts)

    with open(report_path, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("MONITORING REPORT\n")
        f.write(f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"New events processed : {len(new_events)}\n")
        f.write(f"Alerts generated     : {len(alerts)}\n")
        f.write(f"By type     : {dict(by_type)}\n")
        f.write(f"By severity : {dict(by_severity)}\n\n")

        f.write("--- NEW EVENTS ---\n")
        for e in new_events:
            f.write(f"  {e.get('timestamp')} | {e.get('username')} | {e.get('ip_address')} | {e.get('action')} | {e.get('status')}\n")

        f.write("\n--- ALERTS ---\n")
        for a in alerts:
            f.write(f"  [{a['severity']}] {a['type']}: {a['description']}\n")

        if not alerts:
            f.write("  No alerts generated.\n")

    print(f"[+] Monitoring report saved to '{report_path}'")


def run():
    """Interactive monitoring menu."""
    while True:
        print("\n--- Monitoring & Alerting (Variant C) ---")
        print("1. Run single monitoring check")
        print("2. Run continuous monitoring (every 10 seconds, Ctrl+C to stop)")
        print("3. View current alerts")
        print("4. Reset processed events (re-scan all)")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            log_path = input("Enter log file path (default: data/sample_logs.json): ").strip()
            if not log_path:
                log_path = "data/sample_logs.json"
            monitor_once(log_path)

        elif choice == "2":
            log_path = input("Enter log file path (default: data/sample_logs.json): ").strip()
            if not log_path:
                log_path = "data/sample_logs.json"
            print("[*] Continuous monitoring started. Press Ctrl+C to stop.")
            try:
                while True:
                    monitor_once(log_path)
                    print("[*] Waiting 10 seconds before next check...")
                    time.sleep(10)
            except KeyboardInterrupt:
                print("\n[*] Monitoring stopped.")

        elif choice == "3":
            alerts = load_existing_alerts()
            if not alerts:
                print("  No alerts found.")
            else:
                print(f"\n  Total alerts: {len(alerts)}")
                for a in alerts:
                    print(f"    [{a['severity']}] {a['type']} - {a['description']}")

        elif choice == "4":
            confirm = input("Reset processed events? This will re-process all on next run. (y/n): ").strip().lower()
            if confirm == "y":
                if os.path.exists(PROCESSED_LOG):
                    os.remove(PROCESSED_LOG)
                print("[+] Processed events reset.")

        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
