"""
Module 1 - Log Analyzer
Loads, filters, summarizes, and exports log/event data.
"""

import json
import csv
import os
from datetime import datetime
from collections import Counter


def load_logs(filepath):
    """Load logs from a JSON or CSV file. Returns a list of event dicts."""
    ext = os.path.splitext(filepath)[1].lower()
    logs = []

    if ext == ".json":
        with open(filepath, "r") as f:
            logs = json.load(f)

    elif ext == ".csv":
        with open(filepath, "r") as f:
            reader = csv.DictReader(f)
            logs = [row for row in reader]

    else:
        print("[!] Unsupported file format. Use .json or .csv")
        return []

    print(f"[+] Loaded {len(logs)} log events from '{filepath}'")
    return logs


def filter_logs(logs, username=None, ip=None, status=None, date=None):
    """
    Filter events by one or more criteria.
    date should be a string like '2024-06-01'
    """
    results = logs

    if username:
        results = [e for e in results if e.get("username", "").lower() == username.lower()]
    if ip:
        results = [e for e in results if e.get("ip_address", "") == ip]
    if status:
        results = [e for e in results if e.get("status", "").upper() == status.upper()]
    if date:
        results = [e for e in results if e.get("timestamp", "").startswith(date)]

    return results


def summarize_logs(logs):
    """Print and return a summary of the log events."""
    if not logs:
        print("[!] No events to summarize.")
        return {}

    users = Counter(e.get("username") for e in logs)
    ips = Counter(e.get("ip_address") for e in logs)
    statuses = Counter(e.get("status") for e in logs)
    actions = Counter(e.get("action") for e in logs)

    summary = {
        "total_events": len(logs),
        "events_per_user": dict(users),
        "events_per_ip": dict(ips),
        "events_per_status": dict(statuses),
        "events_per_action": dict(actions),
    }

    print("\n=== Log Summary ===")
    print(f"  Total events : {summary['total_events']}")
    print(f"  By status    : {summary['events_per_status']}")
    print(f"  By action    : {summary['events_per_action']}")
    print("\n  Events per user:")
    for user, count in users.most_common():
        print(f"    {user}: {count}")
    print("\n  Events per IP:")
    for ip, count in ips.most_common():
        print(f"    {ip}: {count}")

    return summary


def save_log_report(logs, summary, output_path="reports/log_report.txt"):
    """Save filtered events and summary to a text report file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("LOG ANALYSIS REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 50 + "\n\n")

        f.write("--- SUMMARY ---\n")
        f.write(f"Total Events : {summary.get('total_events', 0)}\n")
        f.write(f"By Status    : {summary.get('events_per_status', {})}\n")
        f.write(f"By Action    : {summary.get('events_per_action', {})}\n\n")

        f.write("--- FILTERED EVENTS ---\n")
        for event in logs:
            f.write(str(event) + "\n")

    print(f"[+] Log report saved to '{output_path}'")


def run(log_path=None):
    """Interactive log analyzer menu."""
    if not log_path:
        log_path = input("Enter path to log file (default: data/sample_logs.json): ").strip()
        if not log_path:
            log_path = "data/sample_logs.json"

    logs = load_logs(log_path)
    if not logs:
        return

    while True:
        print("\n--- Log Analyzer ---")
        print("1. Show all events")
        print("2. Filter by username")
        print("3. Filter by IP address")
        print("4. Filter by status (SUCCESS/FAILED)")
        print("5. Filter by date (YYYY-MM-DD)")
        print("6. Show summary")
        print("7. Save report")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            for e in logs:
                print(e)

        elif choice == "2":
            user = input("Enter username: ").strip()
            filtered = filter_logs(logs, username=user)
            print(f"[+] {len(filtered)} events found for user '{user}':")
            for e in filtered:
                print(e)

        elif choice == "3":
            ip = input("Enter IP address: ").strip()
            filtered = filter_logs(logs, ip=ip)
            print(f"[+] {len(filtered)} events from IP '{ip}':")
            for e in filtered:
                print(e)

        elif choice == "4":
            status = input("Enter status (SUCCESS/FAILED): ").strip()
            filtered = filter_logs(logs, status=status)
            print(f"[+] {len(filtered)} events with status '{status}':")
            for e in filtered:
                print(e)

        elif choice == "5":
            date = input("Enter date (YYYY-MM-DD): ").strip()
            filtered = filter_logs(logs, date=date)
            print(f"[+] {len(filtered)} events on '{date}':")
            for e in filtered:
                print(e)

        elif choice == "6":
            summarize_logs(logs)

        elif choice == "7":
            summary = summarize_logs(logs)
            save_log_report(logs, summary)

        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
