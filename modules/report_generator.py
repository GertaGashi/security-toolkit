"""
Module 5 - Report Generator
Combines results from all modules into one final report.
"""

import os
import json
from datetime import datetime


def read_file_safe(path):
    """Read a text file if it exists, return its contents or a placeholder."""
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return f"  [No data found at '{path}']\n"


def load_json_safe(path):
    """Load a JSON file if it exists, return dict/list or empty dict."""
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}


def generate_final_report(output_path="reports/final_report.txt"):
    """
    Combine results from all module reports into one final_report.txt.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(output_path, "w") as out:
        out.write("=" * 60 + "\n")
        out.write("  SECURITY TOOLKIT - FINAL REPORT\n")
        out.write(f"  Generated: {now}\n")
        out.write("=" * 60 + "\n\n")

        # --- Log Analysis ---
        out.write("=" * 60 + "\n")
        out.write("SECTION 1: LOG ANALYSIS\n")
        out.write("=" * 60 + "\n")
        out.write(read_file_safe("reports/log_report.txt"))
        out.write("\n")

        # --- File Integrity ---
        out.write("=" * 60 + "\n")
        out.write("SECTION 2: FILE INTEGRITY\n")
        out.write("=" * 60 + "\n")
        out.write(read_file_safe("reports/integrity_report.txt"))
        out.write("\n")

        # --- Secrets Scan ---
        out.write("=" * 60 + "\n")
        out.write("SECTION 3: SECRETS SCAN\n")
        out.write("=" * 60 + "\n")
        out.write(read_file_safe("reports/secrets_report.txt"))
        out.write("\n")

        # --- Port Check ---
        out.write("=" * 60 + "\n")
        out.write("SECTION 4: LOCALHOST PORT CHECK\n")
        out.write("=" * 60 + "\n")
        out.write(read_file_safe("reports/port_report.txt"))
        out.write("\n")

        # --- Monitoring Alerts (Variant C) ---
        out.write("=" * 60 + "\n")
        out.write("SECTION 5: MONITORING & ALERTS (VARIANT C)\n")
        out.write("=" * 60 + "\n")
        out.write(read_file_safe("reports/monitoring_report.txt"))
        out.write("\n")

        alerts_data = load_json_safe("reports/alerts.json")
        if alerts_data:
            alerts = alerts_data.get("alerts", [])
            out.write(f"Total alerts in alerts.json: {len(alerts)}\n")
            for a in alerts:
                out.write(f"  [{a.get('severity','?')}] {a.get('type','?')}: {a.get('description','')}\n")
        else:
            out.write("  [No alerts.json found]\n")

        out.write("\n" + "=" * 60 + "\n")
        out.write("END OF REPORT\n")
        out.write("=" * 60 + "\n")

    print(f"[+] Final report saved to '{output_path}'")


def run():
    """Interactive report generator menu."""
    while True:
        print("\n--- Report Generator ---")
        print("1. Generate final combined report")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            generate_final_report()
        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
