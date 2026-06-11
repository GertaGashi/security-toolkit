"""
Security Toolkit - Main Entry Point
Variant C: Monitoring & Alerting

Run this file to start the toolkit:
    python main.py
"""

import os
import sys

# Make sure Python can find the modules folder
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import log_analyzer
from modules import file_integrity
from modules import secrets_scanner
from modules import port_checker
from modules import monitoring
from modules import report_generator


BANNER = """
╔══════════════════════════════════════════════╗
║         SECURITY TOOLKIT  v1.0               ║
║         Variant C: Monitoring & Alerting     ║
╚══════════════════════════════════════════════╝
"""

MENU = """
  ─── MAIN MENU ───────────────────────────────
  1. Analyze log file
  2. Search and summarize log events
  3. Monitor log file for new events  [Variant C]
  4. Create file hash baseline
  5. Check file integrity
  6. Scan folder for exposed secrets
  7. Check localhost ports
  8. Generate final report
  0. Exit
  ─────────────────────────────────────────────
"""


def main():
    print(BANNER)

    while True:
        print(MENU)
        choice = input("  Enter choice: ").strip()

        if choice == "1":
            log_analyzer.run()

        elif choice == "2":
            # Quick filter + summary shortcut
            log_path = input("  Log file path (default: data/sample_logs.json): ").strip()
            if not log_path:
                log_path = "data/sample_logs.json"
            logs = log_analyzer.load_logs(log_path)
            if logs:
                log_analyzer.summarize_logs(logs)

        elif choice == "3":
            monitoring.run()

        elif choice == "4":
            folder = input("  Folder path (default: data/important_files): ").strip()
            if not folder:
                folder = "data/important_files"
            file_integrity.build_baseline(folder)

        elif choice == "5":
            file_integrity.run()

        elif choice == "6":
            secrets_scanner.run()

        elif choice == "7":
            port_checker.run()

        elif choice == "8":
            report_generator.run()

        elif choice == "0":
            print("\n  Goodbye!\n")
            break

        else:
            print("  [!] Invalid choice. Please enter a number from the menu.")


if __name__ == "__main__":
    main()
