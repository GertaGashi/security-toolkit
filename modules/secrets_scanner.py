"""
Module 3 - Secrets Scanner
Scans files in a folder for exposed fake/test credentials.
"""

import os
import re
from datetime import datetime

# Patterns to search for - these match common secret variable names
SECRET_PATTERNS = [
    (r'password\s*=\s*\S+', "PASSWORD"),
    (r'api_key\s*=\s*\S+', "API_KEY"),
    (r'token\s*=\s*\S+', "TOKEN"),
    (r'secret\s*=\s*\S+', "SECRET"),
    (r'private_key\s*=\s*\S+', "PRIVATE_KEY"),
    (r'connection_string\s*=\s*\S+', "CONNECTION_STRING"),
    (r'auth_token\s*=\s*\S+', "AUTH_TOKEN"),
    (r'access_key\s*=\s*\S+', "ACCESS_KEY"),
]

# File extensions to scan (skip binaries)
SCANNABLE_EXTENSIONS = {".txt", ".env", ".json", ".py", ".js", ".yaml",
                        ".yml", ".ini", ".cfg", ".conf", ".xml", ".properties"}


def mask_secret(value):
    """Mask most of the secret value, showing only first 4 chars."""
    value = value.strip()
    if len(value) <= 4:
        return "****"
    return value[:4] + "*" * (len(value) - 4)


def scan_file(filepath):
    """
    Scan a single file for secret patterns.
    Returns a list of findings: {line_number, category, raw_line, masked_line}
    """
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for pattern, category in SECRET_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Mask the value after the = sign
                        masked = re.sub(
                            r'(=\s*)(\S+)',
                            lambda m: m.group(1) + mask_secret(m.group(2)),
                            line.strip(),
                            count=1
                        )
                        findings.append({
                            "line_number": line_number,
                            "category": category,
                            "raw_line": line.strip(),
                            "masked_line": masked,
                        })
                        break  # One match per line is enough
    except Exception as e:
        print(f"[!] Could not scan '{filepath}': {e}")
    return findings


def scan_folder(folder_path, report_path="reports/secrets_report.txt"):
    """
    Scan all files in a folder for secrets.
    Prints findings and saves a report.
    Returns a dict of {filepath: [findings]}
    """
    if not os.path.isdir(folder_path):
        print(f"[!] Folder not found: '{folder_path}'")
        return {}

    all_findings = {}
    files_scanned = 0

    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in SCANNABLE_EXTENSIONS:
                continue
            full_path = os.path.join(root, filename)
            findings = scan_file(full_path)
            files_scanned += 1
            if findings:
                all_findings[full_path] = findings

    # Print results
    print(f"\n=== Secrets Scan Results ===")
    print(f"  Files scanned : {files_scanned}")
    print(f"  Files with findings : {len(all_findings)}")

    total = 0
    for filepath, findings in all_findings.items():
        print(f"\n  [!] {filepath}")
        for f in findings:
            print(f"      Line {f['line_number']} [{f['category']}]: {f['masked_line']}")
            total += 1

    if not all_findings:
        print("  [OK] No secrets found.")

    # Save report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as out:
        out.write("=" * 50 + "\n")
        out.write("SECRETS SCAN REPORT\n")
        out.write(f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Folder     : {folder_path}\n")
        out.write(f"Files scanned : {files_scanned}\n")
        out.write(f"Total findings: {total}\n")
        out.write("=" * 50 + "\n\n")

        for filepath, findings in all_findings.items():
            out.write(f"FILE: {filepath}\n")
            for f in findings:
                out.write(f"  Line {f['line_number']} [{f['category']}]: {f['masked_line']}\n")
            out.write("\n")

        if not all_findings:
            out.write("No secrets found.\n")

    print(f"[+] Secrets report saved to '{report_path}'")
    return all_findings


def run():
    """Interactive secrets scanner menu."""
    while True:
        print("\n--- Secrets Scanner ---")
        print("1. Scan a folder for secrets")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            folder = input("Enter folder path (default: data/important_files): ").strip()
            if not folder:
                folder = "data/important_files"
            scan_folder(folder)

        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
