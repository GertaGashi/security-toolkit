"""
Module 2 - File Integrity Checker
Creates SHA-256 hashes for files in a folder (baseline),
then compares later to detect changes.
"""

import os
import hashlib
import json
from datetime import datetime


def hash_file(filepath):
    """Compute SHA-256 hash of a single file. Returns hex string."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError) as e:
        print(f"[!] Could not read '{filepath}': {e}")
        return None


def build_baseline(folder_path, baseline_path="reports/baseline.json"):
    """
    Hash all files in folder_path and save as a baseline JSON.
    Returns the baseline dict.
    """
    if not os.path.isdir(folder_path):
        print(f"[!] Folder not found: '{folder_path}'")
        return {}

    baseline = {}
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            file_hash = hash_file(full_path)
            if file_hash:
                # Store relative path as key for portability
                relative_path = os.path.relpath(full_path, folder_path)
                baseline[relative_path] = file_hash

    os.makedirs(os.path.dirname(baseline_path), exist_ok=True)
    with open(baseline_path, "w") as f:
        json.dump({"created": datetime.now().isoformat(), "files": baseline}, f, indent=2)

    print(f"[+] Baseline created for {len(baseline)} files -> '{baseline_path}'")
    return baseline


def load_baseline(baseline_path="reports/baseline.json"):
    """Load a previously saved baseline JSON. Returns dict of {path: hash}."""
    if not os.path.exists(baseline_path):
        print(f"[!] No baseline found at '{baseline_path}'. Create one first.")
        return {}
    with open(baseline_path, "r") as f:
        data = json.load(f)
    return data.get("files", {})


def check_integrity(folder_path, baseline_path="reports/baseline.json",
                    report_path="reports/integrity_report.txt"):
    """
    Compare folder's current state to the saved baseline.
    Reports: changed files, new files, deleted files.
    """
    baseline = load_baseline(baseline_path)
    if not baseline:
        return

    if not os.path.isdir(folder_path):
        print(f"[!] Folder not found: '{folder_path}'")
        return

    # Build current hashes
    current = {}
    for root, dirs, files in os.walk(folder_path):
        for filename in files:
            full_path = os.path.join(root, filename)
            file_hash = hash_file(full_path)
            if file_hash:
                relative_path = os.path.relpath(full_path, folder_path)
                current[relative_path] = file_hash

    changed = []
    new_files = []
    deleted = []

    # Check for changed and deleted files
    for rel_path, old_hash in baseline.items():
        if rel_path not in current:
            deleted.append(rel_path)
        elif current[rel_path] != old_hash:
            changed.append(rel_path)

    # Check for new files
    for rel_path in current:
        if rel_path not in baseline:
            new_files.append(rel_path)

    # Print results
    print("\n=== File Integrity Check ===")
    print(f"  Baseline files : {len(baseline)}")
    print(f"  Current files  : {len(current)}")
    print(f"  Changed        : {len(changed)}")
    print(f"  New files      : {len(new_files)}")
    print(f"  Deleted        : {len(deleted)}")

    if changed:
        print("\n[!] CHANGED FILES:")
        for f in changed:
            print(f"    - {f}")
    if new_files:
        print("\n[+] NEW FILES (not in baseline):")
        for f in new_files:
            print(f"    - {f}")
    if deleted:
        print("\n[-] DELETED FILES (missing from folder):")
        for f in deleted:
            print(f"    - {f}")

    if not changed and not new_files and not deleted:
        print("\n[OK] All files match the baseline. No changes detected.")

    # Save report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as out:
        out.write("=" * 50 + "\n")
        out.write("FILE INTEGRITY REPORT\n")
        out.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Folder    : {folder_path}\n")
        out.write(f"Baseline  : {baseline_path}\n")
        out.write("=" * 50 + "\n\n")
        out.write(f"Baseline files : {len(baseline)}\n")
        out.write(f"Current files  : {len(current)}\n")
        out.write(f"Changed        : {len(changed)}\n")
        out.write(f"New files      : {len(new_files)}\n")
        out.write(f"Deleted        : {len(deleted)}\n\n")

        out.write("--- CHANGED ---\n")
        out.write("\n".join(changed) if changed else "None\n")
        out.write("\n\n--- NEW ---\n")
        out.write("\n".join(new_files) if new_files else "None\n")
        out.write("\n\n--- DELETED ---\n")
        out.write("\n".join(deleted) if deleted else "None\n")

    print(f"[+] Integrity report saved to '{report_path}'")
    return {"changed": changed, "new": new_files, "deleted": deleted}


def run():
    """Interactive file integrity menu."""
    while True:
        print("\n--- File Integrity Checker ---")
        print("1. Create baseline for a folder")
        print("2. Check integrity against baseline")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            folder = input("Enter folder path (default: data/important_files): ").strip()
            if not folder:
                folder = "data/important_files"
            build_baseline(folder)

        elif choice == "2":
            folder = input("Enter folder path (default: data/important_files): ").strip()
            if not folder:
                folder = "data/important_files"
            check_integrity(folder)

        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
