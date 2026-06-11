"""
Module 4 - Safe Localhost Port Checker
Checks only localhost (127.0.0.1) ports using socket connections.
"""

import socket
from datetime import datetime
import os

# Common ports and their likely services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt / Dev Server",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

HOST = "127.0.0.1"
TIMEOUT = 0.5  # seconds - keeps the check fast


def check_port(port, host=HOST, timeout=TIMEOUT):
    """
    Try to connect to host:port using a TCP socket.
    Returns True if OPEN, False if CLOSED.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0  # 0 means connection succeeded (port open)
    except socket.error:
        return False
    finally:
        sock.close()


def check_ports(port_list, report_path="reports/port_report.txt"):
    """
    Check a list of ports and print/save results.
    Returns a list of result dicts.
    """
    results = []
    print(f"\n=== Port Check on {HOST} ===")
    print(f"  Checking {len(port_list)} ports...\n")

    for port in port_list:
        is_open = check_port(port)
        service = COMMON_PORTS.get(port, "Unknown")
        status = "OPEN" if is_open else "CLOSED"
        results.append({"port": port, "status": status, "service": service})

        marker = "[OPEN] " if is_open else "[----] "
        print(f"  {marker} Port {port:5d}  |  {status:6}  |  {service}")

    open_ports = [r for r in results if r["status"] == "OPEN"]
    print(f"\n  Summary: {len(open_ports)}/{len(results)} ports OPEN")

    # Save report
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("PORT CHECK REPORT\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Host      : {HOST}\n")
        f.write("=" * 50 + "\n\n")
        for r in results:
            f.write(f"Port {r['port']:5d}  |  {r['status']:6}  |  {r['service']}\n")
        f.write(f"\nTotal OPEN: {len(open_ports)}/{len(results)}\n")

    print(f"[+] Port report saved to '{report_path}'")
    return results


def run():
    """Interactive port checker menu."""
    while True:
        print("\n--- Localhost Port Checker ---")
        print("1. Check predefined common ports")
        print("2. Enter ports manually")
        print("0. Back to main menu")

        choice = input("Choice: ").strip()

        if choice == "1":
            check_ports(list(COMMON_PORTS.keys()))

        elif choice == "2":
            raw = input("Enter ports separated by commas (e.g. 80,443,8080): ").strip()
            try:
                ports = [int(p.strip()) for p in raw.split(",") if p.strip()]
                if ports:
                    check_ports(ports)
                else:
                    print("[!] No valid ports entered.")
            except ValueError:
                print("[!] Invalid input. Enter numbers only.")

        elif choice == "0":
            break
        else:
            print("[!] Invalid choice.")
