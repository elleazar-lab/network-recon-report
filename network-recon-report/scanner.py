#!/usr/bin/env python3
"""
Pure-Python port scanner and recon tool.
Uses socket module only — no external binaries required.
Scans localhost by default. Only scan systems you own.
"""

import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports to check + risk metadata
PORT_RULES = {
    21:   ("FTP",       "Unencrypted file transfer",              "Disable or replace with SFTP"),
    22:   ("SSH",       "Remote admin exposed",                   "Restrict source IPs, use key auth"),
    23:   ("Telnet",    "Unencrypted remote admin",               "Disable; use SSH"),
    25:   ("SMTP",      "Mail server",                            "Restrict relay, require auth"),
    53:   ("DNS",       "DNS resolver",                           "Restrict recursion to trusted clients"),
    80:   ("HTTP",      "Unencrypted web",                        "Redirect to HTTPS"),
    110:  ("POP3",      "Unencrypted mail retrieval",             "Use POP3S"),
    143:  ("IMAP",      "Unencrypted mail retrieval",             "Use IMAPS"),
    443:  ("HTTPS",     "Encrypted web",                          "Verify TLS config and cert"),
    445:  ("SMB",       "Windows file sharing",                   "Patch MS17-010, block at perimeter"),
    3306: ("MySQL",     "Database exposed",                       "Bind to localhost only"),
    3389: ("RDP",       "Remote desktop",                         "Restrict IPs, enable NLA, use VPN"),
    5432: ("PostgreSQL","Database exposed",                       "Bind to localhost only"),
    5900: ("VNC",       "Remote desktop, often weak auth",        "Restrict IPs, strong auth"),
    6379: ("Redis",     "Cache DB, often no auth",                "Bind to localhost, require auth"),
    8080: ("HTTP-alt",  "Dev/proxy web server",                   "Check if intentional, add auth"),
    27017:("MongoDB",   "Database, often no auth by default",     "Bind to localhost, enable auth"),
}


def grab_banner(sock: socket.socket) -> str:
    """Try to read a short banner from an open socket (non-blocking-ish)."""
    try:
        sock.settimeout(1.0)
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()[:120]
    except Exception:
        return ""


def check_port(host: str, port: int, timeout: float = 0.5) -> dict | None:
    """Return port info dict if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                banner = grab_banner(s)
                rule = PORT_RULES.get(port)
                return {
                    "port": port,
                    "state": "open",
                    "service": rule[0] if rule else "unknown",
                    "banner": banner,
                    "risk_label": rule[0] if rule else None,
                    "risk_reason": rule[1] if rule else None,
                    "recommendation": rule[2] if rule else None,
                }
    except Exception:
        pass
    return None


def scan_host(host: str, ports: list[int]) -> dict:
    """Scan a list of ports concurrently."""
    print(f"[*] Scanning {host} — {len(ports)} ports...")
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = {pool.submit(check_port, host, p): p for p in ports}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                open_ports.append(result)
                print(f"    [+] {result['port']:>5}/tcp open  {result['service']}")

    open_ports.sort(key=lambda x: x["port"])
    return {"host": host, "ports": open_ports}


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"

    # Scan common ports + a few high ones commonly used by dev servers
    ports = sorted(set(PORT_RULES.keys()) | {3000, 5000, 8000, 8888, 9000})

    result = scan_host(host, ports)

    with open("results.json", "w") as f:
        json.dump({"target": host, "hosts": [result]}, f, indent=2)

    print(f"\n[+] {len(result['ports'])} open port(s) found")
    print("[+] Results written to results.json")


if __name__ == "__main__":
    main()
    