#!/usr/bin/env python3
"""
Network Connection Auditor
============================

A live snapshot tool that lists active outbound/inbound network connections
on the host, cross-references each one against the owning process, and
flags patterns that are commonly associated with malware beaconing,
reverse shells, or generally sloppy exposure.

How it works
------------
1. `psutil.net_connections()` gives us every active socket: local/remote
   address, port, state, and owning PID.
2. For each connection we resolve the owning process (name + executable
   path) via `psutil.Process(pid)`.
3. Each connection is scored against a few heuristics:
     - LISTENING on a well-known "risky" port (Telnet 23, FTP 21, SMB 445,
       RDP 3389, etc.) - often unnecessary exposure on a workstation/server.
     - Process executable running from a suspicious path (/tmp, /dev/shm,
       hidden dotfile directories) - a classic dropper/persistence pattern.
     - Many established connections to the same remote IP from one process -
       can indicate beaconing behaviour (repeated check-ins to a C2 host).
4. Everything is printed in a colour-coded table via `rich`; flagged rows
   are highlighted so they jump out during a manual review.

This tool only *reads* system state - it does not scan other hosts, open
ports, or send any traffic. It is meant for auditing the machine it runs on.

Usage
-----
    python3 network_connection_auditor.py
    python3 network_connection_auditor.py --all     # include local-only sockets too
"""

import argparse
import socket
from collections import Counter

import psutil
from rich.console import Console
from rich.table import Table

RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 445: "SMB",
    3389: "RDP", 5900: "VNC", 6379: "Redis (unauth default)",
    9200: "Elasticsearch (unauth default)",
}

SUSPICIOUS_PATH_FRAGMENTS = ("/tmp/", "/dev/shm/", "/var/tmp/")

BEACON_THRESHOLD = 4  # established connections to the same remote IP from one process


def resolve_process(pid):
    if pid is None:
        return "?", "?"
    try:
        proc = psutil.Process(pid)
        return proc.name(), (proc.exe() or "?")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "?", "?"


def flag_connection(conn, proc_name, proc_path, remote_ip_counts):
    reasons = []

    if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port in RISKY_PORTS:
        reasons.append(f"listening on {RISKY_PORTS[conn.laddr.port]} port {conn.laddr.port}")

    if proc_path and proc_path != "?" and any(frag in proc_path for frag in SUSPICIOUS_PATH_FRAGMENTS):
        reasons.append(f"process running from suspicious path ({proc_path})")

    if conn.raddr and remote_ip_counts.get(conn.raddr.ip, 0) >= BEACON_THRESHOLD:
        reasons.append(f"repeated connections to {conn.raddr.ip} (possible beaconing)")

    return reasons


def format_addr(addr):
    if not addr:
        return "-"
    return f"{addr.ip}:{addr.port}"


def main():
    parser = argparse.ArgumentParser(description="Audit active network connections for risky patterns")
    parser.add_argument("--all", action="store_true", help="Include connections with no remote peer")
    args = parser.parse_args()

    console = Console()
    connections = psutil.net_connections(kind="inet")

    # First pass: count established connections per remote IP per process,
    # to feed the beaconing heuristic.
    remote_ip_counts = Counter()
    for c in connections:
        if c.status == psutil.CONN_ESTABLISHED and c.raddr:
            remote_ip_counts[c.raddr.ip] += 1

    table = Table(title="Active Network Connections", show_lines=False)
    table.add_column("Proto")
    table.add_column("Local")
    table.add_column("Remote")
    table.add_column("Status")
    table.add_column("Process")
    table.add_column("Flags", style="bold")

    flagged_count = 0
    shown_count = 0

    for c in connections:
        if not args.all and not c.raddr and c.status != psutil.CONN_LISTEN:
            continue  # skip uninteresting local-only sockets unless --all

        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        proc_name, proc_path = resolve_process(c.pid)
        reasons = flag_connection(c, proc_name, proc_path, remote_ip_counts)

        row_style = "red" if reasons else None
        flag_text = "; ".join(reasons) if reasons else ""
        if reasons:
            flagged_count += 1
        shown_count += 1

        table.add_row(
            proto,
            format_addr(c.laddr),
            format_addr(c.raddr),
            c.status,
            proc_name,
            flag_text,
            style=row_style,
        )

    console.print(table)
    console.print(f"\n{shown_count} connections shown, [bold red]{flagged_count} flagged[/bold red] for review.")


if __name__ == "__main__":
    main()
