#!/usr/bin/env python3
"""
Brute-Force Login Detector
===========================

Parses SSH-style authentication logs and flags source IPs that are hammering
a host with failed login attempts - the classic signature of a brute-force
or credential-stuffing attack.

How it works
------------
1. Each log line is matched against two regex patterns that cover the
   standard OpenSSH auth.log format:
     - "Failed password for [invalid user] <user> from <ip> port <port> ..."
     - "Accepted password for <user> from <ip> port <port> ..."
2. Every failed attempt is recorded with its timestamp and source IP.
3. A sliding time window (default: 5 minutes) is used to count failures
   per IP. If an IP crosses the configured threshold (default: 5 failures)
   within that window, it's flagged as a suspected brute-force source.
4. A successful login from an IP that was *just* flagged is highlighted
   separately - that pattern (many failures immediately followed by a
   success) is a strong indicator the attack actually succeeded.

Why this matters for security work
-----------------------------------
This is a simplified version of what a SIEM correlation rule does under
the hood: turning raw log noise into a small number of actionable alerts.
It's also exactly the kind of detection logic that shows up in real
incident response, where "how many failed logins, how fast, from where"
is often the first question asked.

Usage
-----
    python3 log_bruteforce_detector.py sample_auth.log
    python3 log_bruteforce_detector.py sample_auth.log --threshold 3 --window 2
"""

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime

# Matches lines like:
# Jul 21 09:14:02 server sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 51422 ssh2
FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd.*Failed password for "
    r"(invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Matches lines like:
# Jul 21 09:14:10 server sshd[1234]: Accepted password for deploy from 203.0.113.7 port 51430 ssh2
ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*sshd.*Accepted password for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+)"
)

# Syslog timestamps have no year; assume the current year for elapsed-time math.
CURRENT_YEAR = datetime.now().year


def parse_timestamp(ts: str) -> datetime:
    return datetime.strptime(f"{CURRENT_YEAR} {ts}", "%Y %b %d %H:%M:%S")


def parse_log(path: str):
    """Yield (event_type, datetime, ip, user) tuples for every recognised line."""
    with open(path) as f:
        for line in f:
            m = FAILED_RE.match(line)
            if m:
                yield "failed", parse_timestamp(m.group("ts")), m.group("ip"), m.group("user")
                continue
            m = ACCEPTED_RE.match(line)
            if m:
                yield "accepted", parse_timestamp(m.group("ts")), m.group("ip"), m.group("user")


def detect_bruteforce(events, threshold: int, window_minutes: int):
    """
    Sliding-window detection: for each IP, keep the timestamps of its recent
    failures and check whether `threshold` of them fall inside `window_minutes`.
    Returns a dict of ip -> list of (window_start, window_end, count) alerts,
    plus a set of IPs that had a success right after being flagged.
    """
    window = window_minutes * 60
    failures_by_ip = defaultdict(list)
    alerts = defaultdict(list)
    flagged_ips = set()
    compromise_candidates = []

    for event_type, ts, ip, user in events:
        if event_type == "failed":
            failures_by_ip[ip].append(ts)
            # drop timestamps outside the window
            recent = [t for t in failures_by_ip[ip] if (ts - t).total_seconds() <= window]
            failures_by_ip[ip] = recent
            if len(recent) >= threshold:
                alerts[ip].append((recent[0], ts, len(recent)))
                flagged_ips.add(ip)
        elif event_type == "accepted" and ip in flagged_ips:
            compromise_candidates.append((ip, user, ts))

    return alerts, compromise_candidates


def main():
    parser = argparse.ArgumentParser(description="Detect brute-force SSH login attempts in auth logs")
    parser.add_argument("logfile", help="Path to an auth.log-style file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts to trigger an alert (default: 5)")
    parser.add_argument("--window", type=int, default=5, help="Sliding window size in minutes (default: 5)")
    args = parser.parse_args()

    try:
        events = list(parse_log(args.logfile))
    except FileNotFoundError:
        sys.exit(f"Error: {args.logfile} not found")

    if not events:
        print("No recognisable SSH auth lines found in this log.")
        return

    alerts, compromise_candidates = detect_bruteforce(events, args.threshold, args.window)

    if not alerts:
        print(f"No IP exceeded {args.threshold} failed attempts within a {args.window}-minute window.")
        return

    print(f"Brute-force alerts (>= {args.threshold} failures / {args.window} min window):\n")
    # report the worst offenders first
    for ip, ip_alerts in sorted(alerts.items(), key=lambda kv: max(a[2] for a in kv[1]), reverse=True):
        worst = max(ip_alerts, key=lambda a: a[2])
        start, end, count = worst
        print(f"  [ALERT] {ip}: {count} failed attempts between "
              f"{start.strftime('%H:%M:%S')} and {end.strftime('%H:%M:%S')}")

    if compromise_candidates:
        print("\nPossible successful compromise after brute-force activity:")
        for ip, user, ts in compromise_candidates:
            print(f"  [CRITICAL] {ip} logged in as '{user}' at {ts.strftime('%H:%M:%S')} "
                  f"shortly after triggering a brute-force alert")


if __name__ == "__main__":
    main()
