# Security Tooling Portfolio

Three small, self-contained Python tools built around a common theme: turning
raw system/log data into clear, actionable security signal. Each one is
deliberately kept small enough to read end-to-end, with the detection logic
documented inline rather than hidden behind abstractions.

No external services, no API keys, no scanning of systems you don't own -
everything here reads local files or local system state.

| Tool | Category | What it answers |
|---|---|---|
| [`file_integrity_monitor.py`](file_integrity_monitor.py) | Host-based detection | "Did anything under this directory change since I last checked?" |
| [`log_bruteforce_detector.py`](log_bruteforce_detector.py) | Log analysis / SIEM logic | "Is someone hammering SSH logins, and did they get in?" |
| [`network_connection_auditor.py`](network_connection_auditor.py) | Network defense | "What is this machine talking to right now, and does any of it look wrong?" |

## 1. File Integrity Monitor

Computes a SHA-256 baseline of every file in a directory, then on a later
scan reports anything **new**, **modified**, or **deleted**. The same core
idea behind Tripwire/AIDE and behind the file-integrity checks most EDR
products run continuously.

```bash
python3 file_integrity_monitor.py init  ./target_dir
python3 file_integrity_monitor.py scan  ./target_dir
```

## 2. Brute-Force Login Detector

Parses OpenSSH-style `auth.log` files, tracks failed login attempts per
source IP inside a sliding time window, and flags any IP that crosses a
threshold - plus a separate, higher-severity flag if a successful login
follows shortly after a flagged burst of failures (a strong signal the
attack actually worked).

```bash
python3 log_bruteforce_detector.py sample_auth.log
python3 log_bruteforce_detector.py sample_auth.log --threshold 3 --window 2
```

A synthetic [`sample_auth.log`](sample_auth.log) is included so you can run
it immediately without needing a real server.

## 3. Network Connection Auditor

Lists every active network connection on the host (via `psutil`), resolves
the owning process, and flags connections that match common risk patterns:
services listening on legacy/risky ports (Telnet, FTP, RDP, unauthenticated
Redis/Elasticsearch), processes running from suspicious paths like `/tmp`,
and repeated connections to the same remote IP from one process (a possible
beaconing pattern). Output is a colour-coded table via `rich`.

```bash
python3 network_connection_auditor.py
```

## Requirements

```bash
pip install psutil rich
```

Python 3.9+ (uses only the standard library plus `psutil` and `rich`).

## Why these three

Each tool maps to a different layer of the same defensive workflow: know
what your files should look like (integrity monitoring), know what your
logs are telling you (detection), and know what your host is actually doing
on the network right now (live auditing). None of them require a lab or
special access - they run against any Linux/macOS box, which made them a
good way to practice the underlying detection logic without needing
production infrastructure.
