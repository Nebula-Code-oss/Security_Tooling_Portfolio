#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
============================

A lightweight host-based integrity monitor, similar in spirit to tools like
Tripwire or AIDE, scaled down to something you can read end-to-end in five
minutes.

How it works
------------
1. `init`  - walks a target directory, computes a SHA-256 hash of every file,
              and stores that as a signed "baseline" (a JSON snapshot).
2. `scan`  - walks the same directory again, recomputes the hashes, and
              diffs the result against the baseline to report:
                - NEW      files that weren't there before
                - MODIFIED files whose hash changed (tampering, corruption,
                             unexpected edits)
                - DELETED  files that vanished
                - OK       everything else (only shown with --verbose)

Why this matters for security work
-----------------------------------
This is the same core idea behind Host-based Intrusion Detection Systems
(HIDS): if you know the "known good" state of critical files (configs,
binaries, web roots), you can detect unauthorized changes fast - which is
often how persistence and tampering get caught in a real incident.

Usage
-----
    python3 file_integrity_monitor.py init  ./target_dir
    python3 file_integrity_monitor.py scan  ./target_dir
    python3 file_integrity_monitor.py scan  ./target_dir --verbose
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

BASELINE_FILENAME = ".fim_baseline.json"
HASH_CHUNK_SIZE = 65536  # read files in 64KB chunks to keep memory usage flat


def hash_file(path: str) -> str:
    """Compute the SHA-256 hex digest of a file without loading it fully into memory."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(HASH_CHUNK_SIZE):
            sha256.update(chunk)
    return sha256.hexdigest()


def walk_files(root: str):
    """Yield every regular file under root, using paths relative to root."""
    for dirpath, _dirnames, filenames in os.walk(root):
        # never fingerprint our own baseline file
        filenames = [f for f in filenames if f != BASELINE_FILENAME]
        for name in filenames:
            full_path = os.path.join(dirpath, name)
            rel_path = os.path.relpath(full_path, root)
            yield rel_path, full_path


def build_snapshot(root: str) -> dict:
    snapshot = {}
    for rel_path, full_path in walk_files(root):
        try:
            snapshot[rel_path] = hash_file(full_path)
        except (PermissionError, OSError) as e:
            print(f"  [!] Could not read {rel_path}: {e}", file=sys.stderr)
    return snapshot


def cmd_init(args):
    root = args.path
    if not os.path.isdir(root):
        sys.exit(f"Error: {root} is not a directory")

    snapshot = build_snapshot(root)
    baseline = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "root": os.path.abspath(root),
        "file_count": len(snapshot),
        "hashes": snapshot,
    }
    baseline_path = os.path.join(root, BASELINE_FILENAME)
    with open(baseline_path, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"Baseline created: {baseline_path}")
    print(f"Tracked {len(snapshot)} files under {os.path.abspath(root)}")


def cmd_scan(args):
    root = args.path
    baseline_path = os.path.join(root, BASELINE_FILENAME)
    if not os.path.exists(baseline_path):
        sys.exit(f"Error: no baseline found. Run 'init' on {root} first.")

    with open(baseline_path) as f:
        baseline = json.load(f)

    old_hashes = baseline["hashes"]
    new_hashes = build_snapshot(root)

    old_files = set(old_hashes)
    new_files = set(new_hashes)

    added = sorted(new_files - old_files)
    removed = sorted(old_files - new_files)
    common = old_files & new_files
    modified = sorted(p for p in common if old_hashes[p] != new_hashes[p])
    unchanged = sorted(p for p in common if old_hashes[p] == new_hashes[p])

    print(f"Scan against baseline from {baseline['created_at']}")
    print(f"Root: {baseline['root']}\n")

    for path in added:
        print(f"  [NEW]      {path}")
    for path in modified:
        print(f"  [MODIFIED] {path}")
    for path in removed:
        print(f"  [DELETED]  {path}")
    if args.verbose:
        for path in unchanged:
            print(f"  [OK]       {path}")

    total_flags = len(added) + len(modified) + len(removed)
    print(f"\nSummary: {total_flags} change(s) detected "
          f"({len(added)} new, {len(modified)} modified, {len(removed)} deleted), "
          f"{len(unchanged)} unchanged.")

    sys.exit(1 if total_flags else 0)


def main():
    parser = argparse.ArgumentParser(description="Simple SHA-256 based file integrity monitor")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create a baseline snapshot of a directory")
    p_init.add_argument("path", help="Directory to fingerprint")
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="Compare current state against the baseline")
    p_scan.add_argument("path", help="Directory to check")
    p_scan.add_argument("--verbose", action="store_true", help="Also list unchanged files")
    p_scan.set_defaults(func=cmd_scan)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
