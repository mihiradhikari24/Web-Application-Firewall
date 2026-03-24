#!/usr/bin/env python3
"""
scripts/view_logs.py
--------------------
Parse and display the WAF attack log file (logs/attacks.jsonl).

Usage:
    python scripts/view_logs.py              # show all logs
    python scripts/view_logs.py --summary    # show attack summary counts
    python scripts/view_logs.py --type SQLi  # filter by attack type
"""

import json
import os
import sys
from collections import Counter

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "attacks.jsonl")

RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def load_logs():
    if not os.path.exists(LOG_FILE):
        print(f"No log file found at {LOG_FILE}")
        print("Run simulate_attacks.py first to generate some logs.")
        return []
    with open(LOG_FILE) as f:
        entries = []
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def show_all(entries, filter_type=None):
    for entry in entries:
        if filter_type and filter_type.lower() not in entry["attack_type"].lower():
            continue
        print(f"{RED}[BLOCKED]{RESET} {entry['timestamp']}")
        print(f"  IP       : {entry['client_ip']}")
        print(f"  Request  : {entry['method']} {entry['path']}")
        print(f"  Type     : {YELLOW}{entry['attack_type']}{RESET}")
        print(f"  Pattern  : {entry['matched_pattern']!r}")
        print(f"  Field    : {entry['field']}")
        print(f"  Payload  : {entry['raw_payload'][:120]}")
        print()


def show_summary(entries):
    if not entries:
        print("No log entries.")
        return

    attack_counts = Counter(e["attack_type"] for e in entries)
    ip_counts = Counter(e["client_ip"] for e in entries)
    path_counts = Counter(e["path"] for e in entries)
    pattern_counts = Counter(e["matched_pattern"] for e in entries)

    print(f"\n{BOLD}Attack Log Summary{RESET}")
    print(f"Total blocked requests: {len(entries)}\n")

    print(f"{CYAN}By Attack Type:{RESET}")
    for attack, count in attack_counts.most_common():
        bar = "█" * count
        print(f"  {attack:<25} {count:>3}  {bar}")

    print(f"\n{CYAN}By Source IP:{RESET}")
    for ip, count in ip_counts.most_common(10):
        print(f"  {ip:<20} {count:>3} requests")

    print(f"\n{CYAN}Top Targeted Paths:{RESET}")
    for path, count in path_counts.most_common(5):
        print(f"  {path:<25} {count:>3} attacks")

    print(f"\n{CYAN}Most Triggered Patterns:{RESET}")
    for pattern, count in pattern_counts.most_common(5):
        print(f"  {pattern!r:<30} {count:>3} times")
    print()


def main():
    args = sys.argv[1:]
    entries = load_logs()

    if "--summary" in args:
        show_summary(entries)
    else:
        filter_type = None
        if "--type" in args:
            idx = args.index("--type")
            if idx + 1 < len(args):
                filter_type = args[idx + 1]
        show_all(entries, filter_type)
        print(f"Total: {len(entries)} blocked requests")


if __name__ == "__main__":
    main()
