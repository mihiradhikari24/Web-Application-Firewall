"""
waf/logger.py
-------------
Attack logging module.

Writes blocked requests to a JSON-lines file so each line
is a valid JSON object. This format is easy to parse later
(grep, jq, pandas, dashboards, etc.).

Also prints a colored summary to stdout for quick visibility.
"""

import json
import os
from datetime import datetime, timezone


# Where to write the log file
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "attacks.jsonl")

# ANSI color codes for terminal output
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"


def ensure_log_dir():
    """Create the logs directory if it doesn't exist."""
    os.makedirs(LOG_DIR, exist_ok=True)


def log_attack(client_ip: str, method: str, path: str, findings: list, raw_payload: str):
    """
    Record a detected attack to the log file and print a summary.

    Args:
        client_ip:   IP address of the attacker
        method:      HTTP method (GET, POST, ...)
        path:        Request path (e.g. /search)
        findings:    List of finding dicts from rules.inspect_inputs()
        raw_payload: The original (un-normalized) user input string
    """
    ensure_log_dir()

    timestamp = datetime.now(timezone.utc).isoformat()

    # Build a log entry for each finding
    for finding in findings:
        entry = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "attack_type": finding["attack_type"],
            "field": finding["field"],
            "matched_pattern": finding["pattern"],
            "raw_payload": raw_payload[:500],  # cap payload length in logs
        }

        # Append to the JSONL log file
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Print to terminal with color
        print(
            f"{RED}[WAF BLOCKED]{RESET} "
            f"{timestamp} | "
            f"IP={client_ip} | "
            f"{method} {path} | "
            f"Attack={finding['attack_type']} | "
            f"Pattern={YELLOW}{finding['pattern']!r}{RESET} | "
            f"Field={finding['field']}"
        )


def log_pass(client_ip: str, method: str, path: str):
    """Optional: log allowed requests (verbose mode only)."""
    # Uncomment if you want to trace all forwarded requests
    # print(f"[WAF PASS] {client_ip} {method} {path}")
    pass
