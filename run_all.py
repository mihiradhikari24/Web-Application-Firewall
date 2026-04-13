#!/usr/bin/env python3
"""
run_all.py
----------
Convenience script that starts both the backend and the WAF proxy
in separate processes. Press Ctrl+C to stop both.

Usage:
    python run_all.py
"""

import subprocess
import sys
import os
import time
import signal

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.join(ROOT, "backend.py")
WAF = os.path.join(ROOT, "waf", "proxy.py")

GREEN = "\033[92m"
RESET = "\033[0m"

procs = []


def shutdown(sig, frame):
    print("\n\nStopping all processes...")
    for p in procs:
        p.terminate()
    sys.exit(0)


signal.signal(signal.SIGINT, shutdown)
signal.signal(signal.SIGTERM, shutdown)


def start(label, script):
    """Start a Python script as a subprocess."""
    proc = subprocess.Popen(
        [sys.executable, script],
        cwd=os.path.dirname(script),
    )
    procs.append(proc)
    print(f"{GREEN}[STARTED]{RESET} {label} (PID {proc.pid})")
    return proc


if __name__ == "__main__":
    print("=" * 50)
    print("  WAF Demo — Starting all services")
    print("=" * 50)

    start("Backend App", BACKEND)
    time.sleep(0.5)
    start("WAF Proxy", WAF)

    print()
    print("  Backend : http://127.0.0.1:8081  (direct, bypass WAF)")
    print("  WAF Proxy : http://127.0.0.1:8080  (protected by WAF)")
    print()
    print("  Press Ctrl+C to stop both services")
    print("=" * 50)

    # Wait forever (until Ctrl+C)
    for p in procs:
        p.wait()
