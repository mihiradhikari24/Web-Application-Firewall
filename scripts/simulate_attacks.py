#!/usr/bin/env python3
"""
scripts/simulate_attacks.py
----------------------------
Simulates a variety of attacks against the WAF to demonstrate
detection and blocking.

Run with: python scripts/simulate_attacks.py

Make sure both the backend (port 8081) and WAF (port 8080) are running first.
"""

import urllib.request
import urllib.parse
import urllib.error
import sys

WAF_URL = "http://127.0.0.1:8080"

# ANSI colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = {"blocked": 0, "passed": 0, "error": 0}


def send_get(label, path):
    """Send a GET request and print the result."""

    if "?" in path:
        base, query = path.split("?", 1)
        encoded_query = urllib.parse.quote_plus(query, safe="=&")
        path = f"{base}?{encoded_query}"

    url = WAF_URL + path
    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req, timeout=5)
        code = response.getcode()
        print(f"  {YELLOW}PASSED{RESET} [{code}] {label}")
        print(f"          URL: {url}")
        results["passed"] += 1
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  {GREEN}BLOCKED{RESET} [403] {label}")
            print(f"          URL: {url}")
            results["blocked"] += 1
        else:
            print(f"  {RED}ERROR{RESET} [{e.code}] {label}")
            results["error"] += 1
    except Exception as e:
        print(f"  {RED}ERROR{RESET} {label}: {e}")
        results["error"] += 1


def send_post(label, path, data: dict):
    """Send a POST request with form data."""
    url = WAF_URL + path
    payload = urllib.parse.urlencode(data).encode()
    try:
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        response = urllib.request.urlopen(req, timeout=5)
        code = response.getcode()
        print(f"  {YELLOW}PASSED{RESET} [{code}] {label}")
        print(f"          POST {url} | data={data}")
        results["passed"] += 1
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  {GREEN}BLOCKED{RESET} [403] {label}")
            print(f"          POST {url} | data={data}")
            results["blocked"] += 1
        else:
            print(f"  {RED}ERROR{RESET} [{e.code}] {label}")
            results["error"] += 1
    except Exception as e:
        print(f"  {RED}ERROR{RESET} {label}: {e}")
        results["error"] += 1


def section(title):
    print(f"\n{BOLD}{CYAN}{'─'*55}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*55}{RESET}")


# ─────────────────────────────────────────────────────────────────────────────
# Attack test cases
# ─────────────────────────────────────────────────────────────────────────────

def test_sql_injection():
    section("SQL INJECTION ATTACKS")

    send_get("Classic OR bypass",
             "/search?q=' OR '1'='1")

    send_get("OR 1=1 bypass",
             "/search?q=alice' OR 1=1--")

    send_get("UNION SELECT extraction",
             "/search?q=' UNION SELECT id,username FROM users--")

    send_post("Login bypass via SQLi",
              "/login",
              {"username": "admin'--", "password": "anything"})

    send_post("OR injection in POST body",
              "/login",
              {"username": "' OR 1=1--", "password": "x"})

    send_get("DROP TABLE attack",
             "/search?q='; DROP TABLE users;--")


def test_xss():
    section("CROSS-SITE SCRIPTING (XSS) ATTACKS")

    send_get("Basic script tag",
             "/profile?name=<script>alert(1)</script>")

    send_get("IMG onerror XSS",
             "/profile?name=<img src=x onerror=alert(1)>")

    send_get("JavaScript protocol",
             "/profile?name=<a href=javascript:alert(1)>click</a>")

    send_post("Stored XSS in comment",
              "/comment",
              {"author": "hacker", "body": "<script>document.cookie</script>"})

    send_post("Event handler XSS",
              "/comment",
              {"author": "x", "body": "<svg onload=alert(1)>"})

    send_get("URL-encoded XSS (evasion test)",
             "/profile?name=%3Cscript%3Ealert(1)%3C/script%3E")


def test_path_traversal():
    section("PATH TRAVERSAL ATTACKS")

    send_get("Basic ../etc/passwd",
             "/file?name=../etc/passwd")

    send_get("Deep traversal",
             "/file?name=../../../../etc/shadow")

    send_get("Windows-style traversal",
             r"/file?name=..\windows\system32\config")

    send_get("URL-encoded traversal",
             "/file?name=..%2F..%2Fetc%2Fpasswd")

    send_get("Double-encoded traversal",
             "/file?name=..%252F..%252Fetc%252Fpasswd")


def test_command_injection():
    section("COMMAND INJECTION ATTACKS")

    send_get("Semicolon injection",
             "/search?q=alice; cat /etc/passwd")

    send_get("Pipe injection",
             "/search?q=alice | whoami")

    send_get("Subshell injection",
             "/search?q=alice$(whoami)")


def test_legitimate_requests():
    section("LEGITIMATE REQUESTS (should PASS)")

    send_get("Normal search",
             "/search?q=alice")

    send_get("Normal profile",
             "/profile?name=Alice")

    send_get("View comments",
             "/comments")

    send_post("Normal login attempt",
              "/login",
              {"username": "alice", "password": "pass456"})

    send_post("Normal comment",
              "/comment",
              {"author": "Carol", "body": "omg i made a post!"})


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{BOLD}WAF Attack Simulation{RESET}")
    print(f"Target: {WAF_URL}")
    print("Make sure both the backend (8081) and WAF (8080) are running.\n")

    test_sql_injection()
    test_xss()
    test_path_traversal()
    test_command_injection()
    test_legitimate_requests()

    # Summary
    total = sum(results.values())
    print(f"\n{BOLD}{'═'*55}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{'═'*55}")
    print(f"  Total requests : {total}")
    print(f"  {GREEN}Blocked (403)  : {results['blocked']}{RESET}")
    print(f"  {YELLOW}Passed  (2xx)  : {results['passed']}{RESET}")
    print(f"  {RED}Errors         : {results['error']}{RESET}")
    print(f"\n  Attack logs written to: logs/attacks.jsonl")
    print(f"{'═'*55}\n")


if __name__ == "__main__":
    main()
