"""
waf/rules.py
------------
Attack detection rules using simple pattern matching.

Each rule has:
- name:     human-readable attack category
- patterns: list of strings to look for in normalized input

The WAF checks all rules against all input values.
If any pattern matches, the request is blocked.

This is the simplest possible rule engine — a flat list of patterns.
The roadmap section describes how to evolve this into a proper rule system.
"""

import re

# ─────────────────────────────────────────────
# Rule definitions
# ─────────────────────────────────────────────

RULES = [
    {
        "name": "SQL Injection",
        "patterns": [
            # ───── Basic boolean injection ─────
            "' or ",
            "' or '",
            "or 1=1",
            "or 1 = 1",

            # ───── Comment-based bypass (CRITICAL FIX) ─────
            "'--",     # admin'--
            "--",      # any SQL comment
            "#",       # MySQL comment

            # ───── UNION extraction ─────
            "union select",
            "union all select",

            # ───── Destructive queries ─────
            "drop table",
            "drop database",
            "delete from",
            "truncate table",

            # ───── Stacked queries ─────
            "; insert",
            "; update",
            "; delete",
            "; drop",

            # ───── Info gathering ─────
            "information_schema",
            "sleep(",
            "benchmark(",
            "waitfor delay",
        ],
    },
    {
        "name": "XSS",
        "patterns": [
            # Script tags
            "<script",
            "</script>",
            # Event handlers
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "onfocus=",
            "onblur=",
            # JavaScript pseudo-protocol
            "javascript:",
            "vbscript:",
            # Dangerous tags
            "<iframe",
            "<object",
            "<embed",
            "<svg",
            "<img",
            # Expression tricks
            "expression(",
            "data:text/html",
        ],
    },
    {
        "name": "Path Traversal",
        "patterns": [
            # Unix-style traversal
            "../",
            "..\\",
            # Encoded variants (pre-normalized so these are decoded already,
            # but keep explicit patterns for clarity)
            "%2e%2e%2f",
            "%2e%2e/",
            # Absolute path attempts
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self",
            "c:\\windows",
            "c:/windows",
            # Null byte injection (terminate strings)
            "%00",
            "\x00",
        ],
    },
    {
        "name": "Command Injection",
        "patterns": [
            # ───── Shell operators (generalized) ─────
            ";",          # command chaining
            "|",          # pipe
            "&&",         # AND chaining
            "||",         # OR chaining

            # ───── Subshell execution (CRITICAL FIX) ─────
            "$(",         # catches $(whoami)
            "`",          # backticks

            # ───── Common commands ─────
            "whoami",
            "id",
            "ls ",
            "cat ",
            "pwd",

            # ───── Shell access ─────
            "/bin/sh",
            "/bin/bash",
            "cmd.exe",
        ],
    },
]


# ─────────────────────────────────────────────
# Detection function
# ─────────────────────────────────────────────

def check_value(value: str):
    """
    Check a single (normalized, lowercased) string against all rules.

    Returns:
        (rule_name, matched_pattern)  if a threat is detected
        None                          if the value looks safe
    """
    for rule in RULES:
        for pattern in rule["patterns"]:
            if pattern in value:
                return (rule["name"], pattern)
    return None


def inspect_inputs(inputs: dict):
    """
    Inspect a dictionary of {label: normalized_value} pairs.

    inputs example:
        {
            "query:q": "alice' or 1=1--",
            "body:username": "admin",
        }

    Returns:
        List of findings:
        [
            {"field": "query:q", "attack_type": "SQL Injection", "pattern": "or 1=1"},
            ...
        ]
    """
    findings = []
    for field, value in inputs.items():
        result = check_value(value)
        if result:
            attack_type, pattern = result
            findings.append({
                "field": field,
                "attack_type": attack_type,
                "pattern": pattern,
            })
    return findings
