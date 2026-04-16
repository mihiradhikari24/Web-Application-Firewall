# 🛡️ Web Application Firewall (WAF) Demo

A lightweight educational Web Application Firewall implemented in pure Python.
This repository demonstrates the main WAF concepts using a reverse proxy, input normalization, pattern-based detection, rate limiting, and IP tracking.

---

## What this project includes

A WAF sits between clients and a web application, inspecting every request before
it reaches the backend. If a request contains suspicious patterns (SQL injection,
XSS, path traversal, etc.) the WAF blocks it and logs the attack. Safe requests
are forwarded transparently.

This project demonstrates the core principles of a WAF using the simplest
possible implementation: ~400 lines of well-commented Python.

---

## Architecture

```
┌──────────┐          ┌─────────────────────────────────┐          ┌───────────────┐
│          │  HTTP    │           WAF Proxy              │  HTTP    │               │
│  Client  │ ──────▶  │  1. Extract inputs               │ ──────▶  │  Backend App  │
│ (browser │          │  2. Normalize (decode, lowercase) │          │  (port 8081)  │
│  / curl) │ ◀──────  │  3. Check rules                  │ ◀──────  │               │
│          │  403/    │  4a. Block  → 403 + log           │  200/    │               │
└──────────┘  200     │  4b. Forward → pipe response      │  etc.    └───────────────┘
                      └─────────────────────────────────┘
                                     │
                                     ▼
                              logs/attacks_v2.jsonl
```

### Request Flow (step by step)

1. Client sends a request to the WAF (port 8080)
2. `WAFHandler._extract_inputs()` collects all user-controlled data:
   - URL path
   - Query string parameters
   - POST body parameters (form-encoded)
   - Raw body
3. `normalizer.normalize()` decodes each value:
   - URL-decode (two passes to catch double-encoding)
   - HTML entity decode
   - Lowercase (for case-insensitive matching)
4. `inspect()` checks each normalized value and combined payload against all rule patterns from `rules.json`
5. If score > 0: `block()` sends HTTP 403 and logs the attack to `logs/attacks_v2.jsonl`
6. If score == 0: `forward()` opens a connection to the backend and pipes the
   full response back to the client

---

## Actual repository structure

```
.
├── backend.py
├── cli.py
├── config
│   ├── config.example.json
│   ├── config.json
│   └── ip_lists.json
├── logs
│   ├── attacks.jsonl
│   └── attacks_v2.jsonl
├── README.md
├── rules
│   └── rules.json
├── run_all.py
├── scripts
│   ├── simulate_attacks.py
│   └── view_logs.py
└── waf
    ├── ip_manager.py
    ├── logger.py
    ├── normalizer.py
    ├── proxy.py
    └── rate_limiter.py
```

> Note: There is no web interface or `static/` folder in this repository.
> The current implementation is a terminal-based WAF demo only.

---

## Detailed workflow

### 1. Request handling flow

```
Client
  │
  │ HTTP request
  ▼
WAF proxy (`waf/proxy.py`)
  ├─ Extract path, query params, body params, raw body
  ├─ Normalize all inputs
  ├─ Build combined payload
  ├─ Check IP blacklist / whitelist
  ├─ Apply rate limiting
  ├─ Match payloads against detection rules
  ├─ Calculate attack score
  │   ├─ Add rule score
  │   └─ Add suspicious IP history bonus
  ├─ If score >= 10: block and log
  └─ Else: forward request to backend
  ▼
Backend service (`backend.py`)
  └─ Returns a simple OK response
```

### 2. Detection and logging flow

1. Extract raw request values from path, query, body, and raw payload.
2. Normalize each extracted input:
   - multiple URL-decoding passes
   - HTML entity unescape
   - Unicode normalization
   - optional Base64 decode attempt
   - lowercase transform
3. Match every normalized field and the combined payload against every rule pattern.
4. Create a finding for each matching pattern.
5. Calculate a score from the matched rules plus historical IP behavior.
6. If the score reaches the blocking threshold, log the event and return `403`.

### 3. IP analysis and rate limiting flow

- `IPManager` loads `config/ip_lists.json` and keeps:
  - `whitelist`
  - `blacklist`
  - `suspicious` IP counters
- Suspicious IPs are promoted to blacklist after repeated attacks.
- If an IP is blacklisted, the WAF returns `403` immediately.
- If a client sends too many requests too quickly, the rate limiter returns `429`.
- Whitelisted IPs bypass inspection and blocking.

---

## Feature summary

### Present features

- Reverse proxy WAF that sits in front of a backend service
- Support for GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Input extraction from path, query string, form-encoded body, and raw body
- Normalization for encoded and obfuscated payloads
- Rule-based detection for:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Path Traversal
  - Command Injection
- Combined payload inspection across all user inputs
- Per-rule scoring model
- Suspicious IP scoring and blacklist escalation
- Token-bucket rate limiting per endpoint
- CLI rule management tools
- Attack simulation script for testing real requests
- Simple backend service for demonstrating proxy behavior

### Not included in this repository

- Browser-based web dashboard
- Static HTML/CSS/JS user interface
- Full reverse proxy configuration for HTTPS
- Database storage for logs or rules
- Automated unit tests or CI harness

---

## How to run the demo

### Requirements
- Python 3.8 or higher
- No external packages needed

### Option A — Run everything at once

```bash
python run_all.py
```

This starts:
- Backend on http://127.0.0.1:8081
- WAF on http://127.0.0.1:8080

### Option B — Run separately

Terminal 1 — Start the backend:
```bash
python backend.py
```

Terminal 2 — Start the WAF:
```bash
python waf/proxy.py
```

---

## CLI for Rules

Manage WAF rules via command line:

```bash
# List all rules
python cli.py list

# Add a new rule
python cli.py add --type "XSS" --pattern "<script>" --score 10

# Update an existing rule
python cli.py update --id "XSS-001" --pattern "<iframe>"

# Delete a rule
python cli.py delete --id "XSS-001"
```

---

## Attack simulation

Run the attack simulator against the WAF:

```bash
python scripts/simulate_attacks.py
```

This script sends a mix of:
- SQL injection payloads
- XSS payloads
- Path traversal probes
- Command injection attempts
- Legitimate requests to verify forwarding

### Manual testing with curl

SQL Injection:
```bash
curl "http://127.0.0.1:8080/search?q=' OR 1=1--"
```

XSS:
```bash
curl "http://127.0.0.1:8080/profile?name=<script>alert(1)</script>"
```

Path Traversal:
```bash
curl "http://127.0.0.1:8080/file?name=../../etc/passwd"
```

URL-encoded evasion:
```bash
curl "http://127.0.0.1:8080/profile?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Legitimate request:
```bash
curl "http://127.0.0.1:8080/search?q=alice"
```

---

## Logs and analysis

The active attack logger writes JSON lines to `logs/attacks_v2.jsonl`.
Each event includes:
- `timestamp`
- `client_ip`
- `method`
- `path`
- `attack_type`
- `rule_id`
- `field`
- `pattern`
- `status`
- `raw_payload`

The built-in log viewer script currently reads `logs/attacks.jsonl`.
If you want to inspect the latest output, update `scripts/view_logs.py` to use `logs/attacks_v2.jsonl`.

View logs or a summary:

```bash
python scripts/view_logs.py --summary
```

---

## Notes

- This implementation is a local proof of concept, not a production WAF.
- The detection engine is simple substring matching over normalized payloads.
- The WAF is single-process and uses Python's standard `http.server`.
- The attack log file name differs from the viewer script's default path; be aware when inspecting results.

---

## License

MIT — use freely for educational purposes.
