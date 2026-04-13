# 🛡️ WAF Demo — Web Application Firewall

A minimal, educational Web Application Firewall (WAF) implemented in pure Python.
Built for a cybersecurity course — no external dependencies required.

---

## Project Idea

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
                              logs/attacks.jsonl
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
5. If score > 0: `block()` sends HTTP 403 and logs the attack to `logs/attacks.jsonl`
6. If score == 0: `forward()` opens a connection to the backend and pipes the
   full response back to the client

---

## Project Structure

```
waf_demo/
│
├── backend.py              Simple backend server (port 8081)
│
├── waf/
│   ├── proxy.py            Main WAF reverse proxy (port 8080)
│   ├── normalizer.py       Input normalization (decode, lowercase)
│   ├── rules.json          Attack detection patterns
│   └── rules_enforcer.py   Old rules system (deprecated)
│
├── scripts/
│   ├── simulate_attacks.py Sends attack and legitimate requests to the WAF
│   └── view_logs.py        Parse and display the attack log
│
├── static/                 Web interface static files
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── logs/
│   └── attacks.jsonl       Attack log (JSON-lines format, created at runtime)
│
├── cli.py                  Command-line interface for rule management
├── web_interface.py        Web server for management interface (port 8000)
├── run_all.py              Starts backend, WAF, and web interface
└── README.md               This file
```

### Module descriptions

| Module | Purpose |
|---|---|
| `backend.py` | Simple backend server for testing |
| `waf/proxy.py` | Core reverse proxy: receive → inspect → block or forward |
| `waf/normalizer.py` | Decodes encoded payloads (URL encoding, HTML entities) |
| `waf/rules.json` | Pattern-matching rules for SQLi, XSS, traversal, command injection |
| `waf/rules_enforcer.py` | Old rules system (deprecated) |
| `scripts/simulate_attacks.py` | Automated attack simulation script |
| `scripts/view_logs.py` | Log file viewer and summary tool |
| `cli.py` | Command-line interface for managing rules |
| `web_interface.py` | Web server for local management interface |
| `static/` | HTML/CSS/JS files for the web interface |
| `run_all.py` | Starts backend, WAF proxy, and web interface |

---

## How to Run

### Requirements
- Python 3.8 or higher
- No external packages needed

### Option A — Run everything at once

```bash
cd waf_demo
python run_all.py
```

This starts:
- Backend on http://127.0.0.1:8081
- WAF on http://127.0.0.1:8080
- Web interface on http://127.0.0.1:8000

### Option B — Run separately

Terminal 1 — Start the backend:
```bash
python backend.py
```

Terminal 2 — Start the WAF:
```bash
python waf/proxy.py
```

Terminal 3 — Start the web interface:
```bash
python web_interface.py
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

## Web Interface

Access the local web management interface at http://localhost:8000

Features:
- **Logs & Analytics**: View blocked requests with timestamps, attack types, and basic analytics
- **Attack Testing**: Run automated attack simulations and view results
- **Rule CRUD**: Create, read, update, and delete WAF rules through a web form

With both services running, open a third terminal:

```bash
cd waf_demo
python scripts/simulate_attacks.py
```

This sends:
- SQL injection attempts (GET and POST)
- XSS payloads (reflected and stored)
- Path traversal attempts (including encoded variants)
- Command injection payloads
- Legitimate requests (should all pass through)

### Manual testing with curl

SQL Injection:
```bash
curl "http://localhost:8080/search?q=' OR 1=1--"
```

XSS:
```bash
curl "http://localhost:8080/profile?name=<script>alert(1)</script>"
```

Path Traversal:
```bash
curl "http://localhost:8080/file?name=../../etc/passwd"
```

URL-encoded evasion (WAF should still catch this):
```bash
curl "http://localhost:8080/profile?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

Legitimate request (should pass through):
```bash
curl "http://localhost:8080/search?q=alice"
```

---

## Example Output

### WAF terminal when attacks are detected:

```
[WAF] Starting on http://0.0.0.0:8080
[WAF] Forwarding safe requests to http://127.0.0.1:8081

[WAF BLOCKED] 2024-01-15T10:23:45+00:00 | IP=127.0.0.1 | GET /search | Attack=SQL Injection | Pattern="or 1=1" | Field=query:q
[WAF BLOCKED] 2024-01-15T10:23:46+00:00 | IP=127.0.0.1 | GET /profile | Attack=XSS | Pattern="<script" | Field=query:name
[WAF BLOCKED] 2024-01-15T10:23:47+00:00 | IP=127.0.0.1 | GET /file | Attack=Path Traversal | Pattern="../" | Field=query:name
```

### Simulation script summary:

```
══════════════════════════════════════════════════════
  SUMMARY
══════════════════════════════════════════════════════
  Total requests : 23
  Blocked (403)  : 18
  Passed  (2xx)  : 5
  Errors         : 0

  Attack logs written to: logs/attacks.jsonl
══════════════════════════════════════════════════════
```

### View attack logs:

```bash
python scripts/view_logs.py --summary
```

Output:
```
Attack Log Summary
Total blocked requests: 18

By Attack Type:
  SQL Injection             6  ██████
  XSS                       7  ███████
  Path Traversal            4  ████
  Command Injection         1  █

Top Targeted Paths:
  /search                   7  attacks
  /profile                  6  attacks
  /file                     4  attacks
  /comment                  2  attacks
  /login                    2  attacks
```

---

## Known Limitations (by design)

This is an educational demo, not a production WAF. Known gaps:

1. **No HTTPS support** — real WAFs terminate TLS
2. **Single-threaded** — one request at a time
3. **Pattern matching only** — no ML, no behavioral analysis
4. **No rate limiting** — DoS attacks are not detected
5. **No IP blocking** — repeat offenders are not tracked
6. **Body size limit** — large POST bodies not handled
7. **No configuration file** — rules are hardcoded

These are all addressed in the roadmap below.

---

## Roadmap: Scaling the WAF

### 1. Rule-based Engine with Configurable Files
**What**: Load rules from YAML/JSON files instead of hardcoding them in Python.
**Why**: Security teams can update rules without touching code; rules can be versioned.
**Where**: Replace `waf/rules.py` constants with a `RuleLoader` class that reads from `rules/*.yaml`.

### 2. Better Payload Normalization
**What**: Add more decoding passes — Unicode normalization, base64 detection, hex sequences, null bytes, multi-byte encodings.
**Why**: Sophisticated attackers use uncommon encodings to bypass WAFs.
**Where**: Extend `waf/normalizer.py` with additional decode functions.

### 3. Rate Limiting
**What**: Count requests per IP per time window; block IPs that exceed a threshold.
**Why**: Prevents brute-force attacks and automated scanners.
**Where**: Add a `waf/rate_limiter.py` module using a sliding window counter (dict of IP → deque of timestamps). Check before inspection.

### 4. IP Blacklist / Whitelist
**What**: Maintain lists of known-bad IPs (blacklist) and trusted IPs (whitelist).
**Why**: Instantly block known attackers; allow internal IPs to bypass inspection.
**Where**: New `waf/ip_filter.py` module, checked first before any other processing. Load from a file or database.

### 5. Improved Logging and Analytics
**What**: Structured logging with severity levels, request IDs, and response times. Integration with log aggregators (ELK stack, Loki, etc.).
**Why**: Easier to search, alert on, and correlate attacks.
**Where**: Upgrade `waf/logger.py` to use Python's `logging` module with JSON formatter.

### 6. Attack Dashboard
**What**: A simple web UI that reads `attacks.jsonl` and shows charts: attacks over time, top IPs, top attack types.
**Why**: Visual monitoring is much faster than reading raw log files.
**Where**: New `dashboard/` folder with a lightweight Flask/FastAPI app or a static HTML page that reads a pre-computed JSON summary.

### 7. Anomaly-Based Detection
**What**: Instead of pattern matching, establish a baseline of normal requests (URL length distribution, parameter names, request frequency) and flag deviations.
**Why**: Catches zero-day attacks that don't match known patterns.
**Where**: New `waf/anomaly_detector.py` with statistical models. Runs in parallel with rule-based inspection.

### 8. Machine Learning Classification
**What**: Train a classifier (e.g. logistic regression or a small neural network) on labeled request datasets to predict attack probability.
**Why**: Handles obfuscated payloads that simple string matching misses.
**Where**: `waf/ml_detector.py` using scikit-learn. Model is trained offline on datasets like CSIC 2010 HTTP Dataset, loaded at startup.

### 9. Modular Detection Pipeline
**What**: Chain detectors as independent stages. Each stage can add findings or short-circuit. Easy to add/remove stages.
**Why**: Clean architecture that makes combining different detection methods easy.
**Where**: A `DetectionPipeline` class in `waf/pipeline.py` that runs: `[IPFilter → RateLimiter → Normalizer → RuleEngine → MLDetector]`.

### 10. Performance: Async Proxy
**What**: Replace `http.server` with an async framework (asyncio + aiohttp) to handle many concurrent connections.
**Why**: The current single-threaded server blocks on every request. Real WAFs handle thousands of concurrent connections.
**Where**: Rewrite `waf/proxy.py` using `aiohttp` as both server and client, or use `uvicorn` + `httpx`.

---

## License

MIT — use freely for educational purposes.
