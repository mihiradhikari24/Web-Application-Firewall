"""
waf/proxy.py
------------
The core WAF reverse proxy.

Flow for every incoming request:
  1. Receive request from client
  2. Extract all user-controlled inputs (URL params, body, path)
  3. Normalize each input (URL-decode, entity-decode, lowercase)
  4. Check normalized inputs against attack rules
  5a. If threat detected → return 403 Forbidden + log the attack
  5b. If safe → forward request to backend, return response to client

Uses only Python's built-in http.server and urllib — no extra dependencies.
"""

import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from normalizer import normalize
from rules import inspect_inputs
from logger import log_attack, log_pass


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
WAF_HOST = "0.0.0.0"   # Listen on all interfaces
WAF_PORT = 8080

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8081

# Headers we strip before forwarding (hop-by-hop headers)
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
}

# HTML shown when a request is blocked
BLOCKED_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>403 Blocked by WAF</title>
<style>
  body {{ font-family: monospace; max-width: 600px; margin: 80px auto; text-align: center; }}
  .box {{ background: #ffebee; border: 2px solid #f44336; border-radius: 8px; padding: 30px; }}
  h1 {{ color: #c62828; }}
  code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
</style>
</head>
<body>
<div class="box">
  <h1>🛡️ 403 — Request Blocked</h1>
  <p>The Web Application Firewall has detected a potential attack in your request.</p>
  <p>Attack type: <code>{attack_type}</code></p>
  <p>Matched pattern: <code>{pattern}</code></p>
  <hr>
  <small>WAF Demo System</small>
</div>
</body>
</html>"""


# ─────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────
class WAFHandler(BaseHTTPRequestHandler):
    """
    Handles every HTTP request that arrives at the WAF port.
    Decides: block or forward.
    """

    def log_message(self, format, *args):
        # Suppress default access log — we have our own logging
        pass

    def _get_client_ip(self):
        """Get the client's real IP (respect X-Forwarded-For if present)."""
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _read_body(self):
        """Read the request body if Content-Length is set."""
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return self.rfile.read(length).decode(errors="replace")
        return ""

    def _extract_inputs(self, parsed_url, body):
        """
        Collect all user-controlled input fields into a flat dict.

        Returns:
            {
                "path": "/search",
                "query:q": "alice",
                "body:username": "admin",
                ...
            }

        Each key is prefixed with its source (path/query/body)
        so logs clearly show where the attack came from.
        """
        inputs = {}

        # The URL path itself can carry traversal payloads
        inputs["path"] = parsed_url.path

        # Query string parameters (?key=value&...)
        query_params = parse_qs(parsed_url.query)
        for key, values in query_params.items():
            for i, val in enumerate(values):
                inputs[f"query:{key}"] = val

        # POST body parameters (application/x-www-form-urlencoded)
        if body:
            body_params = parse_qs(body)
            for key, values in body_params.items():
                for val in values:
                    inputs[f"body:{key}"] = val
            # Also inspect the raw body in case it's JSON or something else
            inputs["body:raw"] = body

        return inputs

    def _normalize_inputs(self, inputs):
        """
        Return a new dict with every value normalized for inspection.
        The original inputs dict is kept intact for logging raw payloads.
        """
        return {field: normalize(value) for field, value in inputs.items()}

    def _block(self, client_ip, method, path, findings, raw_payload):
        """Send a 403 response and log the attack."""
        # Use the first finding for the block page details
        first = findings[0]
        body = BLOCKED_HTML.format(
            attack_type=first["attack_type"],
            pattern=first["pattern"],
        ).encode()

        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        # Write to log file
        log_attack(client_ip, method, path, findings, raw_payload)

    def _forward(self, method, path, body, client_ip):
        """
        Forward the request to the backend and pipe the response back.

        We open a fresh HTTP connection for each request — fine for a demo,
        connection pooling would be needed for production.
        """
        try:
            conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=10)

            # Build clean headers to forward (remove hop-by-hop headers)
            forward_headers = {}
            for key, value in self.headers.items():
                if key.lower() not in HOP_BY_HOP:
                    forward_headers[key] = value

            # Add X-Forwarded-For so the backend knows the real client IP
            forward_headers["X-Forwarded-For"] = client_ip
            forward_headers["X-Forwarded-By"] = "WAF-Demo"

            # Make the request to the backend
            conn.request(method, path, body=body.encode() if body else None, headers=forward_headers)
            response = conn.getresponse()

            # Forward the backend's response back to the client
            self.send_response(response.status)
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP:
                    self.send_header(key, value)
            self.end_headers()

            # Stream the response body
            self.wfile.write(response.read())

            log_pass(client_ip, method, self.path)

        except Exception as e:
            # Backend unreachable — tell the client
            error_body = f"<h1>502 Bad Gateway</h1><p>Backend error: {e}</p>".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(error_body)))
            self.end_headers()
            self.wfile.write(error_body)

    def _handle_request(self, method, body=""):
        """Shared logic for all HTTP methods."""
        parsed = urlparse(self.path)
        client_ip = self._get_client_ip()

        # Step 1: Collect all inputs
        inputs = self._extract_inputs(parsed, body)

        # Step 2: Normalize inputs (decode, lowercase)
        normalized = self._normalize_inputs(inputs)

        # Step 3: Inspect normalized inputs against rules
        findings = inspect_inputs(normalized)

        # Step 4: Block or forward
        if findings:
            # Build a representative raw payload string for logging
            raw_payload = " | ".join(f"{k}={v}" for k, v in inputs.items())
            self._block(client_ip, method, parsed.path, findings, raw_payload)
        else:
            self._forward(method, self.path, body, client_ip)

    # HTTP method handlers — all delegate to _handle_request
    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        body = self._read_body()
        self._handle_request("POST", body)

    def do_PUT(self):
        body = self._read_body()
        self._handle_request("PUT", body)

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_HEAD(self):
        self._handle_request("HEAD")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print(f"[WAF] Starting on http://{WAF_HOST}:{WAF_PORT}")
    print(f"[WAF] Forwarding safe requests to http://{BACKEND_HOST}:{BACKEND_PORT}")
    print(f"[WAF] Attack logs → logs/attacks.jsonl")
    print("[WAF] Press Ctrl+C to stop\n")

    server = HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    server.serve_forever()
