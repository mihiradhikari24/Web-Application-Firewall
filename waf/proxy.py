import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import http.client
from normalizer import normalize
import re
from collections import defaultdict, deque
import time
import os
from datetime import datetime, timezone

REQUESTS = defaultdict(deque)

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "attacks.jsonl")

def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)

def load_config():
    with open("../config/config.json", "r") as f:
        return json.load(f)
    
def parse_backend_url(url):
    parsed = urlparse(url)
    return parsed.hostname, parsed.port or 80

def load_rules():
        with open("../rules/rules.json") as f:
            return json.load(f)["rules"]



def log_attack(client_ip, method, path, findings, raw_payload):
    ensure_log_dir()
    timestamp = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        entry = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "attack_type": finding["type"],
            "rule_id": finding["rule_id"],
            "field": finding["field"],
            "raw_payload": raw_payload
        }
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

class WAFHandler(BaseHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # return super().log_message(format, *args)
        pass  # Suppress default logging to stderr

    def get_client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]
    
    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return self.rfile.read(length).decode(errors="replace")
        return ""
    
    def extract_inputs(self, parsed_url, body):
        inputs = {}

        inputs["path"] = parsed_url.path

        query = parse_qs(parsed_url.query)
        for k, values in query.items():
            for v in values:
                inputs[f"query:{k}"] = v

        # body params
        if body:
            body_params = parse_qs(body)
            for k, values in body_params.items():
                for v in values:
                    inputs[f"body:{k}"] = v

            inputs["body:raw"] = body

        return inputs
    
    def normalize_inputs(self, inputs):
        return {k: normalize(v) for k, v in inputs.items()}
    
    def build_combined_payload(self, inputs):
        return " ".join(str(v) for v in inputs.values())
    
    def compute_score(self, findings):
        return sum(f["score"] for f in findings)

    def inspect(self, normalized, combined):
        findings = []
        rules = load_rules()  # dynamic loading (important)

        # field-wise check
        for field, value in normalized.items():
            for rule in rules:
                for pattern in rule["patterns"]:   # ✅ FIX
                    if pattern in value:           # keep simple for now
                        findings.append({
                            "rule_id": rule["id"],
                            "attack_type": rule["type"],
                            "score": rule["score"],
                            "pattern": pattern,
                            "field": field
                        })

        # combined check
        for rule in rules:
            for pattern in rule["patterns"]:       # ✅ FIX
                if pattern in combined:
                    findings.append({
                        "rule_id": rule["id"],
                        "attack_type": rule["type"],
                        "score": rule["score"],
                        "pattern": pattern,
                        "field": "combined"
                    })

        return findings
    
    def is_rate_limited(self, ip):
        now = time.time()

        WINDOW = 10
        LIMIT = 20

        q = REQUESTS[ip]

        while q and now - q[0] > WINDOW:
            q.popleft()

        if len(q) >= LIMIT:
            return True

        q.append(now)
        return False
    
    def forward(self, method, path, body, client_ip):
        config = load_config()
        host, port = parse_backend_url(config["backend"])

        conn = http.client.HTTPConnection(host, port)

        headers = dict(self.headers)
        headers["X-Forwarded-For"] = client_ip

        conn.request(method, path, body=body.encode() if body else None, headers=headers)
        response = conn.getresponse()

        self.send_response(response.status)

        for k, v in response.getheaders():
            self.send_header(k, v)

        self.end_headers()
        self.wfile.write(response.read())

    def block(self, client_ip, method, path, findings, raw_payload):
        log_attack(client_ip, method, path, findings, raw_payload)
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

        msg = f"Blocked by WAF: {findings[0]['type']}"
        self.wfile.write(msg.encode())

    def handle_request(self, method, body=""):
        parsed = urlparse(self.path)
        client_ip = self.get_client_ip()

        if self.is_rate_limited(client_ip):
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Too many requests")
            return

        inputs = self.extract_inputs(parsed, body)
        normalized = self.normalize_inputs(inputs)

        combined = self.build_combined_payload(normalized)
        normalized_combined = normalize(combined)

        findings = self.inspect(normalized, normalized_combined)

        score = self.compute_score(findings)

        if score > 0:
            self.block(client_ip, method, self.path, findings, combined)
        else:
            self.forward(method, self.path, body, client_ip)

    
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        body = self.read_body()
        self.handle_request("POST", body)

    def do_PUT(self):
        body = self.read_body()
        self.handle_request("PUT", body)

    def do_DELETE(self):
        body = self.read_body()
        self.handle_request("DELETE", body)

    def do_PATCH(self):
        body = self.read_body()
        self.handle_request("PATCH", body)

    def do_HEAD(self):
        self.handle_request("HEAD")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


if __name__ == "__main__":
    config = load_config()
    port = config["waf_port"]

    server = HTTPServer(("0.0.0.0", port), WAFHandler)
    print(f"WAF running on port {port}")
    server.serve_forever()