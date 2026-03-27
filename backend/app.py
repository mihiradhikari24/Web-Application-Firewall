"""
backend/app.py
--------------
A simple demo web application that intentionally accepts unsanitized input.
This simulates a vulnerable app that the WAF is protecting.

Uses only Python's built-in http.server module — no Flask required.
"""

import json
import sqlite3
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "app.db")

# Single shared DB connection for this demo
DB = sqlite3.connect(DB_PATH, check_same_thread=False)

# ─────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────
def html_page(title, body):
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>{title}</title>
<style>
  body {{ font-family: monospace; max-width: 700px; margin: 40px auto; padding: 0 20px; }}
  .endpoint {{ background: #f4f4f4; padding: 10px; border-radius: 4px; margin: 8px 0; }}
  .result {{ background: #e8f5e9; padding: 10px; border-left: 4px solid #4caf50; margin: 10px 0; }}
  .comment {{ background: #fff3e0; padding: 8px; margin: 4px 0; border-left: 3px solid #ff9800; }}
  a {{ color: #1565c0; }}
</style>
</head>
<body>{body}</body>
</html>"""


def send_html(handler, code, content):
    data = content.encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


# ─────────────────────────────────────────────
# Request handler
# ─────────────────────────────────────────────
class BackendHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[BACKEND] {self.address_string()} - {format % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/":
            self._handle_home()
        elif path == "/search":
            query = params.get("q", [""])[0]
            self._handle_search(query)
        elif path == "/profile":
            name = params.get("name", ["Guest"])[0]
            self._handle_profile(name)
        elif path == "/comments":
            self._handle_list_comments()
        elif path == "/file":
            filename = params.get("name", [""])[0]
            self._handle_file(filename)
        elif path == "/logs":
            self._handle_logs()
        elif path == "/stats":
            self._handle_stats()
        else:
            send_html(self, 404, html_page("404", "<h2>404 Not Found</h2>"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")
        params = parse_qs(body)

        if path == "/login":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            self._handle_login(username, password)
        elif path == "/comment":
            author = params.get("author", ["Anonymous"])[0]
            text = params.get("body", [""])[0]
            self._handle_add_comment(author, text)
        else:
            send_html(self, 404, html_page("404", "<h2>404 Not Found</h2>"))

    # ── Endpoint implementations ──────────────────────────────────────────

    def _handle_home(self):
        body = """
        <h1>WAF Demo — Backend App</h1>
        <p>This is the vulnerable backend. Access through the WAF on port 8080.</p>
        <h3>Endpoints:</h3>
        <div class="endpoint"><b>GET /search?q=term</b> — SQL injection demo</div>
        <div class="endpoint"><b>GET /profile?name=Alice</b> — XSS demo</div>
        <div class="endpoint"><b>GET /comments</b> — stored XSS demo</div>
        <div class="endpoint"><b>GET /file?name=readme.txt</b> — path traversal demo</div>
        <div class="endpoint"><b>POST /login</b> — username=&amp;password= (SQLi)</div>
        <div class="endpoint"><b>POST /comment</b> — author=&amp;body= (XSS)</div>
        """
        send_html(self, 200, html_page("Backend App", body))

    def _handle_search(self, query):
        # INTENTIONALLY VULNERABLE: raw string format in SQL
        try:
            sql = f"SELECT id, username FROM users WHERE username = '{query}'"
            cursor = DB.cursor()
            cursor.execute(sql)
            rows = cursor.fetchall()
            items = "".join(f"<li>ID={r[0]}, Username={r[1]}</li>" for r in rows)
            body = f"""
            <h2>Search: <code>{html.escape(query)}</code></h2>
            <p><small>SQL: <code>{html.escape(sql)}</code></small></p>
            <ul>{items or '<li>No results</li>'}</ul>
            <a href="/">Home</a>
            """
        except Exception as e:
            body = f"<h2>DB Error</h2><pre>{html.escape(str(e))}</pre>"
        send_html(self, 200, html_page("Search", body))

    def _handle_profile(self, name):
        # INTENTIONALLY VULNERABLE: reflects name raw into HTML
        body = f"<h2>Welcome, {name}!</h2><a href='/'>Home</a>"
        send_html(self, 200, html_page("Profile", body))

    def _handle_list_comments(self):
        cursor = DB.cursor()
        cursor.execute("SELECT author, body FROM comments")
        rows = cursor.fetchall()
        # INTENTIONALLY VULNERABLE: body reflected raw (stored XSS)
        items = "".join(f'<div class="comment"><b>{r[0]}</b>: {r[1]}</div>' for r in rows)
        body = f"<h2>Comments</h2>{items}<a href='/'>Home</a>"
        send_html(self, 200, html_page("Comments", body))

    def _handle_file(self, filename):
        # INTENTIONALLY VULNERABLE: no path validation
        import os
        base = os.path.dirname(os.path.abspath(__file__))
        target = os.path.join(base, filename)
        try:
            with open(target, "r") as f:
                content = html.escape(f.read())
            body = f"<h2>File: {html.escape(filename)}</h2><pre>{content}</pre>"
        except Exception as e:
            body = f"<h2>Error</h2><p>{html.escape(str(e))}</p>"
        send_html(self, 200, html_page("File", body))

    def _handle_login(self, username, password):
        # INTENTIONALLY VULNERABLE: raw SQL interpolation
        try:
            sql = f"SELECT id, username FROM users WHERE username='{username}' AND password='{password}'"
            cursor = DB.cursor()
            cursor.execute(sql)
            row = cursor.fetchone()
            if row:
                body = f'<div class="result"><h2>Login OK: {html.escape(row[1])}</h2></div>'
            else:
                body = "<h2>Invalid credentials.</h2>"
            body += f"<p><small>SQL: <code>{html.escape(sql)}</code></small></p><a href='/'>Home</a>"
        except Exception as e:
            body = f"<h2>DB Error</h2><pre>{html.escape(str(e))}</pre>"
        send_html(self, 200, html_page("Login", body))

    def _handle_add_comment(self, author, text):
        cursor = DB.cursor()
        # INTENTIONALLY VULNERABLE: no sanitization before storage
        cursor.execute("INSERT INTO comments (author, body) VALUES (?, ?)", (author, text))
        DB.commit()
        body = '<div class="result"><h2>Comment added!</h2></div><a href="/comments">View</a>'
        send_html(self, 200, html_page("Comment", body))

    def _handle_logs(self):
        log_file = os.path.join(os.path.dirname(BASE_DIR), "logs", "attacks.jsonl")

        logs = []
        try:
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        logs.append(json.loads(line))
                    except:
                        continue
        except:
            logs = []

        # # return last 100
        # logs = logs[-100:]

        data = json.dumps(logs).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle_stats(self):
        PROJECT_ROOT = os.path.dirname(BASE_DIR)
        LOG_FILE = os.path.join(PROJECT_ROOT, "logs", "attacks.jsonl")

        total = 0
        types = {}

        try:
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        log = json.loads(line)
                        total += 1
                        attack = log.get("attack_type", "unknown")
                        types[attack] = types.get(attack, 0) + 1
                    except:
                        continue
        except:
            pass

        result = {
            "total_attacks": total,
            "by_type": types
        }

        data = json.dumps(result).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    


BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8081

if __name__ == "__main__":
    server = HTTPServer((BACKEND_HOST, BACKEND_PORT), BackendHandler)
    print(f"[BACKEND] Running on http://{BACKEND_HOST}:{BACKEND_PORT}")
    server.serve_forever()
