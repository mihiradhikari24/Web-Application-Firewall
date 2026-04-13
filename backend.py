#!/usr/bin/env python3
"""
backend.py
----------
Simple backend server for testing the WAF.

Responds to all requests with a simple message.
"""

import http.server
import socketserver

class BackendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Hello from backend! Request was allowed by WAF.")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"Received: {body}".encode())

    def log_message(self, format, *args):
        pass  # Suppress logs

if __name__ == "__main__":
    PORT = 8081
    with socketserver.TCPServer(("", PORT), BackendHandler) as httpd:
        print(f"Backend running on port {PORT}")
        httpd.serve_forever()