"""Minimal test HTTP server for AutoSecAudit.

Serves a login page with weak credentials (admin / password123) so the
brute-force module can be validated. Run:
    py tests/fixtures/test_server.py
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

VALID_USER = "admin"
VALID_PASS = "password123"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep console quiet
        pass

    def _send(self, status, body, ctype="text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if status in (301, 302):
            self.send_header("Location", "/dashboard")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/login"):
            body = (b'<html><body><form action="/login" method="POST">'
                    b'<input name="username"><input name="password" type="password">'
                    b'</form></body></html>')
            self._send(200, body)
        elif self.path.startswith("/dashboard"):
            self._send(200, b"<html><body>Welcome admin</body></html>")
        else:
            self._send(200, b"<html><body>Hello</body></html>")

    def do_POST(self):
        if self.path.startswith("/login"):
            length = int(self.headers.get("Content-Length", 0))
            data = parse_qs(self.rfile.read(length).decode("utf-8", errors="ignore"))
            user = (data.get("username") or [""])[0]
            pw = (data.get("password") or [""])[0]
            if user == VALID_USER and pw == VALID_PASS:
                self.send_response(302)
                self.send_header("Location", "/dashboard")
                self.send_header("Set-Cookie", "session=abcdef123456; Path=/")
                self.end_headers()
            else:
                self._send(200, b"<html><body>Invalid username or password</body></html>")
        else:
            self._send(200, b"ok")


if __name__ == "__main__":
    port = 8088
    print(f"Test server on http://127.0.0.1:{port} (admin/password123)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
