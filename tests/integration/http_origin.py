#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Test origin server.

GET /       -> "sentinel-ok"
GET /blob   -> 1 MiB of 'x' (large segments origin -> client)
POST /upload-> number of body bytes received (large segments client -> origin)

Every request is logged as "<client ip> <request line>" so tests can check that
the origin sees the real client address.

Usage: http_origin.py <bind address> <port>
"""
import http.server
import sys

BLOB = b"x" * (1 << 20)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._send(BLOB if self.path == "/blob" else b"sentinel-ok\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        got = 0
        while got < n:
            chunk = self.rfile.read(min(65536, n - got))
            if not chunk:
                break
            got += len(chunk)
        self._send(f"{got}\n".encode())

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)


def main():
    addr, port = sys.argv[1], int(sys.argv[2])
    http.server.ThreadingHTTPServer((addr, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
