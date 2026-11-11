#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Lab webhook receiver: appends every POST (headers + body) as one JSON line."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = sys.argv[3]


class Sink(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(n).decode()
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": self.path,
                                "headers": {k.lower(): v for k, v in self.headers.items()},
                                "body": body}) + "\n")
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


HTTPServer((sys.argv[1], int(sys.argv[2])), Sink).serve_forever()
