#!/usr/bin/env python3
"""Tern E2E replay — local HTTP origin + resource server (127.0.0.1:18480).

Serves, for the sanitized sample fixture (tools/e2e/sample/):
  /sub/<file>        proxy-provider subscription (QX server_remote)
  /rules/<file>      remote rule lists (QX filter_remote)
  /modules/<file>    remote rewrite modules (QX rewrite_remote)
  /scripts/<file>    rewrite / task scripts
  /generate_204      204 (server_check_url, group delay tests)
  /e2e/<anything>    200 "e2e-ok host=<Host> path=<path>" — the origin the data-plane scenarios reach
                     (DIRECT, proxied through the loopback sing-box nodes, fake-ip, redir-host)
  /stats             JSON request counters per path prefix (no hosts / query strings)

Stdlib only. Never logs query strings (subscription URLs of a real fixture may carry tokens).
Usage: e2e_server.py [--root DIR] [--port 18480]
"""

import argparse
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNTS = {}
LOCK = threading.Lock()


def bump(key):
    with LOCK:
        COUNTS[key] = COUNTS.get(key, 0) + 1


class Handler(BaseHTTPRequestHandler):
    root = "."
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # path only, no query string
        sys.stderr.write("[e2e-server] %s %s\n" % (self.command, self.path.split("?", 1)[0]))

    def _send(self, code, body=b"", ctype="text/plain; charset=utf-8", extra=None):
        self.send_response(code)
        if code != 204:
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
        else:
            self.send_header("Content-Length", "0")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body and self.command != "HEAD" and code != 204:
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        top = "/" + path.strip("/").split("/", 1)[0]
        bump(top)
        if path == "/generate_204":
            return self._send(204)
        if path == "/stats":
            with LOCK:
                body = json.dumps(COUNTS, sort_keys=True).encode()
            return self._send(200, body, "application/json")
        if path.startswith("/e2e/"):
            host = self.headers.get("Host", "-")
            body = ("e2e-ok host=%s path=%s\n" % (host, path)).encode()
            return self._send(200, body, extra={"X-E2E-Origin": "1"})
        for prefix in ("/sub/", "/rules/", "/modules/", "/scripts/"):
            if path.startswith(prefix):
                rel = os.path.normpath(path.lstrip("/"))
                if rel.startswith(".."):
                    return self._send(403, b"forbidden")
                full = os.path.join(self.root, rel)
                if not os.path.isfile(full):
                    return self._send(404, b"not found")
                with open(full, "rb") as f:
                    data = f.read()
                ctype = "application/javascript" if full.endswith(".js") else "text/plain; charset=utf-8"
                return self._send(200, data, ctype)
        return self._send(404, b"not found")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample"))
    ap.add_argument("--port", type=int, default=18480)
    a = ap.parse_args()
    Handler.root = a.root
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    sys.stderr.write("[e2e-server] serving %s on 127.0.0.1:%d\n" % (a.root, a.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
