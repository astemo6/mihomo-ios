#!/usr/bin/env python3
"""Tern E2E replay — secrets of a fixture, never printed.

  mask.py add-mask FIXTURE          print one `::add-mask::<value>` per secret (GitHub hides these lines and masks
                                    the values in every later log line of the job)
  mask.py scrub FIXTURE FILE...     replace every secret in FILE(s) in place with ‹redacted› (artifacts, raw logs)
  mask.py check FIXTURE FILE...     exit 1 (naming only the file) when a FILE still contains a secret

Secrets: every URL in the fixture (and its host), server host / host:port of [server_local] lines, values of
password / passphrase / p12 / obfs-host / obfs-uri / tls-host / sni / username / uuid-like keys, and
mitm passphrase / p12. Values shorter than 4 characters and loopback addresses are ignored.
Stdlib only.
"""

import re
import sys

KEYS = {"password", "passphrase", "p12", "ca-p12", "ca-passphrase", "obfs-host", "obfs-uri", "tls-host", "sni",
        "username", "uuid", "psk", "public-key", "private-key", "short-id", "token", "auth", "tls-pubkey-sha256",
        "tls-cert-sha256", "server_check_url", "resource_parser_url", "geo_location_checker", "profile_img_url"}
PROTOS = {"shadowsocks", "vmess", "vless", "trojan", "http", "socks5", "hysteria2", "tuic", "anytls", "ss", "ssr"}
HARMLESS = {"127.0.0.1", "localhost", "true", "false", "none", "auto", "direct", "reject", "http", "https"}
URL_RE = re.compile(r"(?:https?|wss?|tls|quic)://[^\s,\"'<>)]+")


def secrets(text):
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;[":
            continue
        for u in URL_RE.findall(line):
            out.add(u)
            host = re.sub(r"^[a-z]+://", "", u).split("/")[0].split("?")[0]
            out.add(host)
            out.add(host.rsplit(":", 1)[0])
        for part in line.split(","):
            p = part.strip()
            if "=" not in p:
                continue
            k, v = p.split("=", 1)
            k, v = k.strip().lower(), v.strip()
            if k in KEYS:
                out.add(v)
            if k in PROTOS:
                out.add(v)
                out.add(v.rsplit(":", 1)[0])
            if k == "hostname" or k == "simple_cert_hostname":
                pass  # MitM hostnames are app domains, not secrets
    return sorted({s for s in out if len(s) >= 4 and s.lower() not in HARMLESS and not s.startswith("127.")},
                  key=len, reverse=True)


def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    mode, fixture, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    with open(fixture, encoding="utf-8", errors="replace") as f:
        sec = secrets(f.read())
    if mode == "add-mask":
        for s in sec:
            if "\n" not in s and len(s) < 4096:
                print("::add-mask::" + s)
        print("masked %d value(s)" % len(sec), file=sys.stderr)
        return 0
    bad = 0
    for path in files:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                data = f.read()
        except OSError:
            continue
        if mode == "scrub":
            new = data
            for s in sec:
                new = new.replace(s, "‹redacted›")
            if new != data:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new)
                print("scrubbed %s" % path, file=sys.stderr)
        elif mode == "check":
            if any(s in data for s in sec):
                print("SECRET FOUND in %s" % path)
                bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
