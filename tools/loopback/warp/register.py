#!/usr/bin/env python3
"""Register a throwaway free Cloudflare WARP device with a MASQUE (P-256) key, for the WARP interop job.

feat/nc-masque-warp, proto-loopback.yml job `masque-warp`. Nothing here is committed or stored: the keys live only in
the runner's environment for one job and the device is deleted again by `register.py delete`.

Flow (Cloudflare's public client API, as the open-source WARP MASQUE clients use it):
  1. POST {API}/reg               — new device; the WireGuard key is a random placeholder (never used).
  2. PATCH {API}/reg/{id}         — enroll our P-256 public key: key_type secp256r1, tunnel_type masque.
     The response's config.peers[0] carries the MASQUE endpoint (v4/v6, "host:0") and the endpoint's P-256 public key
     (PEM SPKI); config.interface.addresses the tunnel v4/v6.
  3. DELETE {API}/reg/{id}        — `register.py delete` at the end of the job.

Usage: register.py env <out-file>   writes KEY=VALUE lines (TEST_RUNNER_NC_WARP_*), prints masks for GitHub Actions.
       register.py delete <out-file>
Keys: the client key is SEC 1 DER (base64), the pinned key PEM-less SPKI DER (base64). A second, never-enrolled key
pair provides the wrong-private-key / wrong-public-key cases.
"""
import base64, datetime, json, os, secrets, subprocess, sys, tempfile, urllib.request, urllib.error

API = "https://api.cloudflareclient.com/v0a4471"
HEADERS = {
    "User-Agent": "WARP for Android",
    "CF-Client-Version": "a-6.35-4471",
    "Content-Type": "application/json; charset=UTF-8",
}


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers=dict(HEADERS))
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode(errors="replace")[:400]}


def p256():
    """(SEC 1 DER b64 private key, SPKI DER b64 public key) via openssl."""
    with tempfile.TemporaryDirectory() as d:
        pem = os.path.join(d, "k.pem")
        subprocess.run(["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", pem], check=True)
        priv = subprocess.run(["openssl", "ec", "-in", pem, "-outform", "DER"], check=True,
                              capture_output=True).stdout
        pub = subprocess.run(["openssl", "ec", "-in", pem, "-pubout", "-outform", "DER"], check=True,
                             capture_output=True).stdout
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def strip_port(ep, v6=False):
    ep = ep or ""
    if v6:
        return ep[1:ep.rindex("]")] if ep.startswith("[") else ep
    return ep.rsplit(":", 1)[0] if ep.count(":") == 1 else ep


def register(out):
    now = datetime.datetime.now(datetime.timezone.utc)
    st, acct = call("POST", "/reg", {
        "key": base64.b64encode(secrets.token_bytes(32)).decode(), "install_id": "", "fcm_token": "",
        "tos": now.isoformat(timespec="milliseconds"), "model": "PC", "serial_number": secrets.token_hex(8),
        "os_version": "", "key_type": "curve25519", "tunnel_type": "wireguard", "locale": "en_US",
    })
    print(f"warp-register: POST /reg -> HTTP {st}")
    if st != 200 or "id" not in acct or "token" not in acct:
        print(f"warp-register: registration failed: {json.dumps(acct)[:400]}")
        return 2
    dev, token = acct["id"], acct["token"]
    print(f"::add-mask::{token}")
    priv, pub = p256()
    print(f"::add-mask::{priv}")
    st, upd = call("PATCH", f"/reg/{dev}", {"key": pub, "key_type": "secp256r1", "tunnel_type": "masque",
                                            "name": "tern-ci"}, token)
    print(f"warp-register: PATCH /reg/<id> (enroll secp256r1 / masque) -> HTTP {st}")
    if st != 200:
        print(f"warp-register: key enrollment failed: {json.dumps(upd)[:400]}")
        call("DELETE", f"/reg/{dev}", token=token)
        return 3
    cfg = upd.get("config", {})
    peer = (cfg.get("peers") or [{}])[0]
    ep = peer.get("endpoint", {})
    addrs = cfg.get("interface", {}).get("addresses", {})
    server_pub = "".join(l for l in (peer.get("public_key") or "").splitlines() if "-----" not in l).strip()
    wrong_priv, _ = p256()
    _, wrong_pub = p256()
    env = {
        "TEST_RUNNER_NC_WARP_INTEROP": "1",
        "TEST_RUNNER_NC_WARP_SERVER": strip_port(ep.get("v4")),
        "TEST_RUNNER_NC_WARP_SERVER6": strip_port(ep.get("v6"), v6=True),
        "TEST_RUNNER_NC_WARP_PRIV": priv,
        "TEST_RUNNER_NC_WARP_PUB": server_pub,
        "TEST_RUNNER_NC_WARP_IP4": addrs.get("v4", ""),
        "TEST_RUNNER_NC_WARP_IP6": addrs.get("v6", ""),
        "TEST_RUNNER_NC_WARP_WRONG_PRIV": wrong_priv,
        "TEST_RUNNER_NC_WARP_WRONG_PUB": wrong_pub,
        "NC_WARP_DEVICE": dev,
        "NC_WARP_TOKEN": token,
    }
    print(f"warp-register: endpoint v4={env['TEST_RUNNER_NC_WARP_SERVER']} v6={env['TEST_RUNNER_NC_WARP_SERVER6']} "
          f"ports={ep.get('ports')} tunnel v4={env['TEST_RUNNER_NC_WARP_IP4']} v6 set={bool(env['TEST_RUNNER_NC_WARP_IP6'])} "
          f"server key={'SPKI' if server_pub.startswith('MF') else 'unexpected'} ({len(server_pub)} b64 chars) "
          f"tunnel_type={upd.get('tunnel_type') or upd.get('policy', {}).get('tunnel_protocol')}")
    missing = [k for k in ("TEST_RUNNER_NC_WARP_SERVER", "TEST_RUNNER_NC_WARP_PUB", "TEST_RUNNER_NC_WARP_IP4") if not env[k]]
    if missing:
        print(f"warp-register: enrollment response lacks {missing}: {json.dumps(upd)[:600]}")
        call("DELETE", f"/reg/{dev}", token=token)
        return 4
    with open(out, "w") as f:
        for k, v in env.items():
            f.write(f"{k}={v}\n")
    return 0


def delete(out):
    env = dict(l.rstrip("\n").split("=", 1) for l in open(out) if "=" in l)
    st, _ = call("DELETE", f"/reg/{env['NC_WARP_DEVICE']}", token=env["NC_WARP_TOKEN"])
    print(f"warp-register: DELETE /reg/<id> -> HTTP {st}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("env", "delete"):
        print(__doc__)
        sys.exit(64)
    sys.exit(register(sys.argv[2]) if sys.argv[1] == "env" else delete(sys.argv[2]))
