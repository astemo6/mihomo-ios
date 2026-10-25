#!/usr/bin/env python3
"""Cross-check for the classic Shadowsocks AEAD UDP wire format (SIP022).

Background: fix/nc-ss-udp — NativeCoreLoopbackTests.testShadowsocksUDPEcho
timed out with no reply while SS2022 UDP passed. The classic-AEAD UDP path
in NCUDPSSSession was reusing the TCP *stream* codec (NCSSEncoder /
NCSSDecoder) per packet, which wraps the plaintext in a sealed 2-byte length
block followed by a sealed body block under an incrementing nonce. The UDP
spec is different: every datagram is independent and is

    salt || AEAD_seal(subkey, nonce = 0, target-header || payload)

a *single* seal with an all-zero nonce and a fresh salt. A stream-shaped
datagram fails AEAD verification at the server and is dropped silently —
exactly the observed "no reply" symptom.

This script is an independent, spec-first implementation (EVP_BytesToKey +
HKDF-SHA1 "ss-subkey", python `cryptography` for the AEAD). It verifies:

  1. Crypto cross-check against the real server: the stream framing below
     is spoken over TCP to the local sing-box SS inbound and the echo comes
     back byte-exact — this pins master-key derivation, subkey HKDF, salt
     handling and the AES-GCM seal/open to sing-box's own implementation.
  2. The UDP failure mechanism, offline: feeding a stream-shaped datagram
     to a spec-conformant UDP endpoint (salt + one open with nonce 0) fails
     AEAD verification, while a spec-shaped datagram opens cleanly. That
     asymmetry is the whole bug.
  3. Live UDP round-trip when the sandbox allows UDP sends (the dev VM
     blocks them with EPERM; CI runners do not): a spec-shaped datagram
     gets the echo back and the reply decrypts. Skipped, not failed, when
     the send itself is refused by the sandbox.

It also prints the golden vectors used by
UnitTests/NativeCoreTests.testShadowsocksUDPPacketGoldenVectors so the
Swift packet codec is pinned to the same bytes.

Usage:  python3 -m venv /tmp/ssvenv && /tmp/ssvenv/bin/pip install cryptography
        tools/loopback/start-servers.sh start
        /tmp/ssvenv/bin/python tools/loopback/ss-aead-udp-check.py
"""

import hashlib
import hmac as hmac_mod
import socket
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

PASSWORD = "nc-loop-ss-pw"          # mirrors sing-box-config.json / the tests
SERVER = ("127.0.0.1", 18001)       # sing-box classic SS inbound (TCP+UDP)
TCP_ECHO_TARGET = ("127.0.0.1", 18080)
UDP_ECHO_TARGET = ("127.0.0.1", 18081)

# Same DNS-shaped payload as NativeCoreLoopbackTests.dnsQuery.
DNS_QUERY = bytes.fromhex(
    "4e43" "0100" "0001" "0000" "0000" "0000"
    "07" "6578616d706c65" "03" "636f6d" "00" "0001" "0001"
)


def evp_bytes_to_key(password: bytes, key_len: int) -> bytes:
    out, prev = b"", b""
    while len(out) < key_len:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:key_len]


def hkdf_sha1(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_mod.new(salt, ikm, hashlib.sha1).digest()
    okm, t, counter = b"", b"", 1
    while len(okm) < length:
        t = hmac_mod.new(prk, t + info + bytes([counter]), hashlib.sha1).digest()
        okm += t
        counter += 1
    return okm[:length]


def atyp(host: str, port: int) -> bytes:
    return b"\x01" + socket.inet_aton(host) + port.to_bytes(2, "big")


def subkey(cipher: str, password: str, salt: bytes) -> bytes:
    key_len = 32 if cipher in ("aes-256-gcm", "chacha20-ietf-poly1305") else 16
    master = evp_bytes_to_key(password.encode(), key_len)
    return hkdf_sha1(master, salt, b"ss-subkey", key_len)


def seal(cipher: str, key: bytes, nonce_int: int, plain: bytes) -> bytes:
    nonce = nonce_int.to_bytes(12, "little")  # SS AEAD counter nonces are LE
    if cipher.startswith("aes-"):
        return AESGCM(key).encrypt(nonce, plain, None)
    return ChaCha20Poly1305(key).encrypt(nonce, plain, None)


def open_sealed(cipher: str, key: bytes, nonce_int: int, sealed: bytes) -> bytes:
    nonce = nonce_int.to_bytes(12, "little")
    if cipher.startswith("aes-"):
        return AESGCM(key).decrypt(nonce, sealed, None)
    return ChaCha20Poly1305(key).decrypt(nonce, sealed, None)


def spec_packet(cipher: str, password: str, plain: bytes, salt: bytes) -> bytes:
    """The SIP022 UDP datagram: salt || single seal, nonce zero."""
    return salt + seal(cipher, subkey(cipher, password, salt), 0, plain)


def stream_packet(cipher: str, password: str, plain: bytes, salt: bytes) -> bytes:
    """The TCP stream framing (and what the old Swift UDP path emitted):
    salt || seal(nonce 0, 2-byte length) || seal(nonce 1, body)."""
    key = subkey(cipher, password, salt)
    return (salt
            + seal(cipher, key, 0, len(plain).to_bytes(2, "big"))
            + seal(cipher, key, 1, plain))


def tcp_stream_echo(cipher: str, plain: bytes) -> bytes:
    """Speak the stream framing over TCP to sing-box; return the decrypted
    echo plaintext. Validates every shared crypto primitive against the
    real server implementation."""
    salt = bytes(range(32))
    with socket.create_connection(SERVER, timeout=5) as sock:
        sock.sendall(stream_packet(cipher, PASSWORD, plain, salt))
        buf = b""
        while len(buf) < 32 + 18:
            chunk = sock.recv(65535)
            if not chunk:
                raise IOError("EOF before response header")
            buf += chunk
        resp_salt, rest = buf[:32], buf[32:]
        key = subkey(cipher, PASSWORD, resp_salt)
        length = int.from_bytes(open_sealed(cipher, key, 0, rest[:18]), "big")
        while len(rest) < 18 + length + 16:
            chunk = sock.recv(65535)
            if not chunk:
                raise IOError("EOF inside response body")
            rest += chunk
        return open_sealed(cipher, key, 1, rest[18:18 + length + 16])


def udp_roundtrip(packet: bytes, timeout: float = 3.0) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, SERVER)
        data, _ = sock.recvfrom(65535)
        return data
    except socket.timeout:
        return None
    finally:
        sock.close()


def strip_atyp(plain: bytes) -> bytes:
    assert plain[0] == 0x01, f"unexpected ATYP {plain[0]}"
    return plain[1 + 4 + 2:]


def main() -> int:
    cipher = "aes-256-gcm"
    salt = bytes(range(32))
    plain = atyp(*UDP_ECHO_TARGET) + DNS_QUERY

    print("== 1. crypto cross-check: stream framing over TCP to sing-box ==")
    tcp_plain = atyp(*TCP_ECHO_TARGET) + DNS_QUERY
    echoed = tcp_stream_echo(cipher, tcp_plain)
    # The server consumes the ATYP header; the echo comes back as raw payload.
    assert echoed == DNS_QUERY, f"TCP echo mismatch: {echoed.hex()} != {DNS_QUERY.hex()}"
    print("sing-box decrypted our stream packet and echoed it byte-exact;")
    print("master key / subkey HKDF / salt / AES-GCM all match the server.")

    print("\n== 2. the UDP failure mechanism (offline, spec-conformant endpoint) ==")
    key = subkey(cipher, PASSWORD, salt)
    try:
        open_sealed(cipher, key, 0, stream_packet(cipher, PASSWORD, plain, salt)[32:])
        print("stream-shaped datagram OPENED as a UDP packet (unexpected!)")
        return 1
    except InvalidTag:
        print("stream-shaped datagram: AEAD verify fails -> server drops it silently")
    opened = open_sealed(cipher, key, 0, spec_packet(cipher, PASSWORD, plain, salt)[32:])
    assert opened == plain
    print("spec-shaped datagram:   opens cleanly, payload intact")

    print("\n== 3. live UDP round-trip (needs UDP sends; dev VM sandbox blocks them) ==")
    try:
        reply = udp_roundtrip(spec_packet(cipher, PASSWORD, plain, salt))
    except PermissionError:
        reply = "blocked"
    if reply == "blocked":
        print("skipped: sandbox refused the UDP send (EPERM); CI runs this for real")
    elif reply is None:
        print("FAIL: spec-shaped datagram got no reply from sing-box")
        return 1
    else:
        reply_plain = open_sealed(cipher, subkey(cipher, PASSWORD, reply[:32]), 0, reply[32:])
        assert strip_atyp(reply_plain) == DNS_QUERY, "echo payload mismatch"
        print("spec-shaped datagram: echo reply decrypted, payload matches")

    print("\n== golden vectors (fixed salts; pinned in NativeCoreTests) ==")
    req_salt = bytes(range(0x00, 0x20))
    rep_salt = bytes(range(0x20, 0x40))
    print(f"plain (atyp+payload)     : {plain.hex()}")
    print(f"aes-256-gcm request salt : {req_salt.hex()}")
    print(f"aes-256-gcm request      : {spec_packet(cipher, PASSWORD, plain, req_salt).hex()}")
    print(f"aes-256-gcm reply salt   : {rep_salt.hex()}")
    print(f"aes-256-gcm reply        : {spec_packet(cipher, PASSWORD, plain, rep_salt).hex()}")
    chacha = "chacha20-ietf-poly1305"
    print(f"chacha request salt      : {req_salt.hex()}")
    print(f"chacha request           : {spec_packet(chacha, PASSWORD, plain, req_salt).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
