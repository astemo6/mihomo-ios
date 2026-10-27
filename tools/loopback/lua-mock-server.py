#!/usr/bin/env python3
"""Loopback peer for the NativeCore Lua backend test (feat/nc-lua S2).

Plays the server side of the tiny test backend protocol that the test's
Lua script implements (see NativeCoreLoopbackTests.testLuaCustomBackendEcho):

  1. The client (Lua script, via backend.write) sends the 2-byte greeting
     "HE" during its handshake phase; this peer answers "HO".
  2. Afterwards the peer is a decoding relay to the standard TCP echo
     backend (127.0.0.1:18080): client->backend bytes are XORed with 0x5A
     (decoding the script's on_write transform), backend->client bytes are
     XORed with 0x5A (encoding what the script's on_read will decode). The
     transform is symmetric, so both directions apply the same XOR.

TCP 127.0.0.1:18016, stdlib only, threads per connection/direction.
"""

import socket
import threading

HOST = "127.0.0.1"
PORT = 18016
ECHO_HOST = "127.0.0.1"
ECHO_PORT = 18080
KEY = 0x5A


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            dst.sendall(bytes(b ^ KEY for b in chunk))
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(conn: socket.socket) -> None:
    try:
        greeting = b""
        while len(greeting) < 2:
            chunk = conn.recv(2 - len(greeting))
            if not chunk:
                return
            greeting += chunk
        if greeting != b"HE":
            return
        conn.sendall(b"HO")
        backend = socket.create_connection((ECHO_HOST, ECHO_PORT), timeout=5)
        backend.settimeout(None)  # create_connection leaves its timeout on the socket
        t = threading.Thread(target=pump, args=(conn, backend), daemon=True)
        t.start()
        pump(backend, conn)
        t.join(timeout=2)
        backend.close()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(16)
    print(f"lua-mock-server listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
