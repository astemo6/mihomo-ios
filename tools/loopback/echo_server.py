#!/usr/bin/env python3
"""Loopback backends for the NativeCore protocol loopback tests.

One process, four sockets (all 127.0.0.1):

  TCP 18080  echo        — every byte received is sent back verbatim.
  UDP 18081  echo        — every datagram is sent back verbatim.
  TCP 18082  blackhole   — accepts connections and reads NOTHING while paused,
                           so a sender's flow control is the only thing that
                           can stop it; used by the back-pressure tests.
  UDP 18083  control     — datagram "go"    : blackhole starts discarding
                                              (reads and drops) on every held
                                              connection and on future ones.
                           datagram "pause" : future blackhole connections are
                                              held unread again.

The sing-box inbounds route to whatever target the client names, so the
tests pick echo vs blackhole purely by the target port they ask for.

Stdlib only, so this runs on any macOS/Linux python3. SIGTERM/SIGINT stops it.
"""

import socket
import sys
import threading

HOST = "127.0.0.1"
TCP_ECHO_PORT = 18080
UDP_ECHO_PORT = 18081
BLACKHOLE_PORT = 18082
CONTROL_PORT = 18083

_state_lock = threading.Lock()
_discarding = False          # blackhole mode: False = hold unread, True = read & drop
_held = []                   # blackhole connections waiting for "go"


def _discard_loop(conn: socket.socket) -> None:
    try:
        while True:
            data = conn.recv(65536)
            if not data:
                break
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _start_discarding(conn: socket.socket) -> None:
    threading.Thread(target=_discard_loop, args=(conn,), daemon=True).start()


def _set_discarding(on: bool) -> None:
    global _discarding
    with _state_lock:
        _discarding = on
        held, _held[:] = list(_held), []
    if on:
        for conn in held:
            _start_discarding(conn)


def tcp_echo_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, TCP_ECHO_PORT))
    srv.listen(64)

    def handle(conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def blackhole_server() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, BLACKHOLE_PORT))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        with _state_lock:
            if _discarding:
                _start_discarding(conn)
            else:
                _held.append(conn)


def udp_echo_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, UDP_ECHO_PORT))
    while True:
        data, addr = sock.recvfrom(65535)
        sock.sendto(data, addr)


def control_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, CONTROL_PORT))
    while True:
        data, _ = sock.recvfrom(1024)
        cmd = data.strip().lower()
        if cmd == b"go":
            _set_discarding(True)
        elif cmd == b"pause":
            _set_discarding(False)


def main() -> int:
    for fn in (tcp_echo_server, blackhole_server, udp_echo_server, control_server):
        threading.Thread(target=fn, daemon=True).start()
    print(
        f"echo_server: tcp-echo :{TCP_ECHO_PORT} udp-echo :{UDP_ECHO_PORT} "
        f"blackhole :{BLACKHOLE_PORT} control :{CONTROL_PORT}",
        flush=True,
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
