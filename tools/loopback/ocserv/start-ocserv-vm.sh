#!/bin/bash
# fix/nc-openconnect-dp: a REAL ocserv for the OpenConnect loopback test, on a macOS runner (no Docker, no nested
# virtualisation): an Alpine aarch64 cloud image under QEMU TCG, configured by cloud-init (user-data here, served over
# HTTP on 127.0.0.1:$SEED_PORT and announced through SMBIOS — no ISO tooling needed). ocserv's TCP 443 is forwarded to
# 127.0.0.1:$OC_PORT (default 18443) on the host, which the iOS simulator shares.
#
#   start-ocserv-vm.sh start   # boot in the background (returns at once)
#   start-ocserv-vm.sh wait    # block until OCSETUP-READY (or fail with the console tail), default 900 s
#   start-ocserv-vm.sh stop
#
# Works on macOS (brew qemu) and Linux (qemu-system-arm + qemu-efi-aarch64), so it can be checked locally.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${OC_VM_DIR:-/tmp/nc-ocserv}
OC_PORT=${OC_PORT:-18443}
SEED_PORT=${SEED_PORT:-18765}
IMG_URL=${OC_IMG_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.4-aarch64-uefi-cloudinit-r0.qcow2}
IMG=${OC_IMG:-$W/alpine.qcow2}

firmware() {
  for f in "${OC_FIRMWARE:-}" \
           "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-aarch64-code.fd" \
           /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd; do
    [ -n "$f" ] && [ -f "$f" ] && { echo "$f"; return; }
  done
  echo "no aarch64 UEFI firmware found" >&2; exit 1
}

case "${1:-start}" in
start)
  mkdir -p "$W"
  [ -s "$IMG" ] || curl -fsSL --retry 3 -o "$IMG" "$IMG_URL"
  cp "$IMG" "$W/run.qcow2"
  mkdir -p "$W/seed"; cp "$HERE/user-data" "$HERE/meta-data" "$HERE/vendor-data" "$W/seed/"
  : > "$W/console.log"
  (cd "$W/seed" && nohup python3 -m http.server "$SEED_PORT" --bind 127.0.0.1 > "$W/seed-http.log" 2>&1 < /dev/null & echo $! > "$W/seed.pid")
  FW=$(firmware)
  nohup qemu-system-aarch64 -M virt -cpu max -smp "${OC_VM_CPUS:-2}" -m 1024 -accel tcg,thread=multi \
    -bios "$FW" -drive if=virtio,file="$W/run.qcow2" \
    -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${OC_PORT}-:443,hostfwd=udp:127.0.0.1:${OC_PORT}-:443 -device virtio-net-pci,netdev=n0,romfile= \
    -smbios "type=1,serial=ds=nocloud;s=http://10.0.2.2:${SEED_PORT}/" \
    -display none -serial file:"$W/console.log" -monitor none > "$W/qemu.log" 2>&1 < /dev/null &
  echo $! > "$W/qemu.pid"
  echo "ocserv VM booting (pid $(cat "$W/qemu.pid"), firmware $FW); console: $W/console.log"
  ;;
wait)
  T=${2:-900}; S=$(date +%s)
  while :; do
    if grep -a -q "OCSETUP-READY" "$W/console.log" 2>/dev/null; then
      # ocserv answers on the forwarded port once the worker is up
      for i in $(seq 1 30); do
        if python3 - "$OC_PORT" <<'PY'
import socket, ssl, sys
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
s = c.wrap_socket(socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=10), server_hostname="ocserv.test")
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"); print("ocserv:", s.recv(64).split(b"\r\n")[0].decode())
PY
        then echo "ocserv ready after $(( $(date +%s) - S )) s"; exit 0; fi
        sleep 2
      done
      echo "OCSETUP-READY but port $OC_PORT does not answer TLS"; tail -n 60 "$W/console.log"; exit 1
    fi
    if grep -a -q "OCSETUP-FAIL" "$W/console.log" 2>/dev/null || ! kill -0 "$(cat "$W/qemu.pid")" 2>/dev/null; then
      echo "ocserv VM failed"; tail -n 80 "$W/console.log"; cat "$W/qemu.log"; exit 1
    fi
    if [ $(( $(date +%s) - S )) -gt "$T" ]; then echo "ocserv VM not ready after $T s"; tail -n 80 "$W/console.log"; exit 1; fi
    sleep 5
  done
  ;;
stop)
  for p in qemu seed; do [ -f "$W/$p.pid" ] && kill "$(cat "$W/$p.pid")" 2>/dev/null || true; done
  ;;
*) echo "usage: $0 start|wait|stop"; exit 2;;
esac
