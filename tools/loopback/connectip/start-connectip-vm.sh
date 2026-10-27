#!/bin/bash
# fix/nc-masque-ip: a REAL RFC 9484 CONNECT-IP proxy for the MASQUE CONNECT-IP loopback test, on a macOS runner (no
# Docker, no nested virtualisation): an Alpine aarch64 cloud image under QEMU TCG (same approach as ../ocserv),
# configured by cloud-init (user-data here, served over HTTP on 127.0.0.1:$SEED_PORT and announced through SMBIOS).
#
# The proxy is the upstream connect-ip-go integration proxy (quic-go/connect-ip-go, MIT, integration/proxy) built on
# the runner for linux/arm64 (`build`) and fetched by the VM from the seed server — no proxy source lives in this repo.
# Its QUIC port (UDP 4433 in the VM) is forwarded to 127.0.0.1:$MQ_PORT (default 18446) on the host, which the iOS
# simulator shares. Behind the proxy, in a network namespace reached over a veth pair: 10.89.1.1 with TCP echo :9000,
# UDP echo :9001, DNS :53 (*.mq.test -> 10.89.1.1), HTTP :8080. The client is assigned 10.89.0.2/32, route 10.89.1.0/24.
#
#   start-connectip-vm.sh build   # go build the proxy (needs Go >= 1.26 on the host)
#   start-connectip-vm.sh start   # boot in the background (returns at once)
#   start-connectip-vm.sh wait    # block until MQSETUP-READY (or fail with the console tail), default 900 s
#   start-connectip-vm.sh stop
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${MQ_VM_DIR:-/tmp/nc-mqip}
MQ_PORT=${MQ_PORT:-18446}
SEED_PORT=18766 # fixed: user-data fetches the proxy binary from http://10.0.2.2:18766/
CIP_REV=${CIP_REV:-23c2121ee525c46e1c19a7bb36b87e44f45bff0a}
IMG_URL=${MQ_IMG_URL:-https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/nocloud_alpine-3.22.4-aarch64-uefi-cloudinit-r0.qcow2}
IMG=${MQ_IMG:-$W/alpine.qcow2}

firmware() {
  for f in "${MQ_FIRMWARE:-}" \
           "$(brew --prefix qemu 2>/dev/null)/share/qemu/edk2-aarch64-code.fd" \
           /usr/share/qemu-efi-aarch64/QEMU_EFI.fd /usr/share/AAVMF/AAVMF_CODE.fd; do
    [ -n "$f" ] && [ -f "$f" ] && { echo "$f"; return; }
  done
  echo "no aarch64 UEFI firmware found" >&2; exit 1
}

case "${1:-start}" in
build)
  mkdir -p "$W/seed"
  rm -rf "$W/cip-src"
  git clone -q https://github.com/quic-go/connect-ip-go "$W/cip-src"
  git -C "$W/cip-src" checkout -q "$CIP_REV"
  (cd "$W/cip-src/integration" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -o "$W/seed/cip-proxy" ./proxy)
  ls -l "$W/seed/cip-proxy"
  ;;
start)
  mkdir -p "$W/seed"
  [ -s "$W/seed/cip-proxy" ] || { echo "run '$0 build' first"; exit 1; }
  [ -s "$IMG" ] || curl -fsSL --retry 3 -o "$IMG" "$IMG_URL"
  cp "$IMG" "$W/run.qcow2"
  cp "$HERE/user-data" "$HERE/meta-data" "$HERE/vendor-data" "$W/seed/"
  : > "$W/console.log"
  (cd "$W/seed" && nohup python3 -m http.server "$SEED_PORT" --bind 127.0.0.1 > "$W/seed-http.log" 2>&1 < /dev/null & echo $! > "$W/seed.pid")
  FW=$(firmware)
  nohup qemu-system-aarch64 -M virt -cpu max -smp "${MQ_VM_CPUS:-2}" -m 1024 -accel tcg,thread=multi \
    -bios "$FW" -drive if=virtio,file="$W/run.qcow2" \
    -netdev user,id=n0,hostfwd=udp:127.0.0.1:${MQ_PORT}-:4433 -device virtio-net-pci,netdev=n0,romfile= \
    -smbios "type=1,serial=ds=nocloud;s=http://10.0.2.2:${SEED_PORT}/" \
    -display none -serial file:"$W/console.log" -monitor none > "$W/qemu.log" 2>&1 < /dev/null &
  echo $! > "$W/qemu.pid"
  echo "CONNECT-IP VM booting (pid $(cat "$W/qemu.pid"), firmware $FW); console: $W/console.log"
  ;;
wait)
  T=${2:-900}; S=$(date +%s)
  while :; do
    if grep -a -q "MQSETUP-READY" "$W/console.log" 2>/dev/null; then
      echo "CONNECT-IP proxy ready after $(( $(date +%s) - S )) s"; exit 0
    fi
    if grep -a -q "MQSETUP-FAIL" "$W/console.log" 2>/dev/null || ! kill -0 "$(cat "$W/qemu.pid")" 2>/dev/null; then
      echo "CONNECT-IP VM failed"; tail -n 80 "$W/console.log"; cat "$W/qemu.log"; exit 1
    fi
    if [ $(( $(date +%s) - S )) -gt "$T" ]; then echo "CONNECT-IP VM not ready after $T s"; tail -n 80 "$W/console.log"; exit 1; fi
    sleep 5
  done
  ;;
stop)
  for p in qemu seed; do [ -f "$W/$p.pid" ] && kill "$(cat "$W/$p.pid")" 2>/dev/null || true; done
  ;;
*) echo "usage: $0 build|start|wait|stop"; exit 2;;
esac
