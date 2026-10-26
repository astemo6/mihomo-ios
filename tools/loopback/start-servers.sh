#!/bin/bash
# Start / stop the local servers for the NativeCore protocol loopback tests
# (UnitTests/NativeCoreLoopbackTests.swift):
#
#   - sing-box (pinned release) with one inbound per protocol, all on
#     127.0.0.1 — see sing-box-config.json next to this script.
#   - echo_server.py — TCP/UDP echo backends + a blackhole backend for the
#     back-pressure tests.
#
# Usage:
#   tools/loopback/start-servers.sh start   # generate cert+config, launch, wait for readiness
#   tools/loopback/start-servers.sh stop    # kill what start launched
#   tools/loopback/start-servers.sh status  # pid liveness
#
# Environment:
#   SING_BOX_VERSION   pinned sing-box version (default 1.12.24)
#   SING_BOX_BIN       path to an existing sing-box binary (skips the download)
#   NC_LOOPBACK_DIR    runtime dir for binary/config/cert/logs/pids (default /tmp/nc-loopback)
#
# Works on macOS and Linux; the same script is what proto-loopback.yml runs
# on the CI runner and what you run locally before
#   TEST_RUNNER_NC_LOOPBACK=1 xcodebuild test -only-testing:MihomoUnitTests/NativeCoreLoopbackTests …
# (or just run the tests — they probe the SS port and skip when nothing is up).

set -euo pipefail

SING_BOX_VERSION="${SING_BOX_VERSION:-1.12.24}"
DIR="$(cd "$(dirname "$0")" && pwd)"
RUN="${NC_LOOPBACK_DIR:-/tmp/nc-loopback}"
mkdir -p "$RUN/bin"

# stderr, so command substitutions (find_sing_box) only ever capture a path.
log() { printf '%s\n' "[loopback] $*" >&2; }

find_sing_box() {
    if [ -n "${SING_BOX_BIN:-}" ]; then
        printf '%s' "$SING_BOX_BIN"
        return
    fi
    if command -v sing-box >/dev/null 2>&1; then
        command -v sing-box
        return
    fi
    local os arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        arm64|aarch64) arch="arm64" ;;
        x86_64|amd64)  arch="amd64" ;;
        *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    local bin="$RUN/bin/sing-box"
    if [ ! -x "$bin" ]; then
        local name="sing-box-${SING_BOX_VERSION}-${os}-${arch}"
        log "downloading sing-box ${SING_BOX_VERSION} (${os}-${arch})"
        curl -fsSL "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${name}.tar.gz" \
            | tar -xz -C "$RUN/bin" --strip-components=1 "$name/sing-box"
        chmod +x "$bin"
    fi
    printf '%s' "$bin"
}

find_masque_proxy() {
    if [ -n "${MASQUE_PROXY_BIN:-}" ]; then
        printf '%s' "$MASQUE_PROXY_BIN"
        return 0
    fi
    if [ -x "$RUN/bin/masque-proxy" ]; then
        printf '%s' "$RUN/bin/masque-proxy"
        return 0
    fi
    if command -v masque-proxy >/dev/null 2>&1; then
        command -v masque-proxy
        return 0
    fi
    if command -v go >/dev/null 2>&1; then
        log "installing masque-go proxy (RFC 9298, MIT) via go install"
        GOBIN="$RUN/bin" go install github.com/quic-go/masque-go/cmd/proxy@v0.6.0
        if [ -x "$RUN/bin/proxy" ]; then
            mv "$RUN/bin/proxy" "$RUN/bin/masque-proxy"
        fi
        if [ -x "$RUN/bin/masque-proxy" ]; then
            printf '%s' "$RUN/bin/masque-proxy"
            return 0
        fi
    fi
    return 1
}

gen_cert() {
    if [ -f "$RUN/cert.pem" ] && [ -f "$RUN/key.pem" ]; then
        return
    fi
    log "generating self-signed cert (CN=localhost, SAN DNS:localhost IP:127.0.0.1)"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
        -keyout "$RUN/key.pem" -out "$RUN/cert.pem" >/dev/null 2>&1
}

render_config() {
    sed -e "s|__LOOPBACK_DIR__|$RUN|g" "$DIR/sing-box-config.json" > "$RUN/sing-box.json"
}

wait_tcp() {
    local port="$1" tries=0
    while [ $tries -lt 75 ]; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.2
    done
    echo "port $port never became ready" >&2
    return 1
}

alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

do_start() {
    if alive "$RUN/sing-box.pid" && alive "$RUN/echo.pid"; then
        log "already running (sing-box pid $(cat "$RUN/sing-box.pid"), echo pid $(cat "$RUN/echo.pid"))"
        return
    fi
    do_stop >/dev/null 2>&1 || true

    local sb
    sb="$(find_sing_box)"
    gen_cert
    render_config

    log "sing-box check"
    "$sb" check -c "$RUN/sing-box.json"

    log "starting echo_server.py"
    nohup python3 "$DIR/echo_server.py" >"$RUN/echo.log" 2>&1 &
    echo $! > "$RUN/echo.pid"

    log "starting sing-box $("$sb" version | head -n1)"
    nohup "$sb" run -c "$RUN/sing-box.json" >"$RUN/sing-box.log" 2>&1 &
    echo $! > "$RUN/sing-box.pid"

    local masque_bin=""
    if masque_bin="$(find_masque_proxy 2>/dev/null)" && [ -n "$masque_bin" ]; then
        log "starting masque-proxy on port 18012"
        nohup "$masque_bin" \
            -t "https://127.0.0.1:18012/.well-known/masque/udp/{target_host}/{target_port}/" \
            -b "127.0.0.1:18012" \
            -c "$RUN/cert.pem" \
            -k "$RUN/key.pem" >"$RUN/masque.log" 2>&1 &
        echo $! > "$RUN/masque.pid"
        sleep 0.5
        kill -0 "$(cat "$RUN/masque.pid")" 2>/dev/null || log "masque-proxy failed to stay alive"
    else
        log "masque-proxy not found (install go or set MASQUE_PROXY_BIN to enable MASQUE loopback)"
    fi

    # TCP inbounds + backends can be probed directly. The UDP inbounds
    # (hysteria2 / tuic / wireguard / masque) cannot; sing-box is a single process, so
    # TCP readiness + process liveness covers them.
    local p
    for p in 18001 18002 18003 18004 18005 18080 18082; do
        wait_tcp "$p"
    done
    kill -0 "$(cat "$RUN/sing-box.pid")"
    kill -0 "$(cat "$RUN/echo.pid")"
    log "ready: ss :18001 ss2022 :18002 vmess :18003 vless :18004 trojan :18005 hy2 :18006 tuic :18007 wg :18008 masque :18012 echo :18080/:18081 blackhole :18082"
}

do_stop() {
    local f
    for f in "$RUN/sing-box.pid" "$RUN/echo.pid" "$RUN/masque.pid"; do
        if alive "$f"; then
            kill "$(cat "$f")" 2>/dev/null || true
        fi
        rm -f "$f"
    done
    log "stopped"
}

do_status() {
    local rc=0
    for name in sing-box echo masque; do
        if alive "$RUN/$name.pid"; then
            log "$name running (pid $(cat "$RUN/$name.pid"))"
        else
            log "$name not running"
            rc=1
        fi
    done
    return $rc
}

case "${1:-start}" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *) echo "usage: $0 [start|stop|status]" >&2; exit 2 ;;
esac
