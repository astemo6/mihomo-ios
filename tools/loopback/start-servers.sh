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
TRUSTTUNNEL_VERSION="${TRUSTTUNNEL_VERSION:-1.1.0}"
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

find_trusttunnel() {
    if [ -n "${TRUSTTUNNEL_BIN:-}" ]; then
        printf '%s' "$TRUSTTUNNEL_BIN"
        return
    fi
    if command -v trusttunnel_endpoint >/dev/null 2>&1; then
        command -v trusttunnel_endpoint
        return
    fi
    local os arch name
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os" in
        darwin)
            name="trusttunnel-v${TRUSTTUNNEL_VERSION}-macos-universal"
            ;;
        linux)
            case "$(uname -m)" in
                arm64|aarch64) arch="aarch64" ;;
                x86_64|amd64)  arch="x86_64" ;;
                *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
            esac
            name="trusttunnel-v${TRUSTTUNNEL_VERSION}-linux-${arch}"
            ;;
        *) echo "unsupported os: $os" >&2; exit 1 ;;
    esac
    local bin="$RUN/bin/trusttunnel_endpoint"
    if [ ! -x "$bin" ]; then
        log "downloading trusttunnel_endpoint ${TRUSTTUNNEL_VERSION} ($name)"
        curl -fsSL "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${TRUSTTUNNEL_VERSION}/${name}.tar.gz" \
            | tar -xz -C "$RUN/bin" --strip-components=1 "$name/trusttunnel_endpoint"
        chmod +x "$bin"
    fi
    printf '%s' "$bin"
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

render_trusttunnel_config() {
    cat << EOF > "$RUN/tt-credentials.toml"
[[client]]
username = "nc-loop-tt-user"
password = "nc-loop-tt-pw"
EOF

    cat << EOF > "$RUN/tt-hosts.toml"
[[main_hosts]]
hostname = "localhost"
cert_chain_path = "$RUN/cert.pem"
private_key_path = "$RUN/key.pem"
EOF

    cat << EOF > "$RUN/tt-settings.toml"
listen_address = "127.0.0.1:18013"
credentials_file = "$RUN/tt-credentials.toml"
allow_private_network_connections = true

[listen_protocols.http2]

[listen_protocols.quic]

[forward_protocol.direct]
EOF
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
    if alive "$RUN/sing-box.pid" && alive "$RUN/echo.pid" && alive "$RUN/trusttunnel.pid"; then
        log "already running (sing-box pid $(cat "$RUN/sing-box.pid"), echo pid $(cat "$RUN/echo.pid"), tt pid $(cat "$RUN/trusttunnel.pid"))"
        return
    fi
    do_stop >/dev/null 2>&1 || true

    local sb tt
    sb="$(find_sing_box)"
    tt="$(find_trusttunnel)"
    gen_cert
    render_config
    render_trusttunnel_config

    log "sing-box check"
    "$sb" check -c "$RUN/sing-box.json"

    log "starting echo_server.py"
    nohup python3 "$DIR/echo_server.py" >"$RUN/echo.log" 2>&1 &
    echo $! > "$RUN/echo.pid"

    log "starting sing-box $("$sb" version | head -n1)"
    nohup "$sb" run -c "$RUN/sing-box.json" >"$RUN/sing-box.log" 2>&1 &
    echo $! > "$RUN/sing-box.pid"

    log "starting trusttunnel_endpoint $("$tt" --version 2>&1 | head -n1)"
    nohup "$tt" "$RUN/tt-settings.toml" "$RUN/tt-hosts.toml" >"$RUN/trusttunnel.log" 2>&1 &
    echo $! > "$RUN/trusttunnel.pid"

    # TCP inbounds + backends can be probed directly. The UDP inbounds
    # (hysteria2 / tuic / wireguard) cannot; sing-box is a single process, so
    # TCP readiness + process liveness covers them.
    local p
    for p in 18001 18002 18003 18004 18005 18013 18080 18082; do
        wait_tcp "$p"
    done
    kill -0 "$(cat "$RUN/sing-box.pid")"
    kill -0 "$(cat "$RUN/echo.pid")"
    kill -0 "$(cat "$RUN/trusttunnel.pid")"
    log "ready: ss :18001 ss2022 :18002 vmess :18003 vless :18004 trojan :18005 hy2 :18006 tuic :18007 wg :18008 tt :18013 echo :18080/:18081 blackhole :18082"
}

do_stop() {
    local f
    for f in "$RUN/sing-box.pid" "$RUN/echo.pid" "$RUN/trusttunnel.pid"; do
        if alive "$f"; then
            kill "$(cat "$f")" 2>/dev/null || true
        fi
        rm -f "$f"
    done
    log "stopped"
}

do_status() {
    local rc=0
    for name in sing-box echo trusttunnel; do
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
