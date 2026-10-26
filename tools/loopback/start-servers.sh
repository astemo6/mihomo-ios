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

# Wire capture of the hysteria2 UDP path (hy2-frag lane): UDP sizes on loopback for the hy2 inbound
# (:18006, client <-> sing-box) and the UDP echo backend (:18081, sing-box <-> echo), so a lost
# datagram can be placed — never sent, sent inside an oversized QUIC packet (> 1452, quic-go's
# receive buffer), or dropped after reassembly. Needs passwordless sudo (GitHub macOS runners have
# it); skipped otherwise. NC_LOOPBACK_WIRE=0 disables it.
start_wire_capture() {
    [ "${NC_LOOPBACK_WIRE:-1}" = 1 ] || return 0
    command -v tcpdump >/dev/null 2>&1 || { log "wire capture skipped (no tcpdump)"; return 0; }
    sudo -n true 2>/dev/null || { log "wire capture skipped (no passwordless sudo)"; return 0; }
    local ifc=lo0
    [ "$(uname -s)" = Linux ] && ifc=lo
    sudo -n tcpdump -i "$ifc" -nn -q -l -s 96 'udp and (port 18006 or port 18081)' \
        >"$RUN/hy2-wire.txt" 2>"$RUN/tcpdump.err" &
    echo $! > "$RUN/tcpdump.pid"
    log "wire capture on $ifc (udp 18006/18081)"
}

stop_wire_capture() {
    [ -f "$RUN/tcpdump.pid" ] || return 0
    sudo -n kill "$(cat "$RUN/tcpdump.pid")" 2>/dev/null || true
    sudo -n pkill -f "tcpdump -i lo.* -nn -q -l -s 96" 2>/dev/null || true
    rm -f "$RUN/tcpdump.pid"
    sleep 1
    [ -s "$RUN/hy2-wire.txt" ] || { log "wire capture empty ($(head -c 300 "$RUN/tcpdump.err" 2>/dev/null))"; return 0; }
    # "hh:mm:ss.us IP 127.0.0.1.51234 > 127.0.0.1.18006: UDP, length 1230"
    awk '
    function port(a) { sub(/:$/, "", a); n = split(a, p, "."); return p[n] }
    function bucket(l) { return l <= 1200 ? "le1200" : l <= 1300 ? "le1300" : l <= 1452 ? "le1452" : l <= 2000 ? "le2000" : "gt2000" }
    / > / && /length/ {
        src = port($3); dst = port($5); len = $NF + 0
        if (dst == 18006) k = "c2s"; else if (src == 18006) k = "s2c"; else if (dst == 18081) k = "toEcho"; else if (src == 18081) k = "fromEcho"; else next
        cnt[k]++; if (len > mx[k]) mx[k] = len; if (len > 1452) over[k]++
        b[k "," bucket(len)]++
        if (k == "c2s") ports[src]++
        if (k == "c2s" && len > 900) { if (seqn[k] < 400) { seq[k] = seq[k] " " len "@" src; seqn[k]++ } }
        else if (k == "toEcho") { if (seqn[k] < 400) { seq[k] = seq[k] " " len; seqn[k]++ } }
    }
    END {
        split("c2s s2c toEcho fromEcho", ks, " ")
        for (i = 1; i <= 4; i++) {
            k = ks[i]
            printf "HY2WIRE %s n=%d max=%d over1452=%d le1200=%d le1300=%d le1452=%d le2000=%d gt2000=%d\n", k, cnt[k], mx[k], over[k], b[k ",le1200"], b[k ",le1300"], b[k ",le1452"], b[k ",le2000"], b[k ",gt2000"]
        }
        pl = ""; for (q in ports) pl = pl " " q "=" ports[q]
        printf "HY2WIRE c2s srcports:%s\n", pl
        printf "HY2WIRE c2s>900 seq:%s\n", seq["c2s"]
        printf "HY2WIRE toEcho seq:%s\n", seq["toEcho"]
    }' "$RUN/hy2-wire.txt" >&2
}

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

    start_wire_capture

    log "starting echo_server.py"
    nohup python3 "$DIR/echo_server.py" >"$RUN/echo.log" 2>&1 &
    echo $! > "$RUN/echo.pid"

    log "starting sing-box $("$sb" version | head -n1)"
    # NC_LOOPBACK_QUIC_DEBUG=1 (default): quic-go per-packet debug log into sing-box.log, summarised by
    # `stop` (hy2-frag: which received QUIC packets / DATAGRAM frames the server drops, and why).
    if [ "${NC_LOOPBACK_QUIC_DEBUG:-1}" = 1 ]; then
        QUIC_GO_LOG_LEVEL=debug nohup "$sb" run -c "$RUN/sing-box.json" >"$RUN/sing-box.log" 2>&1 &
    else
        nohup "$sb" run -c "$RUN/sing-box.json" >"$RUN/sing-box.log" 2>&1 &
    fi
    echo $! > "$RUN/sing-box.pid"

    # TCP inbounds + backends can be probed directly. The UDP inbounds
    # (hysteria2 / tuic / wireguard) cannot; sing-box is a single process, so
    # TCP readiness + process liveness covers them.
    local p
    for p in 18001 18002 18003 18004 18005 18080 18082; do
        wait_tcp "$p"
    done
    kill -0 "$(cat "$RUN/sing-box.pid")"
    kill -0 "$(cat "$RUN/echo.pid")"
    start_hy2_ref_client "$sb"
    log "ready: ss :18001 ss2022 :18002 vmess :18003 vless :18004 trojan :18005 hy2 :18006 tuic :18007 wg :18008 echo :18080/:18081 blackhole :18082"
}

# hy2-frag: sing-box's own hysteria2 client as a reference (socks :19080 -> hy2-in), probed by
# hy2_ref_probe.py at start and at stop. NC_LOOPBACK_HY2REF=0 disables.
start_hy2_ref_client() {
    [ "${NC_LOOPBACK_HY2REF:-1}" = 1 ] || return 0
    cat > "$RUN/hy2-ref-client.json" <<JSON
{"log":{"level":"warn"},"inbounds":[{"type":"socks","tag":"s","listen":"127.0.0.1","listen_port":19080}],
 "outbounds":[{"type":"hysteria2","tag":"hy","server":"127.0.0.1","server_port":18006,"password":"nc-loop-hy2-pw",
   "tls":{"enabled":true,"server_name":"localhost","insecure":true}}],"route":{"final":"hy"}}
JSON
    nohup "$1" run -c "$RUN/hy2-ref-client.json" >"$RUN/hy2-ref-client.log" 2>&1 &
    echo $! > "$RUN/hy2ref.pid"
    sleep 1
    python3 "$DIR/hy2_ref_probe.py" >&2 || true
}

stop_hy2_ref_client() {
    [ -f "$RUN/hy2ref.pid" ] || return 0
    python3 "$DIR/hy2_ref_probe.py" >&2 || true
    kill "$(cat "$RUN/hy2ref.pid")" 2>/dev/null || true
    rm -f "$RUN/hy2ref.pid"
}

quic_debug_summary() {
    [ -s "$RUN/sing-box.log" ] || return 0
    grep -q "Reading packet" "$RUN/sing-box.log" || return 0
    awk '
    /Reading packet [0-9]+ \([0-9]+ bytes\) for connection/ {
        match($0, /Reading packet [0-9]+ \([0-9]+ bytes\) for connection [0-9a-f]+, [^ ]+/)
        split(substr($0, RSTART, RLENGTH), w, " ")
        pn = w[3]; sz = w[4]; gsub(/\(/, "", sz); cid = w[8]; gsub(/,/, "", cid); lvl = w[9]
        reads++; lastpn = pn; lastsz = sz; lastcid = substr(cid, 1, 8)
        if (lvl == "1-RTT" && sz + 0 > 900 && nseq < 500) { seq = seq " " lastcid ":" pn ":" sz; nseq++ }
        next
    }
    /<- &wire.DatagramFrame/ { dg++; if (ndg < 400) { m = $0; sub(/.*Length: /, "", m); sub(/}.*/, "", m); dgs = dgs " " lastpn ":" m; ndg++ } next }
    /Dropping|Discarding|undecryptable|unknown connection|tateless|Queueing|later decryption|Error|error/ {
        drops++
        if (nd < 60) { l = $0; sub(/^.*(server|client) /, "", l); dl[++nd] = "after pn " lastpn " (" lastsz " B) " lastcid ": " substr(l, 1, 160) }
    }
    END {
        printf "QUICDBG reads=%d datagramFrames=%d dropLines=%d\n", reads, dg, drops
        printf "QUICDBG 1rtt>900 cid:pn:size:%s\n", seq
        printf "QUICDBG datagrams pn:len:%s\n", dgs
        for (i = 1; i <= nd; i++) printf "QUICDBG drop %s\n", dl[i]
    }' "$RUN/sing-box.log" >&2
}

do_stop() {
    local f
    stop_hy2_ref_client
    stop_wire_capture
    quic_debug_summary
    for f in "$RUN/sing-box.pid" "$RUN/echo.pid"; do
        if alive "$f"; then
            kill "$(cat "$f")" 2>/dev/null || true
        fi
        rm -f "$f"
    done
    log "stopped"
}

do_status() {
    local rc=0
    for name in sing-box echo; do
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
