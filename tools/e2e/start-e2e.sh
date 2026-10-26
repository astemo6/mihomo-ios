#!/bin/bash
# Tern E2E replay — local server fleet for the sample fixture (all 127.0.0.1):
#   - tools/loopback/start-servers.sh fleet (sing-box :18001-18008, echo :18080-18083) — the subscription nodes
#   - a second sing-box with tools/e2e/sample/sing-box-e2e.json: VMess+ws :18103 (/e2e-ws), Shadowsocks :18101
#   - tools/e2e/e2e_server.py :18480 — resources (sub / rules / modules / scripts) + the HTTP origin (/e2e/*)
# Usage: tools/e2e/start-e2e.sh start|stop|status
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
RUN="${NC_E2E_DIR:-/tmp/nc-e2e}"
mkdir -p "$RUN"
log() { printf '%s\n' "[e2e] $*" >&2; }
alive() { [ -f "$1" ] && kill -0 "$(cat "$1")" 2>/dev/null; }

wait_tcp() {
    local port="$1" tries=0
    while [ $tries -lt 75 ]; do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3>&- 3<&-; return 0; fi
        tries=$((tries + 1)); sleep 0.2
    done
    echo "port $port never became ready" >&2; return 1
}

do_start() {
    "$ROOT/tools/loopback/start-servers.sh" start
    local sb="${SING_BOX_BIN:-${NC_LOOPBACK_DIR:-/tmp/nc-loopback}/bin/sing-box}"
    command -v sing-box >/dev/null 2>&1 && [ ! -x "$sb" ] && sb="$(command -v sing-box)"
    if ! alive "$RUN/sb.pid"; then
        "$sb" check -c "$DIR/sample/sing-box-e2e.json"
        nohup "$sb" run -c "$DIR/sample/sing-box-e2e.json" >"$RUN/sing-box-e2e.log" 2>&1 &
        echo $! > "$RUN/sb.pid"
    fi
    if ! alive "$RUN/http.pid"; then
        nohup python3 "$DIR/e2e_server.py" --root "${E2E_SERVE_ROOT:-$DIR/sample}" >"$RUN/e2e-server.log" 2>&1 &
        echo $! > "$RUN/http.pid"
    fi
    for p in 18101 18103 18480; do wait_tcp "$p"; done
    log "ready: vmess-ws :18103 ss :18101 http :18480 (+ loopback fleet)"
}

do_stop() {
    for f in "$RUN/sb.pid" "$RUN/http.pid"; do alive "$f" && kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
    "$ROOT/tools/loopback/start-servers.sh" stop || true
}

do_status() {
    local rc=0
    for n in sb http; do if alive "$RUN/$n.pid"; then log "$n running"; else log "$n not running"; rc=1; fi; done
    "$ROOT/tools/loopback/start-servers.sh" status || rc=1
    return $rc
}

case "${1:-start}" in
    start) do_start ;;
    stop) do_stop ;;
    status) do_status ;;
    *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
