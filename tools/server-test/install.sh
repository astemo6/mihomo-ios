#!/usr/bin/env bash
# Tern 服务器自测工具包 (tools/server-test/install.sh)
#
# 在一台 Debian 12 / Ubuntu 22.04 / 24.04 (x86_64 / arm64, root, 公网 IP) 的 VPS 上，一键装好 Tern 支持的各协议
# 的参考服务端（每个都是 systemd 服务），生成随机凭据，开防火墙端口，并打印可直接导入 Tern 的节点
# （分享链接 / Surge 行 / Clash YAML 片段 + 终端二维码 + 一个包含全部节点的订阅地址）。
#
#   bash install.sh                       # 装全部协议（自签证书）
#   bash install.sh --only ss,vless-reality,hysteria2
#   bash install.sh --skip awg,masque-ip  # 跳过某些协议
#   bash install.sh --domain auto         # 用 <ip>.sslip.io + Let's Encrypt 证书（需 80/tcp 可达）
#   bash install.sh --domain vpn.example.com --email me@example.com
#   bash install.sh --show                # 重新打印端口表、节点与二维码
#   bash install.sh --uninstall           # 卸载全部（服务、文件、防火墙规则、本工具装的软件包）
#   bash install.sh --list                # 列出协议 id
#
# 可重复执行（幂等）：凭据保存在 /root/tern-test/state.json，重跑会沿用；未选中的协议的服务会被停掉并移除。
set -Eeuo pipefail
umask 022

KIT_VERSION="1.0.0"
BASE="${TT_BASE:-/opt/tern-test}"
STATE="${TT_STATE:-/root/tern-test}"
PORT_BASE="${TT_PORT_BASE:-24000}"

# ---- pinned upstream versions (server software only; nothing here is part of the app) ----
SING_BOX_VERSION="1.12.24"        # same as tools/loopback/start-servers.sh (CI interop)
XRAY_VERSION="26.10.21"
SSRUST_VERSION="1.25.0"
SUDOKU_VERSION="0.5.2.0"          # same as tools/loopback (docs/nc-proto-sudoku.md §2.6)
TRUSTTUNNEL_VERSION="1.1.0"       # same as tools/loopback
SNELL4_VERSION="4.1.1"
SNELL5_VERSION="5.0.1"
MIERU_VERSION="3.39.0"
BROOK_VERSION="20270101"
JUICITY_VERSION="0.5.0"
GOST_VERSION="3.3.1"
CLOAK_VERSION="2.12.0"
RESTLS_VERSION="0.1.1"
SSR_COMMIT="fd723a92c488d202b407323f0512987346944136"   # shadowsocksrr/shadowsocksr manyuser
GO_VERSION="1.26.10"
CIP_REV="23c2121ee525c46e1c19a7bb36b87e44f45bff0a"      # same as tools/loopback/connectip
MASQUE_GO_VERSION="0.6.0"                               # same as tools/loopback/start-servers.sh
AWG_GO_VERSION="3.1.20260828"
AWG_TOOLS_VERSION="3.1.20260812"

ALL_PROTOS="socks http https ss ss2022 ss-shadowtls vmess vmess-ws vless vless-reality vless-vision vless-enc trojan hysteria hysteria2 tuic anytls naive ss-obfs ss-v2ray ss-kcptun ss-cloak ss-restls ssr snell4 snell5 mieru ssh brook gost-relay juicity wireguard awg openconnect trusttunnel sudoku masque-ip masque-udp"

log()  { printf '\033[1;36m[tern-test]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[tern-test] 警告:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[tern-test] 错误:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    printf '%s\n' "Tern 服务器自测工具包 v$KIT_VERSION" \
        "用法: bash install.sh [--only id,id] [--skip id,id] [--domain 域名|auto] [--email 邮箱] [--ip 公网IP]" \
        "                      [--port-base 24000] [--no-firewall] | --show | --uninstall | --list" \
        "协议 id: $ALL_PROTOS"
}

# ------------------------------------------------------------------------------------------------ args
ONLY=""; SKIP=""; DOMAIN=""; EMAIL=""; IP=""; ACTION="install"; RENDER_DIR=""; NO_FW=0
while [ $# -gt 0 ]; do
    case "$1" in
        --only) ONLY="${2:-}"; shift ;;
        --only=*) ONLY="${1#*=}" ;;
        --skip) SKIP="${2:-}"; shift ;;
        --skip=*) SKIP="${1#*=}" ;;
        --domain) DOMAIN="${2:-}"; shift ;;
        --domain=*) DOMAIN="${1#*=}" ;;
        --email) EMAIL="${2:-}"; shift ;;
        --email=*) EMAIL="${1#*=}" ;;
        --ip) IP="${2:-}"; shift ;;
        --ip=*) IP="${1#*=}" ;;
        --port-base) PORT_BASE="${2:-}"; shift ;;
        --no-firewall) NO_FW=1 ;;
        --show|show) ACTION="show" ;;
        --uninstall|uninstall|/uninstall) ACTION="uninstall" ;;
        --list) echo "$ALL_PROTOS" | tr ' ' '\n'; exit 0 ;;
        --render-only) ACTION="render"; RENDER_DIR="${2:-}"; shift ;;   # dev: render configs into a dir, no root
        -h|--help) usage; exit 0 ;;
        *) die "未知参数 $1（--help 查看用法）" ;;
    esac
    shift
done

select_protos() {
    local p sel=""
    if [ -n "$ONLY" ]; then
        for p in ${ONLY//,/ }; do
            case " $ALL_PROTOS " in *" $p "*) sel="$sel $p" ;; *) die "未知协议 id: $p（--list 查看）" ;; esac
        done
    else
        sel="$ALL_PROTOS"
    fi
    if [ -n "$SKIP" ]; then
        for p in ${SKIP//,/ }; do
            case " $ALL_PROTOS " in *" $p "*) ;; *) die "未知协议 id: $p（--list 查看）" ;; esac
            sel="$(echo " $sel " | sed "s/ $p / /g")"
        done
    fi
    # shellcheck disable=SC2086
    echo $sel
}
PROTOS="$(select_protos)"
want() { case " $PROTOS " in *" $1 "*) return 0 ;; esac; return 1; }
want_any() { local p; for p in "$@"; do want "$p" && return 0; done; return 1; }

# ------------------------------------------------------------------------------------------------ system
OS_ID=""; OS_VER=""; ARCH=""
detect_os() {
    [ -r /etc/os-release ] || die "找不到 /etc/os-release"
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"
    case "$OS_ID:$OS_VER" in
        debian:12|ubuntu:22.04|ubuntu:24.04) log "系统：$PRETTY_NAME" ;;
        debian:*|ubuntu:*) warn "未测试的版本 $PRETTY_NAME，继续尝试（只支持 Debian 12 / Ubuntu 22.04 / 24.04）" ;;
        *) case " ${ID_LIKE:-} " in
               *" debian "*) warn "非 Debian/Ubuntu（$PRETTY_NAME），继续尝试" ;;
               *) die "只支持 Debian 12 / Ubuntu 22.04 / 24.04（当前 ${PRETTY_NAME:-unknown}）" ;;
           esac ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) die "不支持的架构 $(uname -m)（只支持 x86_64 / arm64）" ;;
    esac
}

detect_ip() {
    [ -n "$IP" ] && return
    IP="$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    [ -n "$IP" ] || IP="$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)"
    [ -n "$IP" ] || IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    [ -n "$IP" ] || die "无法探测公网 IPv4，请用 --ip 指定"
    log "公网 IP：$IP"
}

APT_UPDATED=0
apt_install() {
    local p missing=()
    for p in "$@"; do
        dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed" || missing+=("$p")
    done
    [ ${#missing[@]} -eq 0 ] && return 0
    if [ $APT_UPDATED = 0 ]; then
        log "apt-get update"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        APT_UPDATED=1
    fi
    log "apt 安装：${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${missing[@]}" >/dev/null
    mkdir -p "$BASE/var"
    printf '%s\n' "${missing[@]}" >> "$BASE/var/apt-installed"
}

ensure_universe() {
    [ "$OS_ID" = ubuntu ] || return 0
    local pol; pol="$(apt-cache policy simple-obfs 2>/dev/null || true)"
    if [[ $pol != *"Candidate: "[0-9]* ]]; then
        log "启用 Ubuntu universe 仓库"
        apt_install software-properties-common
        add-apt-repository -y universe >/dev/null
        APT_UPDATED=0
    fi
}

fetch() {  # fetch URL OUTFILE
    log "下载 $1"
    curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 -sS -o "$2" "$1" || die "下载失败：$1"
}

# install_bin NAME VERSION — skip when $BASE/bin/.ver-NAME already says VERSION
have_ver() { [ -f "$BASE/bin/.ver-$1" ] && [ "$(cat "$BASE/bin/.ver-$1")" = "$2" ]; }
mark_ver() { echo "$2" > "$BASE/bin/.ver-$1"; }

# ------------------------------------------------------------------------------------------------ downloads
u_singbox() { echo "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-${ARCH}.tar.gz"; }
u_xray() { local a=64; [ "$ARCH" = arm64 ] && a=arm64-v8a; echo "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-${a}.zip"; }
u_ssrust() { local a=x86_64; [ "$ARCH" = arm64 ] && a=aarch64; echo "https://github.com/shadowsocks/shadowsocks-rust/releases/download/v${SSRUST_VERSION}/shadowsocks-v${SSRUST_VERSION}.${a}-unknown-linux-gnu.tar.xz"; }
u_sudoku() { echo "https://github.com/SUDOKU-ASCII/sudoku/releases/download/v${SUDOKU_VERSION}/sudoku-linux-${ARCH}.tar.gz"; }
u_tt() { local a=x86_64; [ "$ARCH" = arm64 ] && a=aarch64; echo "https://github.com/TrustTunnel/TrustTunnel/releases/download/v${TRUSTTUNNEL_VERSION}/trusttunnel-v${TRUSTTUNNEL_VERSION}-linux-${a}.tar.gz"; }
u_snell() { local a=amd64; [ "$ARCH" = arm64 ] && a=aarch64; echo "https://dl.nssurge.com/snell/snell-server-v${1}-linux-${a}.zip"; }
u_mita() { echo "https://github.com/enfein/mieru/releases/download/v${MIERU_VERSION}/mita_${MIERU_VERSION}_${ARCH}.deb"; }
u_brook() { echo "https://github.com/txthinking/brook/releases/download/v${BROOK_VERSION}/brook_linux_${ARCH}"; }
u_juicity() { local a=x86_64; [ "$ARCH" = arm64 ] && a=arm64; echo "https://github.com/juicity/juicity/releases/download/v${JUICITY_VERSION}/juicity-linux-${a}.zip"; }
u_gost() { echo "https://github.com/go-gost/gost/releases/download/v${GOST_VERSION}/gost_${GOST_VERSION}_linux_${ARCH}.tar.gz"; }
u_cloak() { echo "https://github.com/cbeuw/Cloak/releases/download/v${CLOAK_VERSION}/ck-server-linux-${ARCH}-v${CLOAK_VERSION}"; }
u_restls() { local a=x86_64; [ "$ARCH" = arm64 ] && a=aarch64; echo "https://github.com/3andne/restls/releases/download/v${RESTLS_VERSION}/restls-${a}-unknown-linux-musl"; }
u_ssr() { echo "https://codeload.github.com/shadowsocksrr/shadowsocksr/tar.gz/${SSR_COMMIT}"; }
u_go() { echo "https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz"; }
u_cip() { echo "https://codeload.github.com/quic-go/connect-ip-go/tar.gz/${CIP_REV}"; }
u_masque() { echo "https://codeload.github.com/quic-go/masque-go/tar.gz/refs/tags/v${MASQUE_GO_VERSION}"; }
u_awggo() { echo "https://codeload.github.com/amnezia-vpn/amneziawg-go/tar.gz/refs/tags/v${AWG_GO_VERSION}"; }
u_awgtools() { echo "https://codeload.github.com/amnezia-vpn/amneziawg-tools/tar.gz/refs/tags/v${AWG_TOOLS_VERSION}"; }

unzip_one() {  # unzip_one ZIP MEMBER OUT
    python3 - "$1" "$2" "$3" <<'PY'
import sys, zipfile, shutil
with zipfile.ZipFile(sys.argv[1]) as z, z.open(sys.argv[2]) as src, open(sys.argv[3], "wb") as dst:
    shutil.copyfileobj(src, dst)
PY
    chmod 755 "$3"
}

install_binaries() {
    local t; t="$(mktemp -d)"
    mkdir -p "$BASE/bin"
    if want_any socks http https ss ss2022 ss-shadowtls vmess vmess-ws vless vless-reality vless-vision trojan \
            hysteria hysteria2 tuic anytls naive ss-kcptun ss-cloak ss-restls && ! have_ver sing-box "$SING_BOX_VERSION"; then
        fetch "$(u_singbox)" "$t/sb.tgz"
        tar -xzf "$t/sb.tgz" -C "$t" && install -m 755 "$t/sing-box-${SING_BOX_VERSION}-linux-${ARCH}/sing-box" "$BASE/bin/sing-box"
        mark_ver sing-box "$SING_BOX_VERSION"
    fi
    if want vless-enc && ! have_ver xray "$XRAY_VERSION"; then
        fetch "$(u_xray)" "$t/xray.zip"; unzip_one "$t/xray.zip" xray "$BASE/bin/xray"; mark_ver xray "$XRAY_VERSION"
    fi
    if want_any ss-obfs ss-v2ray && ! have_ver ssserver "$SSRUST_VERSION"; then
        fetch "$(u_ssrust)" "$t/ss.txz"; tar -xJf "$t/ss.txz" -C "$t" ssserver
        install -m 755 "$t/ssserver" "$BASE/bin/ssserver"; mark_ver ssserver "$SSRUST_VERSION"
    fi
    if want sudoku && ! have_ver sudoku "$SUDOKU_VERSION"; then
        fetch "$(u_sudoku)" "$t/sudoku.tgz"; tar -xzf "$t/sudoku.tgz" -C "$t" sudoku
        install -m 755 "$t/sudoku" "$BASE/bin/sudoku"; mark_ver sudoku "$SUDOKU_VERSION"
    fi
    if want trusttunnel && ! have_ver trusttunnel "$TRUSTTUNNEL_VERSION"; then
        fetch "$(u_tt)" "$t/tt.tgz"; tar -xzf "$t/tt.tgz" -C "$t"
        install -m 755 "$(find "$t" -name trusttunnel_endpoint -type f | head -n1)" "$BASE/bin/trusttunnel_endpoint"
        mark_ver trusttunnel "$TRUSTTUNNEL_VERSION"
    fi
    local v
    for v in 4 5; do
        local ver="$SNELL4_VERSION"; [ $v = 5 ] && ver="$SNELL5_VERSION"
        if want "snell$v" && ! have_ver "snell$v" "$ver"; then
            fetch "$(u_snell "$ver")" "$t/snell$v.zip"; unzip_one "$t/snell$v.zip" snell-server "$BASE/bin/snell-server-v$v"
            mark_ver "snell$v" "$ver"
        fi
    done
    if want brook && ! have_ver brook "$BROOK_VERSION"; then
        fetch "$(u_brook)" "$BASE/bin/brook"; chmod 755 "$BASE/bin/brook"; mark_ver brook "$BROOK_VERSION"
    fi
    if want juicity && ! have_ver juicity "$JUICITY_VERSION"; then
        fetch "$(u_juicity)" "$t/j.zip"; unzip_one "$t/j.zip" juicity-server "$BASE/bin/juicity-server"; mark_ver juicity "$JUICITY_VERSION"
    fi
    if want gost-relay && ! have_ver gost "$GOST_VERSION"; then
        fetch "$(u_gost)" "$t/gost.tgz"; tar -xzf "$t/gost.tgz" -C "$t" gost
        install -m 755 "$t/gost" "$BASE/bin/gost"; mark_ver gost "$GOST_VERSION"
    fi
    if want ss-cloak && ! have_ver ck-server "$CLOAK_VERSION"; then
        fetch "$(u_cloak)" "$BASE/bin/ck-server"; chmod 755 "$BASE/bin/ck-server"; mark_ver ck-server "$CLOAK_VERSION"
    fi
    if want ss-restls && ! have_ver restls "$RESTLS_VERSION"; then
        fetch "$(u_restls)" "$BASE/bin/restls"; chmod 755 "$BASE/bin/restls"; mark_ver restls "$RESTLS_VERSION"
    fi
    if want ssr && ! have_ver ssr "$SSR_COMMIT"; then
        fetch "$(u_ssr)" "$t/ssr.tgz"; rm -rf "$BASE/ssr"; mkdir -p "$BASE/ssr"
        tar -xzf "$t/ssr.tgz" -C "$BASE/ssr" --strip-components=1
        # Python 3.10+: collections.MutableMapping moved to collections.abc (the upstream code predates it)
        { grep -rl "collections.MutableMapping" "$BASE/ssr/shadowsocks" || true; } | while read -r f; do
            sed -i -e 's/collections\.MutableMapping/collections.abc.MutableMapping/g' \
                   -e 's/^import collections$/import collections\nimport collections.abc/' "$f"
        done
        mark_ver ssr "$SSR_COMMIT"
    fi
    if want mieru && ! have_ver mita "$MIERU_VERSION"; then
        fetch "$(u_mita)" "$t/mita.deb"
        if ! dpkg-query -W -f='${Status}' mita 2>/dev/null | grep -q "install ok installed"; then
            mkdir -p "$BASE/var"; echo mita >> "$BASE/var/apt-installed"
        fi
        DEBIAN_FRONTEND=noninteractive dpkg -i "$t/mita.deb" >/dev/null
        mark_ver mita "$MIERU_VERSION"
    fi
    rm -rf "$t"
}

# Go is only used to build server software on this VPS (connect-ip-go, masque-go, amneziawg-go).
gobuild_env() {
    export PATH="$BASE/go/bin:$PATH" GOPATH="$BASE/gobuild/gopath" GOCACHE="$BASE/gobuild/cache" \
        GOMODCACHE="$BASE/gobuild/gopath/pkg/mod" GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-trimpath
}
install_go() {
    have_ver go "$GO_VERSION" && return 0
    local t; t="$(mktemp -d)"
    fetch "$(u_go)" "$t/go.tgz"; rm -rf "$BASE/go"; tar -xzf "$t/go.tgz" -C "$BASE"; rm -rf "$t"
    mark_ver go "$GO_VERSION"
}
build_go_servers() {
    want_any masque-ip masque-udp awg || return 0
    install_go; gobuild_env
    local t; t="$(mktemp -d)"
    if want masque-ip && ! have_ver cip-proxy "$CIP_REV"; then
        fetch "$(u_cip)" "$t/cip.tgz"; mkdir -p "$t/cip"; tar -xzf "$t/cip.tgz" -C "$t/cip" --strip-components=1
        log "go build connect-ip-go integration proxy ($CIP_REV)"
        (cd "$t/cip/integration" && go build -o "$BASE/bin/cip-proxy" ./proxy) || die "connect-ip-go 编译失败"
        mark_ver cip-proxy "$CIP_REV"
    fi
    if want masque-udp && ! have_ver masque-proxy "$MASQUE_GO_VERSION"; then
        fetch "$(u_masque)" "$t/mq.tgz"; mkdir -p "$t/mq"; tar -xzf "$t/mq.tgz" -C "$t/mq" --strip-components=1
        log "go build masque-go proxy v$MASQUE_GO_VERSION"
        (cd "$t/mq" && go build -o "$BASE/bin/masque-proxy" ./cmd/proxy) || die "masque-go 编译失败"
        mark_ver masque-proxy "$MASQUE_GO_VERSION"
    fi
    if want awg && ! have_ver awg "$AWG_GO_VERSION-$AWG_TOOLS_VERSION"; then
        apt_install build-essential
        fetch "$(u_awggo)" "$t/awggo.tgz"; mkdir -p "$t/awggo"; tar -xzf "$t/awggo.tgz" -C "$t/awggo" --strip-components=1
        fetch "$(u_awgtools)" "$t/awgt.tgz"; mkdir -p "$t/awgt"; tar -xzf "$t/awgt.tgz" -C "$t/awgt" --strip-components=1
        mkdir -p "$BASE/awg/bin"
        log "go build amneziawg-go v$AWG_GO_VERSION"
        (cd "$t/awggo" && go build -o "$BASE/awg/bin/amneziawg-go" .) || die "amneziawg-go 编译失败"
        log "make amneziawg-tools v$AWG_TOOLS_VERSION"
        make -s -C "$t/awgt/src" >/dev/null || die "amneziawg-tools 编译失败"
        make -s -C "$t/awgt/src" install PREFIX="$BASE/awg" BINDIR="$BASE/awg/bin" MANDIR="$BASE/awg/man" \
            WITH_WGQUICK=yes WITH_SYSTEMDUNITS=no WITH_BASHCOMPLETION=no >/dev/null || die "amneziawg-tools 安装失败"
        mark_ver awg "$AWG_GO_VERSION-$AWG_TOOLS_VERSION"
    fi
    rm -rf "$t"
}

# ------------------------------------------------------------------------------------------------ certificate
CERT_SHA256=""
setup_cert() {
    mkdir -p "$BASE/certs"; chmod 700 "$BASE/certs"
    if [ -n "$DOMAIN" ]; then
        [ "$DOMAIN" = auto ] && DOMAIN="${IP//./-}.sslip.io"
        apt_install certbot
        if [ ! -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
            log "申请 Let's Encrypt 证书：$DOMAIN（standalone，需 80/tcp 可从公网访问）"
            open_port_now 80 tcp
            local em=(--register-unsafely-without-email); [ -n "$EMAIL" ] && em=(-m "$EMAIL")
            certbot certonly --standalone --non-interactive --agree-tos "${em[@]}" -d "$DOMAIN" \
                || die "证书申请失败（80/tcp 被占用或被云防火墙挡住？）。可去掉 --domain 用自签证书。"
            echo "$DOMAIN" > "$BASE/var/certbot-domain"
        fi
        install -m 600 "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$BASE/certs/cert.pem"
        install -m 600 "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$BASE/certs/key.pem"
        mkdir -p /etc/letsencrypt/renewal-hooks/deploy
        cat > /etc/letsencrypt/renewal-hooks/deploy/tern-test.sh <<EOF
#!/bin/sh
# Tern self-test: copy the renewed certificate and restart the services that use it.
[ "\$RENEWED_DOMAINS" = "$DOMAIN" ] || exit 0
install -m 600 "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$BASE/certs/cert.pem"
install -m 600 "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$BASE/certs/key.pem"
systemctl try-restart 'tern-*.service'
EOF
        chmod 755 /etc/letsencrypt/renewal-hooks/deploy/tern-test.sh
    else
        local cn="tern.test"
        local txt=""; [ -s "$BASE/certs/cert.pem" ] && txt="$(openssl x509 -in "$BASE/certs/cert.pem" -noout -text 2>/dev/null || true)"
        if [[ $txt != *"IP Address:$IP"* ]]; then
            log "生成自签证书（CN=$cn, SAN DNS:$cn, DNS:proxy, IP:$IP）"
            openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$cn" \
                -addext "subjectAltName=DNS:$cn,DNS:proxy,IP:$IP" \
                -keyout "$BASE/certs/key.pem" -out "$BASE/certs/cert.pem" >/dev/null 2>&1
            chmod 600 "$BASE/certs/key.pem" "$BASE/certs/cert.pem"
        fi
    fi
    CERT_SHA256="$(openssl x509 -in "$BASE/certs/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
}

# ------------------------------------------------------------------------------------------------ firewall / net
ufw_active() {
    command -v ufw >/dev/null 2>&1 || return 1
    local s; s="$(ufw status 2>/dev/null || true)"
    [[ $s == *"Status: active"* ]]
}
open_port_now() {  # used before net.sh exists (ACME challenge)
    [ "$NO_FW" = 1 ] && return 0
    if ufw_active; then
        ufw allow "$1/$2" comment tern-test >/dev/null && echo "$1/$2" >> "$BASE/var/ufw-rules"
    else
        iptables -C INPUT -p "$2" --dport "$1" -j ACCEPT -m comment --comment tern-test 2>/dev/null \
            || iptables -I INPUT -p "$2" --dport "$1" -j ACCEPT -m comment --comment tern-test
    fi
}

write_net_sh() {
    cat > "$BASE/net.sh" <<'NETSH'
#!/bin/bash
# Tern self-test network helper (tern-net.service): INPUT accepts (when ufw is not active), NAT + forwarding for the
# L3 tunnels (ocserv / WireGuard / AmneziaWG / CONNECT-IP), and the CONNECT-IP network namespace. Every iptables rule
# carries the comment "tern-test", so `down` removes exactly what `up` added.
set -u
BASE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck disable=SC1091
. "$BASE/net.env"
TAG=tern-test
WAN="$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"

del_tagged() {  # del_tagged CMD TABLE
    local cmd=$1 table=$2 rule
    command -v "$cmd" >/dev/null 2>&1 || return 0
    "$cmd" -w -t "$table" -S 2>/dev/null | grep -- "--comment $TAG" | sed 's/^-A /-D /' | while read -r rule; do
        # shellcheck disable=SC2086
        "$cmd" -w -t "$table" $rule 2>/dev/null
    done
}

cip_down() {
    ip rule del from 10.89.1.2 lookup 189 2>/dev/null
    ip route flush table 189 2>/dev/null
    ip route del 10.89.0.0/24 via 10.89.2.2 2>/dev/null
    ip netns del terncip 2>/dev/null
    ip link del tcip0 2>/dev/null
    ip link del tcip3 2>/dev/null
    return 0
}

cip_up() {
    cip_down
    ip netns add terncip
    ip link add tcip0 type veth peer name tcip1
    ip link set tcip1 netns terncip
    ip addr add 10.89.1.2/24 dev tcip0
    ip link set tcip0 up
    ip link add tcip3 type veth peer name tcip2
    ip link set tcip2 netns terncip
    ip addr add 10.89.2.1/30 dev tcip3
    ip link set tcip3 up
    ip -n terncip link set lo up
    ip -n terncip addr add 10.89.1.1/24 dev tcip1
    ip -n terncip link set tcip1 up
    ip -n terncip addr add 10.89.2.2/30 dev tcip2
    ip -n terncip link set tcip2 up
    ip -n terncip route add default via 10.89.2.1
    ip -n terncip route add 10.89.0.0/24 via 10.89.1.2 dev tcip1
    ip netns exec terncip sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 \
        net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.tcip1.rp_filter=0 net.ipv4.conf.tcip2.rp_filter=0
    sysctl -qw net.ipv4.conf.tcip0.rp_filter=0 net.ipv4.conf.tcip3.rp_filter=0
    if command -v ethtool >/dev/null 2>&1; then
        ethtool -K tcip0 tx off rx off >/dev/null 2>&1
        ip netns exec terncip ethtool -K tcip1 tx off rx off >/dev/null 2>&1
    fi
    # client packets (raw socket bound to 10.89.1.2) -> netns -> back to the host -> NAT out of $WAN;
    # replies -> netns -> tcip0, where the proxy captures them (AF_PACKET) — the host itself must not route them.
    ip route add 10.89.0.0/24 via 10.89.2.2 dev tcip3
    ip rule add from 10.89.1.2 lookup 189 priority 189
    ip route add default via 10.89.1.1 dev tcip0 table 189
    iptables -w -t raw -I PREROUTING -i tcip0 -j DROP -m comment --comment $TAG
}

up() {
    down_rules
    local p
    if ! { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; } && [ "${TT_NO_FW:-0}" != 1 ]; then
        for p in $TT_PORTS; do
            iptables -w -I INPUT -p "${p#*/}" --dport "${p%/*}" -j ACCEPT -m comment --comment $TAG
            command -v ip6tables >/dev/null 2>&1 && ip6tables -w -I INPUT -p "${p#*/}" --dport "${p%/*}" -j ACCEPT -m comment --comment $TAG 2>/dev/null
        done
    fi
    if [ -n "$TT_NAT_NETS" ]; then
        [ -f "$BASE/var/ip_forward.prev" ] || cat /proc/sys/net/ipv4/ip_forward > "$BASE/var/ip_forward.prev"
        sysctl -qw net.ipv4.ip_forward=1
        for p in $TT_NAT_NETS; do
            iptables -w -t nat -A POSTROUTING -s "$p" -o "$WAN" -j MASQUERADE -m comment --comment $TAG
            iptables -w -I FORWARD -s "$p" -j ACCEPT -m comment --comment $TAG
            iptables -w -I FORWARD -d "$p" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT -m comment --comment $TAG
            iptables -w -t mangle -A FORWARD -s "$p" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu -m comment --comment $TAG
        done
    fi
    [ "$TT_CIP" = 1 ] && cip_up
    return 0
}

down_rules() {
    local t
    for t in filter nat mangle raw; do del_tagged iptables $t; done
    del_tagged ip6tables filter
}

down() {
    down_rules
    cip_down
    if [ -f "$BASE/var/ip_forward.prev" ]; then
        sysctl -qw "net.ipv4.ip_forward=$(cat "$BASE/var/ip_forward.prev")"
        rm -f "$BASE/var/ip_forward.prev"
    fi
    return 0
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 up|down" >&2; exit 2 ;;
esac
NETSH
    chmod 755 "$BASE/net.sh"
}

ufw_sync() {
    [ "$NO_FW" = 1 ] && return 0
    ufw_active || return 0
    local p
    # shellcheck disable=SC1091
    . "$BASE/net.env"
    for p in $TT_PORTS; do
        ufw allow "$p" comment tern-test >/dev/null
        grep -qx "$p" "$BASE/var/ufw-rules" 2>/dev/null || echo "$p" >> "$BASE/var/ufw-rules"
    done
    log "ufw 已放行：$TT_PORTS"
}

# ------------------------------------------------------------------------------------------------ per-protocol setup
post_render() {
    local user pass
    user="$(python3 "$BASE/render.py" get user)"; pass="$(python3 "$BASE/render.py" get pass)"
    mkdir -p "$BASE/var"
    if want openconnect; then
        printf '%s\n%s\n' "$pass" "$pass" | ocpasswd -c "$BASE/etc/ocpasswd" "$user" >/dev/null 2>&1 \
            || die "ocpasswd 失败"
        chmod 600 "$BASE/etc/ocpasswd"
    fi
    if want ssh; then
        mkdir -p "$BASE/ssh"
        [ -s "$BASE/ssh/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N "" -f "$BASE/ssh/ssh_host_ed25519_key"
        id "$user" >/dev/null 2>&1 || { useradd -M -s /usr/sbin/nologin -c "Tern self-test" "$user"; echo "$user" > "$BASE/var/ssh-user"; }
        echo "$user:$pass" | chpasswd
        /usr/sbin/sshd -t -f "$BASE/etc/sshd_config" || die "sshd 配置检查失败"
    fi
    if want masque-ip; then
        mkdir -p "$BASE/cip"
        ln -sf "$BASE/certs/cert.pem" "$BASE/cip/cert.pem"; ln -sf "$BASE/certs/key.pem" "$BASE/cip/key.pem"
    fi
    if want wireguard; then
        modprobe wireguard 2>/dev/null || warn "内核没有 wireguard 模块（OpenVZ/LXC 容器 VPS？）— WireGuard 服务可能起不来"
    fi
    [ -c /dev/net/tun ] || { want_any awg openconnect && warn "/dev/net/tun 不存在 — ocserv / AmneziaWG 需要 TUN"; }
    if [ -x "$BASE/bin/sing-box" ] && [ -f "$BASE/etc/sing-box.json" ]; then
        "$BASE/bin/sing-box" check -c "$BASE/etc/sing-box.json" || die "sing-box 配置检查失败"
    fi
    if [ -x "$BASE/bin/xray" ] && [ -f "$BASE/etc/xray.json" ]; then
        "$BASE/bin/xray" run -test -c "$BASE/etc/xray.json" >/dev/null || die "xray 配置检查失败"
    fi
}

setup_mieru() {
    want mieru || return 0
    systemctl enable --now mita >/dev/null 2>&1 || true
    for _ in 1 2 3 4 5; do mita status >/dev/null 2>&1 && break; sleep 1; done
    mita apply config "$BASE/etc/mita.json" >/dev/null || die "mita apply config 失败"
    mita start >/dev/null 2>&1 || mita reload >/dev/null 2>&1 || true
}

install_units() {
    local f name keep=" "
    for f in "$BASE"/units/*.service; do
        name="$(basename "$f")"; keep="$keep$name "
        install -m 644 "$f" "/etc/systemd/system/$name"
    done
    # services of protocols no longer selected
    for f in /etc/systemd/system/tern-*.service; do
        [ -e "$f" ] || continue
        name="$(basename "$f")"
        case "$keep" in *" $name "*) ;; *)
            log "移除未选中的服务 $name"; systemctl disable --now "$name" >/dev/null 2>&1 || true; rm -f "$f" ;;
        esac
    done
    if ! want mieru && systemctl list-unit-files mita.service >/dev/null 2>&1 && [ -f "$BASE/bin/.ver-mita" ]; then
        systemctl disable --now mita >/dev/null 2>&1 || true
    fi
    systemctl daemon-reload
    systemctl enable tern-net.service >/dev/null 2>&1
    systemctl restart tern-net.service
    for f in "$BASE"/units/*.service; do
        name="$(basename "$f")"
        [ "$name" = tern-net.service ] && continue
        systemctl enable "$name" >/dev/null 2>&1
        systemctl restart "$name" || warn "$name 启动失败：journalctl -u $name -n 50"
    done
    setup_mieru
}

# ------------------------------------------------------------------------------------------------ uninstall
do_uninstall() {
    [ "$(id -u)" = 0 ] || die "请用 root 运行"
    log "卸载 Tern 自测服务端"
    local f name
    for f in /etc/systemd/system/tern-*.service; do
        [ -e "$f" ] || continue
        name="$(basename "$f")"
        [ "$name" = tern-net.service ] && continue
        systemctl disable --now "$name" >/dev/null 2>&1 || true
        rm -f "$f"
    done
    if [ -e /etc/systemd/system/tern-net.service ]; then
        systemctl disable --now tern-net.service >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/tern-net.service
    fi
    [ -x "$BASE/net.sh" ] && "$BASE/net.sh" down
    systemctl daemon-reload
    if [ -f "$BASE/var/ufw-rules" ] && command -v ufw >/dev/null 2>&1; then
        while read -r f; do [ -n "$f" ] && ufw delete allow "$f" >/dev/null 2>&1; done < "$BASE/var/ufw-rules"
    fi
    # rules added by open_port_now (ACME) when ufw was inactive
    iptables -S INPUT 2>/dev/null | grep -- "--comment tern-test" | sed 's/^-A /-D /' | while read -r f; do
        # shellcheck disable=SC2086
        iptables -w $f 2>/dev/null
    done
    if [ -f "$BASE/var/ssh-user" ]; then userdel "$(cat "$BASE/var/ssh-user")" 2>/dev/null || true; fi
    if [ -f "$BASE/var/certbot-domain" ] && command -v certbot >/dev/null 2>&1; then
        certbot delete --non-interactive --cert-name "$(cat "$BASE/var/certbot-domain")" >/dev/null 2>&1 || true
    fi
    rm -f /etc/letsencrypt/renewal-hooks/deploy/tern-test.sh
    if [ -f "$BASE/var/apt-installed" ]; then
        local pkgs; pkgs="$(sort -u "$BASE/var/apt-installed" | grep -vxE 'curl|ca-certificates|openssl|python3|iptables|iproute2|tar|xz-utils|procps|software-properties-common|openssh-server' | tr '\n' ' ')"
        if grep -qx mita "$BASE/var/apt-installed"; then systemctl disable --now mita >/dev/null 2>&1 || true; fi
        if [ -n "${pkgs// /}" ]; then
            log "卸载本工具安装的软件包：$pkgs"
            # shellcheck disable=SC2086
            DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq $pkgs >/dev/null 2>&1 || warn "部分软件包卸载失败：$pkgs"
            DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq >/dev/null 2>&1 || true
        fi
    fi
    rm -rf "$BASE" "$STATE"
    log "已卸载。"
}

# ------------------------------------------------------------------------------------------------ renderer
write_render_py() {
    mkdir -p "$BASE"
    cat > "$BASE/render.py" <<'PYEOF'
#!/usr/bin/env python3
# Tern server self-test kit — renderer (embedded in tools/server-test/install.sh, written to $BASE/render.py).
# Generates / keeps credentials (state.json), every server config, the systemd units, the firewall port list,
# the Tern node list (Clash-style YAML proxies, share links, Surge lines), the subscription file, and prints the
# port table + nodes + terminal QR codes.  Python >= 3.9, stdlib only (+ openssl / qrencode binaries).
import base64, json, os, secrets, shutil, string, subprocess, sys, urllib.parse, uuid

ENV = os.environ
BASE = ENV.get("TT_BASE", "/opt/tern-test")
STATE_DIR = ENV.get("TT_STATE", "/root/tern-test")
ETC = os.path.join(BASE, "etc")
BIN = os.path.join(BASE, "bin")
CERT = os.path.join(BASE, "certs", "cert.pem")
KEY = os.path.join(BASE, "certs", "key.pem")
UNIT_OUT = os.path.join(BASE, "units")
PB = int(ENV.get("TT_PORT_BASE", "24000"))
IP = ENV.get("TT_IP", "")
DOMAIN = ENV.get("TT_DOMAIN", "")          # set => trusted cert, no skip-cert-verify
SNI = DOMAIN or "tern.test"
INSECURE = not DOMAIN
CERT_SHA256 = ENV.get("TT_CERT_SHA256", "")
SELECTED = [p for p in ENV.get("TT_PROTOS", "").split(",") if p]
REALITY_DEST = "www.microsoft.com"
RESTLS_SCRIPT = "300?100,400~100,350~100,600~100,300~200,300~100"
SS_BACKEND = 34004   # 127.0.0.1-only Shadowsocks backend behind kcptun / Cloak / restls
STLS_BACKEND = 34006  # 127.0.0.1-only Shadowsocks behind shadow-tls

# id: (port offset, firewall protos, display name)
PROTOS = {
    "socks": (1, "tcp,udp", "SOCKS5"),
    "http": (2, "tcp", "HTTP 代理"),
    "https": (3, "tcp", "HTTPS 代理"),
    "ss": (4, "tcp,udp", "Shadowsocks AEAD"),
    "ss2022": (5, "tcp,udp", "Shadowsocks 2022"),
    "ss-shadowtls": (6, "tcp", "SS + shadow-tls v3"),
    "vmess": (7, "tcp", "VMess TCP"),
    "vmess-ws": (8, "tcp", "VMess WS"),
    "vless": (9, "tcp", "VLESS TCP"),
    "vless-reality": (10, "tcp", "VLESS Reality+Vision"),
    "vless-vision": (11, "tcp", "VLESS TLS+Vision"),
    "trojan": (12, "tcp", "Trojan"),
    "hysteria": (13, "udp", "Hysteria v1"),
    "hysteria2": (14, "udp", "Hysteria2"),
    "tuic": (15, "udp", "TUIC v5"),
    "anytls": (16, "tcp", "AnyTLS"),
    "naive": (17, "tcp,udp", "Naive (H2 / H3)"),
    "vless-enc": (18, "tcp", "VLESS mlkem768x25519plus"),
    "ss-obfs": (21, "tcp", "SS + simple-obfs http"),
    "ss-v2ray": (22, "tcp", "SS + v2ray-plugin ws"),
    "ss-kcptun": (23, "udp", "SS + kcptun"),
    "ss-cloak": (24, "tcp", "SS + Cloak"),
    "ss-restls": (25, "tcp", "SS + restls"),
    "ssr": (26, "tcp,udp", "ShadowsocksR"),
    "snell4": (27, "tcp,udp", "Snell v4"),
    "snell5": (28, "tcp,udp", "Snell v5"),
    "mieru": (29, "tcp", "Mieru (TCP)"),
    "ssh": (30, "tcp", "SSH"),
    "brook": (31, "tcp,udp", "Brook"),
    "gost-relay": (32, "tcp", "GOST relay+tls"),
    "juicity": (33, "udp", "Juicity"),
    "wireguard": (34, "udp", "WireGuard"),
    "awg": (35, "udp", "AmneziaWG 1.0"),
    "openconnect": (36, "tcp,udp", "OpenConnect (ocserv)"),
    "trusttunnel": (37, "tcp,udp", "TrustTunnel (H2 / H3)"),
    "sudoku": (38, "tcp", "Sudoku"),
    "masque-ip": (39, "udp", "MASQUE CONNECT-IP"),
    "masque-udp": (40, "udp", "MASQUE CONNECT-UDP"),
}
SUB_HTTPS, SUB_HTTP = PB + 41, PB + 42
NODE_NAMES = {"socks": "SOCKS5", "http": "HTTP", "https": "HTTPS", "ss": "SS-AEAD", "ss2022": "SS2022",
              "ss-shadowtls": "SS-ShadowTLS", "vmess": "VMess", "vmess-ws": "VMess-WS", "vless": "VLESS",
              "vless-reality": "VLESS-Reality", "vless-vision": "VLESS-Vision", "vless-enc": "VLESS-MLKEM",
              "trojan": "Trojan", "hysteria": "Hysteria", "hysteria2": "Hysteria2", "tuic": "TUIC", "anytls": "AnyTLS",
              "naive": "Naive", "ss-obfs": "SS-Obfs", "ss-v2ray": "SS-V2ray", "ss-kcptun": "SS-KCPTun",
              "ss-cloak": "SS-Cloak", "ss-restls": "SS-Restls", "ssr": "SSR", "snell4": "Snell4", "snell5": "Snell5",
              "mieru": "Mieru", "ssh": "SSH", "brook": "Brook", "gost-relay": "GOST-Relay", "juicity": "Juicity",
              "wireguard": "WireGuard", "awg": "AmneziaWG", "openconnect": "OpenConnect",
              "trusttunnel": "TrustTunnel", "sudoku": "Sudoku", "masque-ip": "MASQUE-IP", "masque-udp": "MASQUE-UDP"}


def port(pid):
    return PB + PROTOS[pid][0]


def rnd(n=20):
    a = string.ascii_letters + string.digits
    return "".join(secrets.choice(a) for _ in range(n))


def b64(b):
    return base64.b64encode(b).decode()


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def x25519():
    """(private raw, public raw) via openssl — no python crypto dependency."""
    der = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                         input=der, check=True, capture_output=True).stdout
    return der[-32:], pub[-32:]


def tool(name):
    p = os.path.join(BIN, name)
    return p if os.access(p, os.X_OK) else shutil.which(name)


def load_state():
    path = os.path.join(STATE_DIR, "state.json")
    st = {}
    if os.path.exists(path):
        with open(path) as f:
            st = json.load(f)
    c = st.setdefault("creds", {})

    def need(k, fn):
        if k not in c:
            c[k] = fn()
        return c[k]

    need("uuid", lambda: str(uuid.uuid4()))
    need("user", lambda: "tern" + rnd(4).lower())
    need("pass", lambda: rnd(20))
    need("ss_pass", lambda: rnd(24))
    need("ss2022_psk", lambda: b64(secrets.token_bytes(16)))
    need("stls_pass", lambda: rnd(20))
    need("stls_ss_pass", lambda: rnd(24))
    need("vmess_ws_path", lambda: "/" + rnd(8).lower())
    need("v2ray_path", lambda: "/" + rnd(8).lower())
    need("reality_sid", lambda: secrets.token_hex(8))
    if "reality_priv" not in c:
        pr, pu = x25519()
        c["reality_priv"], c["reality_pub"] = b64u(pr), b64u(pu)
    need("hy1_auth", lambda: rnd(20))
    need("kcp_key", lambda: rnd(20))
    if "ck_priv" not in c:
        pr, pu = x25519()
        c["ck_priv"], c["ck_pub"] = b64(pr), b64(pu)
        c["ck_uid"] = b64(secrets.token_bytes(16))
        c["ck_admin"] = b64(secrets.token_bytes(16))
    need("restls_pass", lambda: rnd(20))
    need("ssr_pass", lambda: rnd(20))
    need("snell_psk", lambda: rnd(24))
    for k in ("wg", "awg"):
        if k + "_srv_priv" not in c:
            sp, spub = x25519()
            cp, cpub = x25519()
            c[k + "_srv_priv"], c[k + "_srv_pub"] = b64(sp), b64(spub)
            c[k + "_cli_priv"], c[k + "_cli_pub"] = b64(cp), b64(cpub)
    if "awg_h" not in c:
        hs = set()
        while len(hs) < 4:
            hs.add(secrets.randbelow(2**31 - 10) + 5)
        c["awg_h"] = sorted(hs)
        c["awg_s1"] = secrets.randbelow(60) + 15
        c["awg_s2"] = secrets.randbelow(60) + 15
        if c["awg_s1"] + 56 == c["awg_s2"]:
            c["awg_s2"] += 1
    need("sub_token", lambda: secrets.token_hex(16))
    # tool-generated keys: only when the tool is present (it is installed before rendering on the VPS)
    if "vlessenc_dec" not in c and tool("xray"):
        out = subprocess.run([tool("xray"), "vlessenc"], check=True, capture_output=True, text=True).stdout
        # first block = X25519 authentication (shorter keys); lines '"decryption": "…"' / '"encryption": "…"'
        dec = [l.split('"')[3] for l in out.splitlines() if l.strip().startswith('"decryption"')]
        enc = [l.split('"')[3] for l in out.splitlines() if l.strip().startswith('"encryption"')]
        c["vlessenc_dec"], c["vlessenc_enc"] = dec[0], enc[0]
    if "sudoku_pub" not in c and tool("sudoku"):
        out = subprocess.run([tool("sudoku"), "-keygen"], check=True, capture_output=True, text=True)
        txt = out.stdout + out.stderr
        for l in txt.splitlines():
            if "Available Private Key:" in l:
                c["sudoku_priv"] = l.split(":")[-1].strip()
            if "Master Public Key:" in l:
                c["sudoku_pub"] = l.split(":")[-1].strip()
    st["ip"] = IP
    st["domain"] = DOMAIN
    st["selected"] = SELECTED
    st["port_base"] = PB
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return st


def wfile(path, content, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)


def tls_sb(alpn=None):
    t = {"enabled": True, "server_name": SNI, "certificate_path": CERT, "key_path": KEY}
    if alpn:
        t["alpn"] = alpn
    return t


def unit(name, desc, execstart, extra="", after="network-online.target", unit_type="simple", workdir=None, unit_extra=""):
    body = f"""[Unit]
Description=Tern self-test: {desc}
Wants=network-online.target
After={after}
{unit_extra}
[Service]
Type={unit_type}
ExecStart={execstart}
"""
    if workdir:
        body += f"WorkingDirectory={workdir}\n"
    if unit_type == "simple":
        body += "Restart=on-failure\nRestartSec=3\nLimitNOFILE=65535\n"
    body += extra
    body += "\n[Install]\nWantedBy=multi-user.target\n"
    wfile(os.path.join(UNIT_OUT, name + ".service"), body, 0o644)


def has(*ids):
    return any(i in SELECTED for i in ids)


# ---------------------------------------------------------------------------------------------- server configs
def render_servers(c):
    os.makedirs(UNIT_OUT, exist_ok=True)
    for f in os.listdir(UNIT_OUT):
        os.remove(os.path.join(UNIT_OUT, f))
    user, pw = c["user"], c["pass"]

    # sing-box (pinned to the version tools/loopback/start-servers.sh runs in CI)
    ib = []
    if has("socks"):
        ib.append({"type": "socks", "tag": "socks-in", "listen": "0.0.0.0", "listen_port": port("socks"),
                   "users": [{"username": user, "password": pw}]})
    if has("http"):
        ib.append({"type": "http", "tag": "http-in", "listen": "0.0.0.0", "listen_port": port("http"),
                   "users": [{"username": user, "password": pw}]})
    if has("https"):
        ib.append({"type": "http", "tag": "https-in", "listen": "0.0.0.0", "listen_port": port("https"),
                   "users": [{"username": user, "password": pw}], "tls": tls_sb()})
    if has("ss"):
        ib.append({"type": "shadowsocks", "tag": "ss-in", "listen": "0.0.0.0", "listen_port": port("ss"),
                   "method": "aes-256-gcm", "password": c["ss_pass"]})
    if has("ss-kcptun", "ss-cloak", "ss-restls"):
        ib.append({"type": "shadowsocks", "tag": "ss-backend", "listen": "127.0.0.1", "listen_port": SS_BACKEND,
                   "method": "aes-256-gcm", "password": c["ss_pass"]})
    if has("ss2022"):
        ib.append({"type": "shadowsocks", "tag": "ss2022-in", "listen": "0.0.0.0", "listen_port": port("ss2022"),
                   "method": "2022-blake3-aes-128-gcm", "password": c["ss2022_psk"]})
    if has("ss-shadowtls"):
        ib.append({"type": "shadowtls", "tag": "stls-in", "listen": "0.0.0.0", "listen_port": port("ss-shadowtls"),
                   "version": 3, "users": [{"name": user, "password": c["stls_pass"]}],
                   "handshake": {"server": REALITY_DEST, "server_port": 443}, "strict_mode": True,
                   "detour": "stls-ss-in"})
        ib.append({"type": "shadowsocks", "tag": "stls-ss-in", "listen": "127.0.0.1", "listen_port": STLS_BACKEND,
                   "method": "aes-128-gcm", "password": c["stls_ss_pass"]})
    if has("vmess"):
        ib.append({"type": "vmess", "tag": "vmess-in", "listen": "0.0.0.0", "listen_port": port("vmess"),
                   "users": [{"name": user, "uuid": c["uuid"], "alterId": 0}]})
    if has("vmess-ws"):
        ib.append({"type": "vmess", "tag": "vmess-ws-in", "listen": "0.0.0.0", "listen_port": port("vmess-ws"),
                   "users": [{"name": user, "uuid": c["uuid"], "alterId": 0}],
                   "transport": {"type": "ws", "path": c["vmess_ws_path"]}})
    if has("vless"):
        ib.append({"type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": port("vless"),
                   "users": [{"name": user, "uuid": c["uuid"], "flow": ""}]})
    if has("vless-reality"):
        ib.append({"type": "vless", "tag": "vless-reality-in", "listen": "0.0.0.0", "listen_port": port("vless-reality"),
                   "users": [{"name": user, "uuid": c["uuid"], "flow": "xtls-rprx-vision"}],
                   "tls": {"enabled": True, "server_name": REALITY_DEST,
                           "reality": {"enabled": True, "handshake": {"server": REALITY_DEST, "server_port": 443},
                                       "private_key": c["reality_priv"], "short_id": [c["reality_sid"]]}}})
    if has("vless-vision"):
        ib.append({"type": "vless", "tag": "vless-vision-in", "listen": "0.0.0.0", "listen_port": port("vless-vision"),
                   "users": [{"name": user, "uuid": c["uuid"], "flow": "xtls-rprx-vision"}], "tls": tls_sb()})
    if has("trojan"):
        ib.append({"type": "trojan", "tag": "trojan-in", "listen": "0.0.0.0", "listen_port": port("trojan"),
                   "users": [{"name": user, "password": pw}], "tls": tls_sb()})
    if has("hysteria"):
        ib.append({"type": "hysteria", "tag": "hy1-in", "listen": "0.0.0.0", "listen_port": port("hysteria"),
                   "up_mbps": 200, "down_mbps": 200, "users": [{"name": user, "auth_str": c["hy1_auth"]}],
                   "tls": tls_sb(["hysteria"])})
    if has("hysteria2"):
        ib.append({"type": "hysteria2", "tag": "hy2-in", "listen": "0.0.0.0", "listen_port": port("hysteria2"),
                   "users": [{"name": user, "password": pw}], "tls": tls_sb(["h3"])})
    if has("tuic"):
        ib.append({"type": "tuic", "tag": "tuic-in", "listen": "0.0.0.0", "listen_port": port("tuic"),
                   "users": [{"name": user, "uuid": c["uuid"], "password": pw}], "congestion_control": "bbr",
                   "tls": tls_sb(["h3"])})
    if has("anytls"):
        ib.append({"type": "anytls", "tag": "anytls-in", "listen": "0.0.0.0", "listen_port": port("anytls"),
                   "users": [{"name": user, "password": pw}], "tls": tls_sb()})
    if has("naive"):
        ib.append({"type": "naive", "tag": "naive-h2-in", "listen": "0.0.0.0", "listen_port": port("naive"),
                   "network": "tcp", "users": [{"username": user, "password": pw}], "tls": tls_sb()})
        ib.append({"type": "naive", "tag": "naive-h3-in", "listen": "0.0.0.0", "listen_port": port("naive"),
                   "network": "udp", "users": [{"username": user, "password": pw}], "tls": tls_sb(["h3"])})
    if ib:
        sb = {"log": {"level": "warn", "timestamp": True}, "inbounds": ib,
              "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
        wfile(os.path.join(ETC, "sing-box.json"), json.dumps(sb, indent=2))
        unit("tern-sing-box", "sing-box (socks/http/ss/vmess/vless/trojan/hy/tuic/anytls/naive)",
             f"{BIN}/sing-box run -c {ETC}/sing-box.json")

    if has("vless-enc"):
        xr = {"log": {"loglevel": "warning"},
              "inbounds": [{"listen": "0.0.0.0", "port": port("vless-enc"), "protocol": "vless",
                            "settings": {"clients": [{"id": c["uuid"]}], "decryption": c.get("vlessenc_dec", "none")},
                            "streamSettings": {"network": "tcp", "security": "none"}}],
              "outbounds": [{"protocol": "freedom", "tag": "direct"}]}
        wfile(os.path.join(ETC, "xray.json"), json.dumps(xr, indent=2))
        unit("tern-xray", "Xray (VLESS mlkem768x25519plus encryption)", f"{BIN}/xray run -c {ETC}/xray.json")

    servers = []
    if has("ss-obfs"):
        servers.append({"server": "0.0.0.0", "server_port": port("ss-obfs"), "method": "aes-256-gcm",
                        "password": c["ss_pass"], "mode": "tcp_only", "plugin": "obfs-server",
                        "plugin_opts": "obfs=http"})
    if has("ss-v2ray"):
        servers.append({"server": "0.0.0.0", "server_port": port("ss-v2ray"), "method": "aes-256-gcm",
                        "password": c["ss_pass"], "mode": "tcp_only", "plugin": "ss-v2ray-plugin",
                        "plugin_opts": f"server;path={c['v2ray_path']};host={SNI}"})
    if servers:
        wfile(os.path.join(ETC, "ssrust.json"), json.dumps({"servers": servers}, indent=2))
        unit("tern-ssrust", "shadowsocks-rust + simple-obfs / v2ray-plugin", f"{BIN}/ssserver -c {ETC}/ssrust.json")

    if has("ss-kcptun"):
        unit("tern-kcptun", "kcptun server -> Shadowsocks backend",
             f"/usr/bin/kcptun-server -l :{port('ss-kcptun')} -t 127.0.0.1:{SS_BACKEND} --key {c['kcp_key']} "
             f"--crypt aes --mode fast --nocomp --smuxver 1 --datashard 10 --parityshard 3 --mtu 1350 "
             f"--sndwnd 1024 --rcvwnd 1024")
    if has("ss-cloak"):
        ck = {"ProxyBook": {"shadowsocks": ["tcp", f"127.0.0.1:{SS_BACKEND}"]},
              "BindAddr": [f":{port('ss-cloak')}"], "BypassUID": [c["ck_uid"]], "RedirAddr": "www.bing.com",
              "PrivateKey": c["ck_priv"], "AdminUID": c["ck_admin"],
              "DatabasePath": os.path.join(BASE, "var", "cloak-userinfo.db"), "StreamTimeout": 300}
        wfile(os.path.join(ETC, "cloak.json"), json.dumps(ck, indent=2))
        unit("tern-cloak", "Cloak server -> Shadowsocks backend", f"{BIN}/ck-server -c {ETC}/cloak.json")
    if has("ss-restls"):
        unit("tern-restls", "restls server -> Shadowsocks backend",
             f"{BIN}/restls -l 0.0.0.0:{port('ss-restls')} -f 127.0.0.1:{SS_BACKEND} -s {REALITY_DEST} "
             f"-p {c['restls_pass']} --script {RESTLS_SCRIPT}")
    if has("ssr"):
        ssr = {"server": "0.0.0.0", "server_port": port("ssr"), "password": c["ssr_pass"],
               "method": "aes-256-cfb", "protocol": "auth_aes128_md5", "protocol_param": "",
               "obfs": "tls1.2_ticket_auth", "obfs_param": "", "timeout": 120, "udp_timeout": 60,
               "fast_open": False, "workers": 1, "dns_ipv6": False, "connect_verbose_info": 0,
               "redirect": "", "speed_limit_per_con": 0, "speed_limit_per_user": 0}
        wfile(os.path.join(ETC, "ssr.json"), json.dumps(ssr, indent=2))
        unit("tern-ssr", "ShadowsocksR (python reference server)",
             f"/usr/bin/python3 {BASE}/ssr/shadowsocks/server.py -c {ETC}/ssr.json")
    for v in ("4", "5"):
        pid = "snell" + v
        if has(pid):
            wfile(os.path.join(ETC, f"snell{v}.conf"),
                  f"[snell-server]\nlisten = 0.0.0.0:{port(pid)}\npsk = {c['snell_psk']}\nipv6 = false\n")
            unit(f"tern-snell{v}", f"Snell v{v} (official snell-server)", f"{BIN}/snell-server-v{v} -c {ETC}/snell{v}.conf")
    if has("mieru"):
        mita = {"portBindings": [{"port": port("mieru"), "protocol": "TCP"}],
                "users": [{"name": user, "password": pw}], "loggingLevel": "INFO", "mtu": 1400}
        wfile(os.path.join(ETC, "mita.json"), json.dumps(mita, indent=2))
    if has("ssh"):
        wfile(os.path.join(ETC, "sshd_config"), f"""# Tern self-test SSH (port forwarding only, separate from the system sshd)
Port {port('ssh')}
HostKey {BASE}/ssh/ssh_host_ed25519_key
PidFile /run/tern-sshd.pid
AllowUsers {user}
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
UsePAM yes
AllowTcpForwarding yes
PermitTTY no
X11Forwarding no
AllowAgentForwarding no
ForceCommand /usr/sbin/nologin
""", 0o644)
        unit("tern-sshd", "OpenSSH (forwarding-only test user)", f"/usr/sbin/sshd -D -e -f {ETC}/sshd_config",
             extra="ExecStartPre=/bin/mkdir -p /run/sshd\n")
    if has("brook"):
        unit("tern-brook", "Brook server", f"{BIN}/brook server --listen :{port('brook')} --password {pw}")
    if has("gost-relay"):
        unit("tern-gost", "GOST v3 relay+tls",
             f"{BIN}/gost -L relay+tls://{user}:{pw}@:{port('gost-relay')}?certFile={CERT}&keyFile={KEY}")
    if has("juicity"):
        jc = {"listen": f":{port('juicity')}", "users": {c["uuid"]: pw}, "certificate": CERT, "private_key": KEY,
              "congestion_control": "bbr", "log_level": "info"}
        wfile(os.path.join(ETC, "juicity.json"), json.dumps(jc, indent=2))
        unit("tern-juicity", "Juicity server", f"{BIN}/juicity-server run -c {ETC}/juicity.json")
    if has("wireguard"):
        wfile(os.path.join(ETC, "ternwg.conf"), f"""[Interface]
Address = 10.66.0.1/24
ListenPort = {port('wireguard')}
PrivateKey = {c['wg_srv_priv']}
MTU = 1420

[Peer]
PublicKey = {c['wg_cli_pub']}
AllowedIPs = 10.66.0.2/32
""")
        unit("tern-wg", "WireGuard (kernel, wg-quick)", f"/usr/bin/wg-quick up {ETC}/ternwg.conf",
             extra=f"ExecStop=/usr/bin/wg-quick down {ETC}/ternwg.conf\nRemainAfterExit=yes\n",
             unit_type="oneshot", after="network-online.target tern-net.service")
    if has("awg"):
        h = c["awg_h"]
        wfile(os.path.join(ETC, "ternawg.conf"), f"""[Interface]
Address = 10.67.0.1/24
ListenPort = {port('awg')}
PrivateKey = {c['awg_srv_priv']}
MTU = 1420
Jc = 4
Jmin = 40
Jmax = 70
S1 = {c['awg_s1']}
S2 = {c['awg_s2']}
H1 = {h[0]}
H2 = {h[1]}
H3 = {h[2]}
H4 = {h[3]}

[Peer]
PublicKey = {c['awg_cli_pub']}
AllowedIPs = 10.67.0.2/32
""")
        unit("tern-awg", "AmneziaWG (amneziawg-go userspace, awg-quick)",
             f"{BASE}/awg/bin/awg-quick up {ETC}/ternawg.conf",
             extra=(f"ExecStop={BASE}/awg/bin/awg-quick down {ETC}/ternawg.conf\nRemainAfterExit=yes\n"
                    f"Environment=PATH={BASE}/awg/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                    "Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go\n"),
             unit_type="oneshot", after="network-online.target tern-net.service")
    if has("openconnect"):
        wfile(os.path.join(ETC, "ocserv.conf"), f"""# Tern self-test ocserv (password auth, DTLS on)
auth = "plain[passwd={ETC}/ocpasswd]"
tcp-port = {port('openconnect')}
udp-port = {port('openconnect')}
run-as-user = nobody
run-as-group = nogroup
socket-file = /run/tern-ocserv-socket
pid-file = /run/tern-ocserv.pid
server-cert = {CERT}
server-key = {KEY}
isolate-workers = false
max-clients = 16
max-same-clients = 4
keepalive = 30
dpd = 30
mobile-dpd = 60
try-mtu-discovery = false
tls-priorities = "NORMAL:%SERVER_PRECEDENCE"
auth-timeout = 240
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = false
device = ternoc
predictable-ips = true
default-domain = tern.test
ipv4-network = 10.77.0.0
ipv4-netmask = 255.255.255.0
dns = 1.1.1.1
dns = 8.8.8.8
ping-leases = false
mtu = 1400
cisco-client-compat = true
dtls-legacy = true
""", 0o644)
        unit("tern-ocserv", "ocserv (OpenConnect)", f"/usr/sbin/ocserv -c {ETC}/ocserv.conf -f",
             after="network-online.target tern-net.service")
    if has("trusttunnel"):
        wfile(os.path.join(ETC, "tt-credentials.toml"),
              f'[[client]]\nusername = "{user}"\npassword = "{pw}"\n')
        wfile(os.path.join(ETC, "tt-hosts.toml"),
              f'[[main_hosts]]\nhostname = "{SNI}"\ncert_chain_path = "{CERT}"\nprivate_key_path = "{KEY}"\n')
        wfile(os.path.join(ETC, "tt-settings.toml"),
              f'listen_address = "0.0.0.0:{port("trusttunnel")}"\ncredentials_file = "{ETC}/tt-credentials.toml"\n'
              'allow_private_network_connections = false\n\n[listen_protocols.http2]\n\n[listen_protocols.quic]\n\n'
              '[forward_protocol.direct]\n')
        unit("tern-trusttunnel", "TrustTunnel endpoint (H2 + H3)",
             f"{BIN}/trusttunnel_endpoint {ETC}/tt-settings.toml {ETC}/tt-hosts.toml")
    if has("sudoku"):
        # same shape as tools/loopback/sudoku/entropy.json (proven by NativeCoreLoopbackTests); fallback to a
        # closed port like closed-fallback.json, so probes get a closed socket.
        sk = {"mode": "server", "transport": "tcp", "local_port": port("sudoku"), "fallback_address": "127.0.0.1:9",
              "key": c.get("sudoku_pub", ""), "aead": "chacha20-poly1305", "suspicious_action": "fallback",
              "padding_min": 10, "padding_max": 30, "custom_table": "", "custom_tables": [],
              "ascii": "prefer_entropy", "enable_pure_downlink": True, "multiplex": "off",
              "httpmask": {"disable": False, "mode": "legacy"}}
        wfile(os.path.join(ETC, "sudoku.json"), json.dumps(sk, indent=2))
        unit("tern-sudoku", "Sudoku server (official v0.5.2.0)", f"{BIN}/sudoku -c {ETC}/sudoku.json")
    if has("masque-ip"):
        unit("tern-connectip", "connect-ip-go RFC 9484 proxy",
             f"/usr/bin/env SERVER_INTERFACE=tcip0 PROXY_ADDR=0.0.0.0 PROXY_PORT={port('masque-ip')} "
             f"ASSIGN_ADDR=10.89.0.2 ROUTE=0.0.0.0/0 FILTER_IP_PROTOCOL=0 {BIN}/cip-proxy",
             workdir=os.path.join(BASE, "cip"), after="network-online.target tern-net.service",
             extra="StandardOutput=null\n", unit_extra="Requires=tern-net.service\n")
    if has("masque-udp"):
        unit("tern-masque", "masque-go RFC 9298 CONNECT-UDP proxy",
             f"{BIN}/masque-proxy -t https://{SNI}:{port('masque-udp')}/.well-known/masque/udp/{{target_host}}/{{target_port}}/ "
             f"-b 0.0.0.0:{port('masque-udp')} -c {CERT} -k {KEY}")
    # subscription server + network helper are always present
    unit("tern-sub", "subscription file server (HTTPS, token path)",
         f"/usr/bin/python3 {BASE}/subserver.py")
    unit("tern-net", "firewall / NAT / forwarding / CONNECT-IP netns", f"{BASE}/net.sh up",
         extra=f"ExecStop={BASE}/net.sh down\nRemainAfterExit=yes\n", unit_type="oneshot",
         after="network-online.target")
    # NAT'd tunnel subnets for net.sh
    nets = []
    if has("openconnect"):
        nets.append("10.77.0.0/24")
    if has("wireguard"):
        nets.append("10.66.0.0/24")
    if has("awg"):
        nets.append("10.67.0.0/24")
    if has("masque-ip"):
        nets.append("10.89.0.0/24")
    ports = []
    for pid in SELECTED:
        for pr in PROTOS[pid][1].split(","):
            ports.append(f"{port(pid)}/{pr}")
    ports.append(f"{SUB_HTTPS}/tcp")
    if INSECURE:
        ports.append(f"{SUB_HTTP}/tcp")
    wfile(os.path.join(BASE, "net.env"),
          f'TT_NAT_NETS="{" ".join(nets)}"\nTT_PORTS="{" ".join(ports)}"\n'
          f'TT_CIP={"1" if has("masque-ip") else "0"}\n', 0o644)


# ---------------------------------------------------------------------------------------------- nodes
def q(s):
    return urllib.parse.quote(str(s), safe="")


def yaml_scalar(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(yaml_scalar(x) for x in v) + "]"
    if isinstance(v, dict):
        return yaml_flow(v)
    return json.dumps(str(v), ensure_ascii=False)


def yaml_flow(d):
    return "{" + ", ".join(f"{k}: {yaml_scalar(v)}" for k, v in d.items()) + "}"


def build_nodes(c):
    ip = IP
    user, pw = c["user"], c["pass"]
    tlsf = {"sni": SNI}
    if INSECURE:
        tlsf["skip-cert-verify"] = True
    nodes = []

    def add(pid, name, y, link=None, surge=None, note=""):
        node = {"id": pid, "name": name, "port": y.get("port"), "yaml": dict(name=name, **y)}
        node["yaml_line"] = "- " + yaml_flow(node["yaml"])
        if link:
            node["qr_kind"], node["qr"] = "link", link
        elif surge:
            node["qr_kind"], node["qr"] = "surge", surge
        else:
            node["qr_kind"], node["qr"] = "yaml", "proxies:\n  " + node["yaml_line"]
        node["note"] = note
        nodes.append(node)

    def nm(pid, suffix=""):
        return "Tern-" + NODE_NAMES[pid] + suffix

    def ins():
        return "&allowInsecure=1" if INSECURE else ""

    if has("socks"):
        n = nm("socks")
        add("socks", n, dict(type="socks5", server=ip, port=port("socks"), username=user, password=pw, udp=True),
            link=f"socks5://{q(user)}:{q(pw)}@{ip}:{port('socks')}#{q(n)}")
    if has("http"):
        n = nm("http")
        add("http", n, dict(type="http", server=ip, port=port("http"), username=user, password=pw),
            link=f"http://{q(user)}:{q(pw)}@{ip}:{port('http')}#{q(n)}")
    if has("https"):
        n = nm("https")
        add("https", n, dict(type="http", server=ip, port=port("https"), username=user, password=pw, tls=True, **tlsf),
            link=None if INSECURE else f"https://{q(user)}:{q(pw)}@{ip}:{port('https')}?sni={SNI}#{q(n)}",
            note="自签证书时分享链接无法携带 skip-cert-verify，故用 YAML 片段" if INSECURE else "")
    if has("ss"):
        n = nm("ss")
        add("ss", n, dict(type="ss", server=ip, port=port("ss"), cipher="aes-256-gcm", password=c["ss_pass"], udp=True),
            link=f"ss://{b64u(('aes-256-gcm:' + c['ss_pass']).encode())}@{ip}:{port('ss')}#{q(n)}")
    if has("ss2022"):
        n = nm("ss2022")
        m = "2022-blake3-aes-128-gcm"
        add("ss2022", n, dict(type="ss", server=ip, port=port("ss2022"), cipher=m, password=c["ss2022_psk"], udp=True),
            link=f"ss://{b64u((m + ':' + c['ss2022_psk']).encode())}@{ip}:{port('ss2022')}#{q(n)}")
    if has("ss-shadowtls"):
        n = nm("ss-shadowtls")
        add("ss-shadowtls", n, dict(type="ss", server=ip, port=port("ss-shadowtls"), cipher="aes-128-gcm",
                                    password=c["stls_ss_pass"], udp=False, plugin="shadow-tls",
                                    **{"client-fingerprint": "chrome",
                                       "plugin-opts": {"host": REALITY_DEST, "password": c["stls_pass"], "version": 3}}),
            note="plugin-opts.version 需为数字，ss:// 链接只能带字符串参数，故用 YAML 片段")
    if has("vmess"):
        n = nm("vmess")
        vj = {"v": "2", "ps": n, "add": ip, "port": str(port("vmess")), "id": c["uuid"], "aid": "0", "scy": "auto",
              "net": "tcp", "type": "none", "host": "", "path": "", "tls": ""}
        add("vmess", n, dict(type="vmess", server=ip, port=port("vmess"), uuid=c["uuid"], alterId=0, cipher="auto",
                             network="tcp", udp=True),
            link="vmess://" + b64(json.dumps(vj, separators=(",", ":")).encode()))
    if has("vmess-ws"):
        n = nm("vmess-ws")
        vj = {"v": "2", "ps": n, "add": ip, "port": str(port("vmess-ws")), "id": c["uuid"], "aid": "0", "scy": "auto",
              "net": "ws", "type": "none", "host": SNI, "path": c["vmess_ws_path"], "tls": ""}
        add("vmess-ws", n, dict(type="vmess", server=ip, port=port("vmess-ws"), uuid=c["uuid"], alterId=0, cipher="auto",
                                network="ws", udp=True, **{"ws-opts": {"path": c["vmess_ws_path"],
                                                                       "headers": {"Host": SNI}}}),
            link="vmess://" + b64(json.dumps(vj, separators=(",", ":")).encode()))
    if has("vless"):
        n = nm("vless")
        add("vless", n, dict(type="vless", server=ip, port=port("vless"), uuid=c["uuid"], network="tcp", udp=True),
            link=f"vless://{c['uuid']}@{ip}:{port('vless')}?encryption=none&type=tcp#{q(n)}")
    if has("vless-reality"):
        n = nm("vless-reality")
        add("vless-reality", n, dict(type="vless", server=ip, port=port("vless-reality"), uuid=c["uuid"], network="tcp",
                                     udp=True, tls=True, flow="xtls-rprx-vision", servername=REALITY_DEST,
                                     **{"client-fingerprint": "chrome",
                                        "reality-opts": {"public-key": c["reality_pub"], "short-id": c["reality_sid"]}}),
            link=(f"vless://{c['uuid']}@{ip}:{port('vless-reality')}?encryption=none&flow=xtls-rprx-vision"
                  f"&security=reality&sni={REALITY_DEST}&fp=chrome&pbk={c['reality_pub']}&sid={c['reality_sid']}"
                  f"&type=tcp#{q(n)}"))
    if has("vless-vision"):
        n = nm("vless-vision")
        add("vless-vision", n, dict(type="vless", server=ip, port=port("vless-vision"), uuid=c["uuid"], network="tcp",
                                    udp=True, tls=True, flow="xtls-rprx-vision", servername=SNI,
                                    **{"client-fingerprint": "chrome"},
                                    **({"skip-cert-verify": True} if INSECURE else {})),
            link=(f"vless://{c['uuid']}@{ip}:{port('vless-vision')}?encryption=none&flow=xtls-rprx-vision"
                  f"&security=tls&sni={SNI}&fp=chrome{ins()}&type=tcp#{q(n)}"))
    if has("vless-enc"):
        n = nm("vless-enc")
        enc = c.get("vlessenc_enc", "")
        add("vless-enc", n, dict(type="vless", server=ip, port=port("vless-enc"), uuid=c["uuid"], network="tcp",
                                 udp=True, encryption=enc),
            link=f"vless://{c['uuid']}@{ip}:{port('vless-enc')}?encryption={q(enc)}&type=tcp#{q(n)}")
    if has("trojan"):
        n = nm("trojan")
        add("trojan", n, dict(type="trojan", server=ip, port=port("trojan"), password=pw, udp=True, **tlsf),
            link=f"trojan://{q(pw)}@{ip}:{port('trojan')}?sni={SNI}{ins()}#{q(n)}")
    if has("hysteria"):
        n = nm("hysteria")
        add("hysteria", n, dict(type="hysteria", server=ip, port=port("hysteria"), protocol="udp", up="50 Mbps",
                                down="100 Mbps", alpn=["hysteria"], udp=True, **{"auth-str": c["hy1_auth"]}, **tlsf),
            link=(f"hysteria://{ip}:{port('hysteria')}?protocol=udp&auth={q(c['hy1_auth'])}&peer={SNI}"
                  f"&upmbps=50&downmbps=100&alpn=hysteria{'&insecure=1' if INSECURE else ''}#{q(n)}"))
    if has("hysteria2"):
        n = nm("hysteria2")
        add("hysteria2", n, dict(type="hysteria2", server=ip, port=port("hysteria2"), password=pw, udp=True, **tlsf),
            link=f"hysteria2://{q(pw)}@{ip}:{port('hysteria2')}?sni={SNI}{'&insecure=1' if INSECURE else ''}#{q(n)}")
    if has("tuic"):
        n = nm("tuic")
        add("tuic", n, dict(type="tuic", server=ip, port=port("tuic"), uuid=c["uuid"], password=pw, alpn=["h3"],
                            udp=True, **{"congestion-controller": "bbr"}, **tlsf),
            link=(f"tuic://{c['uuid']}:{q(pw)}@{ip}:{port('tuic')}?sni={SNI}&alpn=h3&congestion_control=bbr"
                  f"{'&allow_insecure=1' if INSECURE else ''}#{q(n)}"))
    if has("anytls"):
        n = nm("anytls")
        add("anytls", n, dict(type="anytls", server=ip, port=port("anytls"), password=pw, udp=True, **tlsf),
            link=f"anytls://{q(pw)}@{ip}:{port('anytls')}?sni={SNI}{'&insecure=1' if INSECURE else ''}#{q(n)}")
    if has("naive"):
        for quic, sfx in ((False, "-H2"), (True, "-H3")):
            n = nm("naive", sfx)
            scheme = "naive+quic" if quic else "naive+https"
            add("naive", n, dict(type="naive", server=ip, port=port("naive"), username=user, password=pw, quic=quic,
                                 udp=True, **{"udp-over-tcp": True}, **tlsf),
                link=(f"{scheme}://{q(user)}:{q(pw)}@{ip}:{port('naive')}?sni={SNI}&uot=1"
                      f"{'&insecure=1' if INSECURE else ''}#{q(n)}"))
    if has("ss-obfs"):
        n = nm("ss-obfs")
        plug = "obfs-local;obfs=http;obfs-host=www.bing.com"
        add("ss-obfs", n, dict(type="ss", server=ip, port=port("ss-obfs"), cipher="aes-256-gcm", password=c["ss_pass"],
                               udp=False, plugin="obfs", **{"plugin-opts": {"mode": "http", "host": "www.bing.com"}}),
            link=f"ss://{b64u(('aes-256-gcm:' + c['ss_pass']).encode())}@{ip}:{port('ss-obfs')}?plugin={q(plug)}#{q(n)}")
    if has("ss-v2ray"):
        n = nm("ss-v2ray")
        plug = f"v2ray-plugin;mode=websocket;host={SNI};path={c['v2ray_path']}"
        add("ss-v2ray", n, dict(type="ss", server=ip, port=port("ss-v2ray"), cipher="aes-256-gcm", password=c["ss_pass"],
                                udp=False, plugin="v2ray-plugin",
                                **{"plugin-opts": {"mode": "websocket", "host": SNI, "path": c["v2ray_path"]}}),
            link=None if "tls" in plug else
            f"ss://{b64u(('aes-256-gcm:' + c['ss_pass']).encode())}@{ip}:{port('ss-v2ray')}?plugin={q(plug)}#{q(n)}")
    if has("ss-kcptun"):
        n = nm("ss-kcptun")
        opts = {"key": c["kcp_key"], "crypt": "aes", "mode": "fast", "nocomp": True, "smuxver": 1,
                "datashard": 10, "parityshard": 3, "mtu": 1350, "sndwnd": 1024, "rcvwnd": 1024}
        add("ss-kcptun", n, dict(type="ss", server=ip, port=port("ss-kcptun"), cipher="aes-256-gcm",
                                 password=c["ss_pass"], udp=False, plugin="kcptun", **{"plugin-opts": opts}),
            note="kcptun 参数含数字/布尔，用 YAML 片段")
    if has("ss-cloak"):
        n = nm("ss-cloak")
        opts = {"UID": c["ck_uid"], "PublicKey": c["ck_pub"], "ServerName": "www.bing.com",
                "EncryptionMethod": "plain", "BrowserSig": "chrome", "NumConn": 4, "ProxyMethod": "shadowsocks"}
        add("ss-cloak", n, dict(type="ss", server=ip, port=port("ss-cloak"), cipher="aes-256-gcm",
                                password=c["ss_pass"], udp=False, plugin="cloak", **{"plugin-opts": opts}))
    if has("ss-restls"):
        n = nm("ss-restls")
        add("ss-restls", n, dict(type="ss", server=ip, port=port("ss-restls"), cipher="aes-256-gcm",
                                 password=c["ss_pass"], udp=False, plugin="restls",
                                 **{"client-fingerprint": "chrome",
                                    "plugin-opts": {"host": REALITY_DEST, "password": c["restls_pass"],
                                                    "version-hint": "tls13", "restls-script": RESTLS_SCRIPT}}))
    if has("ssr"):
        n = nm("ssr")
        main = f"{ip}:{port('ssr')}:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{b64u(c['ssr_pass'].encode())}"
        tail = f"/?remarks={b64u(n.encode())}&obfsparam=&protoparam="
        add("ssr", n, dict(type="ssr", server=ip, port=port("ssr"), cipher="aes-256-cfb", password=c["ssr_pass"],
                           protocol="auth_aes128_md5", obfs="tls1.2_ticket_auth", udp=True),
            link="ssr://" + b64u((main + tail).encode()))
    for v in ("4", "5"):
        pid = "snell" + v
        if has(pid):
            n = nm(pid)
            add(pid, n, dict(type="snell", server=ip, port=port(pid), psk=c["snell_psk"], password=c["snell_psk"],
                             version=int(v), udp=True),
                surge=f"{n} = snell, {ip}, {port(pid)}, psk={c['snell_psk']}, version={v}",
                note="snell:// 链接与只写 psk 的 YAML 落到 psk 字段，而拨号读 password（见报告）；Surge 行由 "
                     "NCConfImport 映射为 password，故二维码用 Surge 行；订阅 YAML 同时写 psk 与 password")
    if has("mieru"):
        n = nm("mieru")
        add("mieru", n, dict(type="mieru", server=ip, port=port("mieru"), transport="TCP", username=user, password=pw,
                             udp=True, multiplexing="MULTIPLEXING_LOW"),
            link=f"mierus://{q(user)}:{q(pw)}@{ip}?profile={q(n)}&port={port('mieru')}&protocol=TCP")
    if has("ssh"):
        n = nm("ssh")
        add("ssh", n, dict(type="ssh", server=ip, port=port("ssh"), username=user, password=pw),
            link=f"ssh://{q(user)}:{q(pw)}@{ip}:{port('ssh')}#{q(n)}")
    if has("brook"):
        n = nm("brook")
        add("brook", n, dict(type="brook", server=ip, port=port("brook"), password=pw, transport="server", udp=True),
            link=f"brook://server?server={q(ip + ':' + str(port('brook')))}&password={q(pw)}&name={q(n)}")
    if has("gost-relay"):
        n = nm("gost-relay")
        add("gost-relay", n, dict(type="gost-relay", server=ip, port=port("gost-relay"), username=user, password=pw,
                                  tls=True, udp=True, **tlsf))
    if has("juicity"):
        n = nm("juicity")
        add("juicity", n, dict(type="juicity", server=ip, port=port("juicity"), uuid=c["uuid"], password=pw,
                               udp=True, **{"congestion-controller": "bbr"}, **tlsf),
            link=(f"juicity://{c['uuid']}:{q(pw)}@{ip}:{port('juicity')}?sni={SNI}&congestion_control=bbr"
                  f"{'&allow_insecure=1' if INSECURE else ''}#{q(n)}"))
    if has("wireguard"):
        n = nm("wireguard")
        add("wireguard", n, dict(type="wireguard", server=ip, port=port("wireguard"), ip="10.66.0.2",
                                 udp=True, mtu=1280, dns=["1.1.1.1"],
                                 **{"private-key": c["wg_cli_priv"], "public-key": c["wg_srv_pub"],
                                    "remote-dns-resolve": True}),
            link=(f"wireguard://{ip}:{port('wireguard')}?privatekey={q(c['wg_cli_priv'])}"
                  f"&publickey={q(c['wg_srv_pub'])}&address={q('10.66.0.2/32')}&mtu=1280#{q(n)}"))
    if has("awg"):
        n = nm("awg")
        h = c["awg_h"]
        add("awg", n, dict(type="wireguard", server=ip, port=port("awg"), ip="10.67.0.2", udp=True, mtu=1280,
                           dns=["1.1.1.1"],
                           **{"private-key": c["awg_cli_priv"], "public-key": c["awg_srv_pub"],
                              "remote-dns-resolve": True,
                              "amnezia-wg-option": {"jc": 4, "jmin": 40, "jmax": 70, "s1": c["awg_s1"],
                                                    "s2": c["awg_s2"], "h1": h[0], "h2": h[1], "h3": h[2],
                                                    "h4": h[3]}}),
            note="wireguard:// 链接不带 AmneziaWG 参数，用 YAML 片段")
    if has("openconnect"):
        n = nm("openconnect")
        add("openconnect", n, dict(type="openconnect", server=ip, port=port("openconnect"), username=user,
                                   password=pw, dtls=True, udp=True, **tlsf),
            link=(f"openconnect://{q(user)}:{q(pw)}@{ip}:{port('openconnect')}?sni={SNI}&dtls=1"
                  f"{'&insecure=1' if INSECURE else ''}#{q(n)}"))
    if has("trusttunnel"):
        for quic, sfx in ((False, "-H2"), (True, "-H3")):
            n = nm("trusttunnel", sfx)
            add("trusttunnel", n, dict(type="trusttunnel", server=ip, port=port("trusttunnel"), username=user,
                                       password=pw, quic=quic, udp=True, **tlsf),
                link=(f"trusttunnel://{q(user)}:{q(pw)}@{ip}:{port('trusttunnel')}?sni={SNI}"
                      f"{'&quic=true' if quic else ''}{'&skip-cert-verify=true' if INSECURE else ''}#{q(n)}"))
    if has("sudoku"):
        n = nm("sudoku")
        key = c.get("sudoku_priv", "")
        sj = {"h": ip, "p": port("sudoku"), "k": key, "e": "chacha20-poly1305", "a": "prefer_entropy", "x": False,
              "hd": False, "hm": "legacy", "n": n}
        add("sudoku", n, dict(type="sudoku", server=ip, port=port("sudoku"), key=key,
                              **{"aead-method": "chacha20-poly1305", "table-type": "prefer_entropy"}),
            link="sudoku://" + b64u(json.dumps(sj, separators=(",", ":")).encode()))  # name rides in "n"; the official parser rejects a #fragment
    if has("masque-ip"):
        n = nm("masque-ip")
        add("masque-ip", n, dict(type="masque", server=ip, port=port("masque-ip"), mode="connect-ip",
                                 uri=f"https://proxy:{port('masque-ip')}/vpn", sni=DOMAIN or "proxy",
                                 mtu=1200, dns=["1.1.1.1"], udp=True,
                                 **({"skip-cert-verify": True} if INSECURE else {})),
            note="masque:// 链接不带 mode / skip-cert-verify，用 YAML 片段；uri 主机必须是 proxy（connect-ip-go 固定模板）")
    if has("masque-udp"):
        n = nm("masque-udp")
        add("masque-udp", n, dict(type="masque", server=ip, port=port("masque-udp"), mode="connect-udp",
                                  username="tern", password="tern",
                                  uri=f"https://{SNI}:{port('masque-udp')}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
                                  udp=True, **tlsf),
            note="CONNECT-UDP 只承载 UDP（TCP 流经此节点会被拒），masque-go 不校验凭据，填任意值")
    return nodes


def write_nodes(st, nodes):
    c = st["creds"]
    names = [n["name"] for n in nodes]
    lines = ["# Tern 自测订阅 — 由 tools/server-test/install.sh 生成", "proxies:"]
    lines += ["  " + n["yaml_line"] for n in nodes]
    lines += ["proxy-groups:", "  - " + yaml_flow({"name": "Tern-Test", "type": "select", "proxies": names}),
              "rules:", "  - MATCH,Tern-Test", ""]
    sub = "\n".join(lines)
    wfile(os.path.join(STATE_DIR, "tern-nodes.yaml"), sub)
    wfile(os.path.join(BASE, "sub", c["sub_token"], "tern.yaml"), sub, 0o644)
    scheme = "https" if not INSECURE else "https"
    host = DOMAIN or IP
    sub_urls = {"https": f"{scheme}://{host}:{SUB_HTTPS}/{c['sub_token']}/tern.yaml"}
    if INSECURE:
        sub_urls["http"] = f"http://{IP}:{SUB_HTTP}/{c['sub_token']}/tern.yaml"
    out = {"nodes": nodes, "sub": sub_urls, "sni": SNI, "insecure": INSECURE, "cert_sha256": CERT_SHA256,
           "ip": IP, "domain": DOMAIN}
    wfile(os.path.join(STATE_DIR, "nodes.json"), json.dumps(out, indent=2, ensure_ascii=False))
    wfile(os.path.join(STATE_DIR, "links.txt"), "\n".join(n["qr"] for n in nodes if n["qr_kind"] != "yaml") + "\n")
    srv = f"""#!/usr/bin/env python3
# Tern self-test subscription server: serves exactly one file under a random token path.
import http.server, os, ssl, sys, threading
FILE = {json.dumps(os.path.join(BASE, 'sub', c['sub_token'], 'tern.yaml'))}
PATH = {json.dumps('/' + c['sub_token'] + '/tern.yaml')}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split('?')[0] != PATH:
            self.send_response(404); self.end_headers(); return
        data = open(FILE, 'rb').read()
        self.send_response(200)
        self.send_header('Content-Type', 'text/yaml; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Content-Disposition', 'attachment; filename="tern-test.yaml"')
        self.end_headers(); self.wfile.write(data)
    def log_message(self, *a):
        pass
class S(http.server.ThreadingHTTPServer):
    daemon_threads = True
def https():
    s = S(('0.0.0.0', {SUB_HTTPS}), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain({json.dumps(CERT)}, {json.dumps(KEY)})
    s.socket = ctx.wrap_socket(s.socket, server_side=True)
    s.serve_forever()
ts = [threading.Thread(target=https, daemon=True)]
if {INSECURE!r}:
    ts.append(threading.Thread(target=S(('0.0.0.0', {SUB_HTTP}), H).serve_forever, daemon=True))
for t in ts: t.start()
for t in ts: t.join()
"""
    wfile(os.path.join(BASE, "subserver.py"), srv, 0o755)


# ---------------------------------------------------------------------------------------------- show
def systemd_state(unit_name):
    if not shutil.which("systemctl"):
        return "-"
    r = subprocess.run(["systemctl", "is-active", unit_name], capture_output=True, text=True)
    return r.stdout.strip() or "?"


UNIT_OF = {"socks": "tern-sing-box", "http": "tern-sing-box", "https": "tern-sing-box", "ss": "tern-sing-box",
           "ss2022": "tern-sing-box", "ss-shadowtls": "tern-sing-box", "vmess": "tern-sing-box",
           "vmess-ws": "tern-sing-box", "vless": "tern-sing-box", "vless-reality": "tern-sing-box",
           "vless-vision": "tern-sing-box", "trojan": "tern-sing-box", "hysteria": "tern-sing-box",
           "hysteria2": "tern-sing-box", "tuic": "tern-sing-box", "anytls": "tern-sing-box", "naive": "tern-sing-box",
           "vless-enc": "tern-xray", "ss-obfs": "tern-ssrust", "ss-v2ray": "tern-ssrust", "ss-kcptun": "tern-kcptun",
           "ss-cloak": "tern-cloak", "ss-restls": "tern-restls", "ssr": "tern-ssr", "snell4": "tern-snell4",
           "snell5": "tern-snell5", "mieru": "mita", "ssh": "tern-sshd", "brook": "tern-brook",
           "gost-relay": "tern-gost", "juicity": "tern-juicity", "wireguard": "tern-wg", "awg": "tern-awg",
           "openconnect": "tern-ocserv", "trusttunnel": "tern-trusttunnel", "sudoku": "tern-sudoku",
           "masque-ip": "tern-connectip", "masque-udp": "tern-masque"}


def show(qr=True):
    with open(os.path.join(STATE_DIR, "nodes.json")) as f:
        d = json.load(f)
    nodes = d["nodes"]
    qrdir = os.path.join(STATE_DIR, "qr")
    os.makedirs(qrdir, exist_ok=True)
    have_qr = shutil.which("qrencode") is not None
    B, R = "\033[1m", "\033[0m"
    print(f"\n{B}==== 端口一览 (服务器 {d['ip']}{' / ' + d['domain'] if d['domain'] else ''}) ===={R}")
    print(f"{'端口':<14}{'协议':<28}{'服务':<18}状态")
    seen = set()
    for pid in SELECTED or [n["id"] for n in nodes]:
        if pid in seen or pid not in PROTOS:
            continue
        seen.add(pid)
        u = UNIT_OF[pid]
        print(f"{str(port(pid)) + '/' + PROTOS[pid][1]:<14}{PROTOS[pid][2]:<28}{u:<18}{systemd_state(u)}")
    print(f"{str(SUB_HTTPS) + '/tcp':<14}{'订阅 (HTTPS)':<28}{'tern-sub':<18}{systemd_state('tern-sub')}")
    if d["insecure"]:
        print(f"{str(SUB_HTTP) + '/tcp':<14}{'订阅 (HTTP 备用)':<28}{'tern-sub':<18}{systemd_state('tern-sub')}")
    if d["insecure"]:
        print(f"\n证书：自签（SNI {d['sni']}），节点已带 skip-cert-verify: true。证书 SHA-256 指纹：{d['cert_sha256']}")
    else:
        print(f"\n证书：Let's Encrypt（{d['domain']}），节点不跳过证书校验。")
    for i, n in enumerate(nodes, 1):
        print(f"\n{B}[{i}/{len(nodes)}] {n['name']}{R}  ({PROTOS[n['id']][2]}, 二维码内容：{ {'link': '分享链接', 'surge': 'Surge 节点行', 'yaml': 'Clash YAML 片段'}[n['qr_kind']] })")
        png = os.path.join(qrdir, f"{i:02d}-{n['name']}.png")
        if have_qr:
            subprocess.run(["qrencode", "-o", png, "-s", "6", "-m", "2", n["qr"]], check=False)
            if qr:
                subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "1", n["qr"]], check=False)
        print(n["qr"])
        if n["qr_kind"] != "yaml":
            print("YAML: " + n["yaml_line"])
        if n.get("note"):
            print("说明: " + n["note"])
    print(f"\n{B}==== 订阅（一次导入全部节点）===={R}")
    for k, url in d["sub"].items():
        png = os.path.join(qrdir, f"00-subscription-{k}.png")
        if have_qr:
            subprocess.run(["qrencode", "-o", png, "-s", "6", "-m", "2", url], check=False)
            if qr:
                subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "1", url], check=False)
        print(f"{k.upper()}: {url}")
    if d["insecure"]:
        print("注意：自签证书下 iOS 不信任 HTTPS 订阅地址；请用 HTTP 备用地址，或重装时加 --domain auto / --domain 你的域名。")
    print(f"\n全部节点 YAML：{os.path.join(STATE_DIR, 'tern-nodes.yaml')}    二维码 PNG：{qrdir}/")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "render"
    if cmd == "render":
        st = load_state()
        render_servers(st["creds"])
        write_nodes(st, build_nodes(st["creds"]))
        print(json.dumps({"user": st["creds"]["user"], "pass": st["creds"]["pass"]}))
    elif cmd == "show":
        show(qr="--no-qr" not in sys.argv)
    elif cmd == "get":
        st = load_state() if False else json.load(open(os.path.join(STATE_DIR, "state.json")))
        print(st["creds"][sys.argv[2]])
    else:
        sys.exit("usage: render.py render|show|get KEY")


if __name__ == "__main__":
    main()
PYEOF
    chmod 755 "$BASE/render.py"
}

# ------------------------------------------------------------------------------------------------ main
run_render() {  # environment for render.py
    TT_BASE="$BASE" TT_STATE="$STATE" TT_PORT_BASE="$PORT_BASE" TT_IP="$IP" TT_DOMAIN="$DOMAIN" \
        TT_CERT_SHA256="$CERT_SHA256" TT_PROTOS="${PROTOS// /,}" python3 "$BASE/render.py" "$@"
}

main_install() {
    [ "$(id -u)" = 0 ] || die "请用 root 运行（sudo -i 后再执行）"
    command -v systemctl >/dev/null 2>&1 || die "需要 systemd"
    log "Tern 服务器自测工具包 v$KIT_VERSION"
    detect_os
    [ -n "$PROTOS" ] || die "没有选中任何协议"
    log "协议：$PROTOS"
    mkdir -p "$BASE"/{bin,etc,var,units} "$STATE"; chmod 700 "$STATE"
    log "apt-get update"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq; APT_UPDATED=1
    ensure_universe   # Ubuntu: qrencode / certbot / ocserv / simple-obfs / kcptun / v2ray-plugin are in universe
    apt_install curl ca-certificates openssl python3 qrencode iptables iproute2 tar xz-utils procps
    detect_ip
    want ss-obfs && apt_install simple-obfs
    want ss-v2ray && apt_install shadowsocks-v2ray-plugin
    want ss-kcptun && apt_install kcptun
    want ssh && apt_install openssh-server
    want wireguard && apt_install wireguard-tools
    want masque-ip && apt_install ethtool
    if want openconnect; then
        apt_install ocserv
        # the distro unit would listen on 443 with its own config — ours runs as tern-ocserv.service
        systemctl disable --now ocserv.service ocserv.socket >/dev/null 2>&1 || true
    fi
    install_binaries
    build_go_servers
    setup_cert
    write_render_py
    run_render render >/dev/null
    printf 'TT_NO_FW=%s\n' "$NO_FW" >> "$BASE/net.env"
    if [ -n "$DOMAIN" ]; then
        sed -i 's|^TT_PORTS="|TT_PORTS="80/tcp |' "$BASE/net.env"
    fi
    post_render
    write_net_sh
    ufw_sync
    install_units
    sleep 3
    run_render show
    echo
    log "完成。之后可用  bash install.sh --show  重新查看，  bash install.sh --uninstall  卸载。"
    log "云厂商的安全组 / 防火墙需另行放行上表端口（TCP 与 UDP）。"
}

main_render_only() {  # developer check without root/systemd: render every config into $RENDER_DIR
    [ -n "$RENDER_DIR" ] || die "--render-only 需要目录"
    BASE="$RENDER_DIR/opt"; STATE="$RENDER_DIR/state"
    mkdir -p "$BASE"/{bin,etc,var,units,certs} "$STATE"
    [ -n "$IP" ] || IP="203.0.113.10"
    [ -n "${TT_BIN_DIR:-}" ] && for f in "$TT_BIN_DIR"/*; do ln -sf "$f" "$BASE/bin/"; done
    if [ ! -s "$BASE/certs/cert.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=tern.test" \
            -addext "subjectAltName=DNS:tern.test,DNS:proxy,IP:$IP" \
            -keyout "$BASE/certs/key.pem" -out "$BASE/certs/cert.pem" >/dev/null 2>&1
    fi
    CERT_SHA256="$(openssl x509 -in "$BASE/certs/cert.pem" -noout -fingerprint -sha256 | cut -d= -f2)"
    write_render_py
    run_render render >/dev/null
    write_net_sh
    run_render show --no-qr
}

case "$ACTION" in
    install) main_install ;;
    show)
        [ -f "$STATE/nodes.json" ] || die "还没有安装（找不到 $STATE/nodes.json）"
        PROTOS="$(python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["selected"]))' "$STATE/state.json")"
        PORT_BASE="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["port_base"])' "$STATE/state.json")"
        TT_BASE="$BASE" TT_STATE="$STATE" TT_PORT_BASE="$PORT_BASE" TT_PROTOS="${PROTOS// /,}" python3 "$BASE/render.py" show ;;
    uninstall) do_uninstall ;;
    render) main_render_only ;;
esac
