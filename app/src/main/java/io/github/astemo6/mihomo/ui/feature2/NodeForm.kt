package io.github.astemo6.mihomo.ui.feature2

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull

/** Declarative per-protocol form (iOS NodeEditorView / NodeProtocols). Keys are mihomo proxy keys; dots = nested maps. */
data class FieldSpec(val key: String, val label: String, val kind: Kind = Kind.TEXT, val placeholder: String = "", val choices: List<String> = emptyList()) {
    enum class Kind { TEXT, SECURE, INT, BOOL, CHOICE, LIST }
}

object NodeProtocols {
    val all = listOf(
        "ss" to "Shadowsocks", "ssr" to "ShadowsocksR", "vmess" to "VMess", "vless" to "VLESS", "trojan" to "Trojan",
        "hysteria2" to "Hysteria2", "hysteria" to "Hysteria", "tuic" to "TUIC v5", "wireguard" to "WireGuard", "snell" to "Snell",
        "anytls" to "AnyTLS", "mieru" to "Mieru", "ssh" to "SSH", "socks5" to "SOCKS5", "http" to "HTTP(S)",
    )

    private val ssCiphers = listOf("aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
        "aes-128-cfb", "aes-256-cfb", "aes-128-ctr", "aes-256-ctr", "rc4-md5", "chacha20-ietf", "none")

    // Labels are string keys resolved by the UI (FieldLabels); unknown ones are shown as is.
    private fun t(k: String, l: String, p: String = "") = FieldSpec(k, l, placeholder = p)
    private fun s(k: String, l: String, p: String = "") = FieldSpec(k, l, FieldSpec.Kind.SECURE, p)
    private fun i(k: String, l: String, p: String = "") = FieldSpec(k, l, FieldSpec.Kind.INT, p)
    private fun b(k: String, l: String) = FieldSpec(k, l, FieldSpec.Kind.BOOL)
    private fun c(k: String, l: String, vararg o: String) = FieldSpec(k, l, FieldSpec.Kind.CHOICE, choices = o.toList())
    private fun l(k: String, l: String, p: String = "") = FieldSpec(k, l, FieldSpec.Kind.LIST, p)

    private val transport = listOf(
        c("network", "transport", "tcp", "ws", "grpc", "h2", "httpupgrade"),
        t("ws-opts.path", "ws_path", "/"), t("ws-opts.headers.Host", "ws_host"), t("grpc-opts.grpc-service-name", "grpc_service"),
    )
    private val tlsCommon = listOf(b("skip-cert-verify", "skip_cert"), c("client-fingerprint", "tls_fp", "", "chrome", "firefox", "safari", "ios", "edge", "random"))

    fun fields(type: String): List<FieldSpec> = when (type) {
        "ss" -> listOf(FieldSpec("cipher", "cipher", FieldSpec.Kind.CHOICE, choices = ssCiphers), s("password", "password"),
            c("plugin", "plugin", "", "obfs", "v2ray-plugin", "shadow-tls"), t("plugin-opts.mode", "plugin_mode", "http / tls / websocket"),
            t("plugin-opts.host", "plugin_host"), t("plugin-opts.path", "plugin_path"), s("plugin-opts.password", "shadowtls_password"),
            i("plugin-opts.version", "shadowtls_version", "3"), b("udp", "udp"))
        "ssr" -> listOf(FieldSpec("cipher", "cipher", FieldSpec.Kind.CHOICE, choices = ssCiphers), s("password", "password"),
            c("obfs", "obfs", "plain", "http_simple", "http_post", "tls1.2_ticket_auth", "random_head"), t("obfs-param", "obfs_param"),
            c("protocol", "protocol", "origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"),
            t("protocol-param", "protocol_param"), b("udp", "udp"))
        "vmess" -> listOf(t("uuid", "UUID"), i("alterId", "alterId", "0"), c("cipher", "cipher", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"),
            b("tls", "TLS"), t("servername", "SNI"), b("udp", "udp")) + transport + tlsCommon
        "vless" -> listOf(t("uuid", "UUID"), c("flow", "Flow", "", "xtls-rprx-vision"), b("tls", "TLS"), t("servername", "SNI"),
            t("reality-opts.public-key", "reality_pk"), t("reality-opts.short-id", "reality_sid"), b("udp", "udp")) + transport + tlsCommon
        "trojan" -> listOf(s("password", "password"), t("sni", "SNI"), b("udp", "udp")) + transport + tlsCommon
        "hysteria2" -> listOf(s("password", "password"), t("sni", "SNI"), c("obfs", "obfs", "", "salamander"), s("obfs-password", "obfs_password"),
            t("ports", "port_hopping", "20000-30000"), t("up", "up_bw", "50 Mbps"), t("down", "down_bw", "200 Mbps"), b("skip-cert-verify", "skip_cert"))
        "hysteria" -> listOf(s("auth-str", "auth"), c("protocol", "protocol", "udp", "wechat-video", "faketcp"), t("up", "up_bw", "50 Mbps"),
            t("down", "down_bw", "200 Mbps"), t("sni", "SNI"), t("obfs", "obfs"), l("alpn", "ALPN", "h3"), b("skip-cert-verify", "skip_cert"))
        "tuic" -> listOf(t("uuid", "UUID"), s("password", "password"), t("sni", "SNI"), l("alpn", "ALPN", "h3"),
            c("congestion-controller", "congestion", "bbr", "cubic", "new_reno"), c("udp-relay-mode", "udp_relay", "native", "quic"), b("skip-cert-verify", "skip_cert"))
        "wireguard" -> listOf(s("private-key", "private_key"), t("public-key", "peer_public_key"), s("pre-shared-key", "psk"),
            t("ip", "local_ipv4", "172.16.0.2"), t("ipv6", "local_ipv6"), t("reserved", "Reserved", "1,2,3"), i("mtu", "MTU", "1408"), b("udp", "udp"))
        "snell" -> listOf(s("psk", "PSK"), i("version", "version", "4"), c("obfs-opts.mode", "obfs", "", "http", "tls"), t("obfs-opts.host", "obfs_host"), b("udp", "udp"))
        "anytls" -> listOf(s("password", "password"), t("sni", "SNI"), b("udp", "udp")) + tlsCommon
        "mieru" -> listOf(t("username", "username"), s("password", "password"), c("transport", "transport", "TCP", "UDP"),
            t("port-range", "port_range", "2090-2099"), c("multiplexing", "multiplexing", "", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"))
        "ssh" -> listOf(t("username", "username"), s("password", "password"), s("private-key", "private_key_opt"))
        "socks5" -> listOf(t("username", "username"), s("password", "password"), b("tls", "TLS"), b("udp", "udp"), b("skip-cert-verify", "skip_cert"))
        "http" -> listOf(t("username", "username"), s("password", "password"), b("tls", "https_tls"), t("sni", "SNI"), b("skip-cert-verify", "skip_cert"))
        else -> emptyList()
    }

    private val echTypes = setOf("vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls")
    private val pinTypes = setOf("vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "http", "socks5")
    private val smuxTypes = setOf("ss", "vmess", "vless", "trojan")
    private val udpOnlyTypes = setOf("hysteria", "hysteria2", "tuic", "wireguard")

    fun advanced(type: String): List<FieldSpec> = buildList {
        if (type in echTypes) { add(b("ech-opts.enable", "ECH")); add(t("ech-opts.config", "ech_config", "Base64")) }
        if (type in pinTypes) add(t("fingerprint", "cert_fp", "SHA-256 (hex)"))
        if (type in smuxTypes) {
            add(b("smux.enabled", "smux")); add(c("smux.protocol", "smux_protocol", "", "h2mux", "smux", "yamux"))
            add(i("smux.max-connections", "smux_max", "4")); add(b("smux.padding", "smux_padding"))
        }
        if (type !in udpOnlyTypes) { add(b("tfo", "TCP Fast Open")); add(b("mptcp", "MPTCP")) }
        add(c("ip-version", "ip_version", "", "dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"))
    }

    fun defaults(type: String): Map<String, String> = when (type) {
        "ss" -> mapOf("cipher" to "aes-128-gcm", "udp" to "true")
        "ssr" -> mapOf("cipher" to "aes-256-cfb", "obfs" to "plain", "protocol" to "origin")
        "vmess" -> mapOf("cipher" to "auto", "alterId" to "0", "network" to "tcp", "udp" to "true")
        "vless" -> mapOf("network" to "tcp", "tls" to "true", "udp" to "true")
        "trojan", "anytls" -> mapOf("udp" to "true", "network" to "tcp")
        "tuic" -> mapOf("alpn" to "h3", "congestion-controller" to "bbr", "udp-relay-mode" to "native")
        "wireguard" -> mapOf("udp" to "true", "ip" to "172.16.0.2")
        "snell" -> mapOf("version" to "4", "udp" to "true")
        "mieru" -> mapOf("transport" to "TCP")
        "socks5" -> mapOf("udp" to "true")
        else -> emptyMap()
    }

    // ---- JSON <-> flat ------------------------------------------------------------------------

    fun flatten(o: JsonObject, prefix: String = "", out: MutableMap<String, String> = mutableMapOf()): MutableMap<String, String> {
        for ((k, v) in o) {
            val key = if (prefix.isEmpty()) k else "$prefix.$k"
            when (v) {
                is JsonObject -> flatten(v, key, out)
                is JsonArray -> out[key] = v.joinToString(",") { (it as? JsonPrimitive)?.contentOrNull ?: it.toString() }
                is JsonPrimitive -> out[key] = v.booleanOrNull?.toString() ?: v.contentOrNull.orEmpty()
                JsonNull -> {}
            }
        }
        return out
    }

    private fun setNested(m: MutableMap<String, JsonElement>, path: List<String>, value: JsonElement) {
        if (path.size == 1) { m[path[0]] = value; return }
        val child = (m[path[0]] as? JsonObject)?.toMutableMap() ?: mutableMapOf()
        setNested(child, path.drop(1), value)
        m[path[0]] = JsonObject(child)
    }

    private fun removeNested(m: MutableMap<String, JsonElement>, path: List<String>) {
        if (path.size == 1) { m.remove(path[0]); return }
        val child = (m[path[0]] as? JsonObject)?.toMutableMap() ?: return
        removeNested(child, path.drop(1))
        if (child.isEmpty()) m.remove(path[0]) else m[path[0]] = JsonObject(child)
    }

    fun build(original: JsonObject?, type: String, name: String, server: String, port: String, values: Map<String, String>, dialer: String): JsonObject {
        val d: MutableMap<String, JsonElement> =
            if (original != null && (original["type"] as? JsonPrimitive)?.contentOrNull == type) original.toMutableMap() else mutableMapOf()
        val specs = fields(type) + advanced(type)
        specs.forEach { removeNested(d, it.key.split('.')) }
        d["type"] = JsonPrimitive(type)
        val label = all.firstOrNull { it.first == type }?.second ?: type
        d["name"] = JsonPrimitive(name.trim().ifEmpty { "$label ${server.trim()}" })
        d["server"] = JsonPrimitive(server.trim())
        d["port"] = JsonPrimitive(port.trim().toIntOrNull() ?: 0)
        for (f in specs) {
            val raw = values[f.key]?.trim().orEmpty()
            if (raw.isEmpty()) continue
            val v: JsonElement = when (f.kind) {
                FieldSpec.Kind.INT -> raw.toIntOrNull()?.let { JsonPrimitive(it) } ?: JsonPrimitive(raw)
                FieldSpec.Kind.BOOL -> if (raw == "true") JsonPrimitive(true) else continue
                FieldSpec.Kind.LIST -> JsonArray(raw.split(',').map { JsonPrimitive(it.trim()) })
                else -> if (f.key == "reserved" && raw.contains(',')) JsonArray(raw.split(',').mapNotNull { it.trim().toIntOrNull()?.let(::JsonPrimitive) })
                else JsonPrimitive(raw)
            }
            setNested(d, f.key.split('.'), v)
        }
        if ((d["network"] as? JsonPrimitive)?.contentOrNull == "tcp") d.remove("network")
        if (dialer.isBlank()) d.remove("dialer-proxy") else d["dialer-proxy"] = JsonPrimitive(dialer.trim())
        return JsonObject(d)
    }
}
