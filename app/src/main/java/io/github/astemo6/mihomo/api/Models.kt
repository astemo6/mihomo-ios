package io.github.astemo6.mihomo.api

import kotlinx.serialization.Serializable

// mihomo external-controller REST models (decoded tolerantly; unknown keys ignored)

@Serializable
data class DelayHistory(val time: String? = null, val delay: Int = 0)

@Serializable
data class ExtraDelay(val alive: Boolean? = null, val history: List<DelayHistory>? = null)

@Serializable
data class ProxyItem(
    val name: String,
    val type: String = "",
    val now: String? = null,
    val all: List<String>? = null,
    val history: List<DelayHistory>? = null,
    val alive: Boolean? = null,
    val udp: Boolean? = null,
    val hidden: Boolean? = null,
    val icon: String? = null,
    val testUrl: String? = null,
    val fixed: String? = null,
    val extra: Map<String, ExtraDelay>? = null,
) {
    val isGroup: Boolean get() = all != null
    val isSelectable: Boolean get() = type == "Selector"
    val lastDelay: Int? get() = history?.lastOrNull()?.delay
    fun lastDelay(url: String): Int? = extra?.get(url)?.history?.lastOrNull()?.delay ?: lastDelay
}

@Serializable
data class ProxiesResponse(val proxies: Map<String, ProxyItem> = emptyMap())

@Serializable
data class ConnectionMetadata(
    val network: String? = null,
    val type: String? = null,
    val sourceIP: String? = null,
    val destinationIP: String? = null,
    val sourcePort: String? = null,
    val destinationPort: String? = null,
    val host: String? = null,
    val sniffHost: String? = null,
    val process: String? = null,
    val processPath: String? = null,
    val remoteDestination: String? = null,
) {
    val displayHost: String
        get() {
            val h = host?.takeIf { it.isNotEmpty() } ?: sniffHost?.takeIf { it.isNotEmpty() } ?: destinationIP ?: "?"
            return if (!destinationPort.isNullOrEmpty()) "$h:$destinationPort" else h
        }
}

@Serializable
data class ConnectionItem(
    val id: String,
    val metadata: ConnectionMetadata = ConnectionMetadata(),
    val upload: Long = 0,
    val download: Long = 0,
    val start: String? = null,
    val chains: List<String>? = null,
    val rule: String? = null,
    val rulePayload: String? = null,
) {
    val chainText: String get() = (chains ?: emptyList()).reversed().joinToString(" ➤ ")
    val ruleText: String
        get() {
            val r = rule ?: return ""
            return if (!rulePayload.isNullOrEmpty()) "$r($rulePayload)" else r
        }
}

@Serializable
data class ConnectionsResponse(
    val downloadTotal: Long? = null,
    val uploadTotal: Long? = null,
    val connections: List<ConnectionItem>? = null,
    val memory: Long? = null,
)

@Serializable
data class RuleItem(
    val index: Int? = null,
    val type: String = "",
    val payload: String = "",
    val proxy: String = "",
    val size: Int? = null,
)

@Serializable
data class RulesResponse(val rules: List<RuleItem> = emptyList())

@Serializable
data class SubscriptionInfoAPI(
    val Upload: Long? = null,
    val Download: Long? = null,
    val Total: Long? = null,
    val Expire: Long? = null,
)

@Serializable
data class ProviderItem(
    val name: String,
    val type: String? = null,
    val vehicleType: String? = null,
    val behavior: String? = null,
    val format: String? = null,
    val ruleCount: Int? = null,
    val updatedAt: String? = null,
    val proxies: List<ProxyItem>? = null,
    val subscriptionInfo: SubscriptionInfoAPI? = null,
)

@Serializable
data class ProvidersResponse(val providers: Map<String, ProviderItem> = emptyMap())

@Serializable
data class TrafficSample(val up: Long = 0, val down: Long = 0)

@Serializable
data class MemorySample(val inuse: Long = 0, val oslimit: Long? = null)

@Serializable
data class LogPayload(val type: String = "info", val payload: String = "")

data class LogLine(val id: Long, val level: String, val message: String, val time: Long)

object ProxyTypes {
    /** Group / protocol label like the iOS app (zh strings resolved in UI for groups). */
    fun short(type: String): String = when (type.lowercase()) {
        "shadowsocks", "ss" -> "SS"
        "shadowsocksr", "ssr" -> "SSR"
        "vmess" -> "VMess"
        "vless" -> "VLESS"
        "trojan" -> "Trojan"
        "hysteria2" -> "Hy2"
        "hysteria" -> "Hysteria"
        "tuic" -> "TUIC"
        "wireguard" -> "WireGuard"
        "snell" -> "Snell"
        "anytls" -> "AnyTLS"
        "mieru" -> "Mieru"
        "ssh" -> "SSH"
        "socks5" -> "SOCKS5"
        "http" -> "HTTP"
        else -> type
    }

    val groupTypes = setOf("selector", "urltest", "fallback", "loadbalance", "relay")
}
