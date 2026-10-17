package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.core.Paths
import kotlinx.serialization.Serializable
import java.io.File

/** <home>/dns.json (core/dns.go DNSOverride), same fields and defaults as the iOS DNSOverrideSettings. */
@Serializable
data class DnsOverride(
    val enabled: Boolean = false,
    val nameserver: List<String> = listOf("https://223.5.5.5/dns-query", "https://doh.pub/dns-query"),
    val foreign: List<String> = listOf("https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"),
    val split: Boolean = true,
    val defaultNameserver: List<String> = listOf("223.5.5.5", "119.29.29.29"),
    val directNameserver: List<String> = emptyList(),
    val proxyNameserver: List<String> = emptyList(),
    val fallback: List<String> = emptyList(),
    val fallbackFilter: Fallback = Fallback(),
    val fakeIPRange: String = "",
    val fakeIPFilter: List<String> = emptyList(),
    val fakeIPFilterMode: String = "blacklist",
    val policy: List<Policy> = emptyList(),
    val preferH3: Boolean = false,
    val respectRules: Boolean = false,
    val cacheAlgorithm: String = "",
    val useHosts: Boolean? = null,
    val useSystemHosts: Boolean? = null,
) {
    @Serializable
    data class Fallback(
        val geoip: Boolean = true,
        val geoipCode: String = "CN",
        val ipcidr: List<String> = emptyList(),
        val domain: List<String> = emptyList(),
        val geosite: List<String> = emptyList(),
    )

    @Serializable
    data class Policy(val match: String, val servers: List<String>)

    companion object {
        private val file: File get() = File(Paths.home, "dns.json")
        fun load(): DnsOverride = runCatching { AppJson.decodeFromString(serializer(), file.readText()) }.getOrDefault(DnsOverride())
    }

    fun save() = file.writeText(AppJson.encodeToString(serializer(), this))
}

/** <home>/localdns.json (core/localdns.go): 本地 DNS 映射 (hosts) and 真实 IP 域名 (fake-ip-filter). */
@Serializable
data class LocalDns(
    val hosts: List<Host> = emptyList(),
    val realIP: List<String> = emptyList(),
) {
    @Serializable
    data class Host(val domain: String = "", val value: String = "", val disabled: Boolean = false)

    companion object {
        private val file: File get() = File(Paths.home, "localdns.json")
        fun load(): LocalDns = runCatching { AppJson.decodeFromString(serializer(), file.readText()) }.getOrDefault(LocalDns())
    }

    fun save() = file.writeText(AppJson.encodeToString(serializer(), this))
}
