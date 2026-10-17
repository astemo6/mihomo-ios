package io.github.astemo6.mihomo.api

import io.github.astemo6.mihomo.data.AppJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Egress IP / location / ASN for the header. The app is not excluded from its own VPN (see HANDOFF:
 * protect() instead of addDisallowedApplication), so these requests leave through the selected policy.
 */
@Serializable
data class IpInfo(
    val ip: String,
    val countryCode: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
    val asn: String? = null,
    val org: String? = null,
    val source: String? = null,
) {
    val flag: String
        get() {
            val cc = countryCode?.uppercase(Locale.ROOT)?.takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } } ?: return "🌐"
            val sb = StringBuilder()
            cc.forEach { sb.appendCodePoint(0x1F1E6 + (it - 'A')) }
            return sb.toString()
        }

    val locationText: String
        get() = listOfNotNull(city?.takeIf { it.isNotBlank() }, region?.takeIf { it.isNotBlank() && it != city },
            country?.takeIf { it.isNotBlank() } ?: countryCode).distinct().joinToString(", ")

    val asnText: String get() = listOfNotNull(asn, org).joinToString(" · ")

    companion object {
        private val client by lazy {
            OkHttpClient.Builder().connectTimeout(6, TimeUnit.SECONDS).readTimeout(6, TimeUnit.SECONDS)
                .callTimeout(8, TimeUnit.SECONDS).build()
        }

        private fun JsonObject.s(vararg keys: String): String? {
            for (k in keys) {
                val v = this[k] ?: continue
                val str = runCatching { v.jsonPrimitive.contentOrNull }.getOrNull()
                if (!str.isNullOrBlank()) return str
            }
            return null
        }

        /** "AS13335 Cloudflare, Inc." → ("AS13335", "Cloudflare, Inc.") */
        private fun splitAsOrg(s: String?): Pair<String?, String?> {
            if (s.isNullOrBlank()) return null to null
            val m = Regex("^(AS\\d+)\\s*(.*)$", RegexOption.IGNORE_CASE).find(s.trim()) ?: return null to s
            return m.groupValues[1].uppercase() to m.groupValues[2].ifBlank { null }
        }

        private fun normAsn(v: String?): String? {
            val t = v?.trim()?.takeIf { it.isNotEmpty() } ?: return null
            return if (t.all { it.isDigit() }) "AS$t" else t.uppercase()
        }

        private class Endpoint(val name: String, val url: String, val parse: (JsonObject) -> IpInfo?)

        private val endpoints = listOf(
            Endpoint("ipinfo.io", "https://ipinfo.io/json") p@{ d ->
                val ip = d.s("ip") ?: return@p null
                val (asn, org) = splitAsOrg(d.s("org"))
                IpInfo(ip, d.s("country"), null, d.s("region"), d.s("city"), asn, org)
            },
            Endpoint("ip-api.com", "http://ip-api.com/json/?fields=status,query,country,countryCode,regionName,city,isp,org,as&lang=en") p@{ d ->
                val ip = d.s("query") ?: return@p null
                val (asn, org) = splitAsOrg(d.s("as"))
                IpInfo(ip, d.s("countryCode"), d.s("country"), d.s("regionName"), d.s("city"), asn, org ?: d.s("isp", "org"))
            },
            Endpoint("ipwho.is", "https://ipwho.is/") p@{ d ->
                val ip = d.s("ip") ?: return@p null
                val conn = d["connection"]?.let { runCatching { it.jsonObject }.getOrNull() }
                IpInfo(ip, d.s("country_code"), d.s("country"), d.s("region"), d.s("city"),
                    normAsn(conn?.s("asn")), conn?.s("org", "isp"))
            },
            Endpoint("ip.sb", "https://api.ip.sb/geoip") p@{ d ->
                val ip = d.s("ip") ?: return@p null
                IpInfo(ip, d.s("country_code"), d.s("country"), d.s("region"), d.s("city"),
                    normAsn(d.s("asn")), d.s("asn_organization", "organization", "isp"))
            },
        )

        suspend fun fetch(): IpInfo? = withContext(Dispatchers.IO) {
            for (ep in endpoints) {
                val info = runCatching {
                    val req = Request.Builder().url(ep.url).header("User-Agent", "curl/8.4.0").header("Accept", "application/json").build()
                    client.newCall(req).execute().use { r ->
                        if (!r.isSuccessful) null
                        else ep.parse(AppJson.parseToJsonElement(r.body?.string().orEmpty()).jsonObject)
                    }
                }.getOrNull()
                if (info != null) return@withContext info.copy(source = ep.name)
            }
            null
        }
    }
}
