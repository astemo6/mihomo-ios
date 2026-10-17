package io.github.astemo6.mihomo.data.feature2

import io.github.astemo6.mihomo.api.ApiException
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.api.IpInfo
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.io.IOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException

/**
 * 节点探测 (iOS PolicyProbe): HTTP(S) requests from the app through one chosen policy. The runtime config
 * (bridge/probe.go) has a hidden select group MIHOMO-PROBE and a loopback mixed listener (127.0.0.1:<ProbePort>,
 * default 7899) whose traffic always goes to that group. A probe selects the policy in the group over the
 * controller, then sends plain OkHttp requests through the listener. One probe at a time (one selection).
 */
object PolicyProbe {
    private val lock = Mutex()

    class ProbeException(val code: String, val arg: String = "") : Exception(code)

    const val BROWSER_UA = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36"

    suspend fun <T> run(policy: String, timeoutSec: Long = 10, body: suspend (OkHttpClient) -> T): T = lock.withLock {
        if (!F2Core.isConnected) throw ProbeException("not_connected")
        try {
            ControllerClient.select(F2Core.PROBE_GROUP, policy)
        } catch (e: ApiException) {
            if (e.code == 404) throw ProbeException("needs_reconnect")
            if (e.code == 400) throw ProbeException("unknown_policy", policy)
            throw e
        }
        val port = withContext(Dispatchers.IO) { F2Core.probePort() }
        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)))
            .connectTimeout(timeoutSec, TimeUnit.SECONDS).readTimeout(timeoutSec, TimeUnit.SECONDS)
            .callTimeout(timeoutSec + 5, TimeUnit.SECONDS).followRedirects(true).followSslRedirects(true)
            .build()
        try { body(client) } finally { client.dispatcher.executorService.shutdown(); client.connectionPool.evictAll() }
    }

    // ---- exit info (same endpoints as the header) ----------------------------------------------

    private fun JsonObject.s(vararg keys: String): String? {
        for (k in keys) {
            val v = runCatching { this[k]?.jsonPrimitive?.contentOrNull }.getOrNull()
            if (!v.isNullOrBlank()) return v
        }
        return null
    }

    private fun splitAs(s: String?): Pair<String?, String?> {
        if (s.isNullOrBlank()) return null to null
        val m = Regex("^(AS\\d+)\\s*(.*)$", RegexOption.IGNORE_CASE).find(s.trim()) ?: return null to s
        return m.groupValues[1].uppercase() to m.groupValues[2].ifBlank { null }
    }

    suspend fun fetchExit(client: OkHttpClient): IpInfo? = withContext(Dispatchers.IO) {
        val eps: List<Pair<String, (JsonObject) -> IpInfo?>> = listOf(
            "https://ipinfo.io/json" to { d -> d.s("ip")?.let { ip -> val (a, o) = splitAs(d.s("org")); IpInfo(ip, d.s("country"), null, d.s("region"), d.s("city"), a, o, "ipinfo.io") } },
            "http://ip-api.com/json/?fields=status,query,country,countryCode,regionName,city,isp,org,as" to { d ->
                d.s("query")?.let { ip -> val (a, o) = splitAs(d.s("as")); IpInfo(ip, d.s("countryCode"), d.s("country"), d.s("regionName"), d.s("city"), a, o ?: d.s("isp"), "ip-api.com") }
            },
            "https://ipwho.is/" to { d ->
                d.s("ip")?.let { ip ->
                    val c = runCatching { d["connection"]?.jsonObject }.getOrNull()
                    IpInfo(ip, d.s("country_code"), d.s("country"), d.s("region"), d.s("city"), c?.s("asn")?.let { "AS$it" }, c?.s("org", "isp"), "ipwho.is")
                }
            },
        )
        for ((url, parse) in eps) {
            val r = runCatching {
                client.newCall(Request.Builder().url(url).header("User-Agent", "curl/8.4.0").header("Accept", "application/json").build())
                    .execute().use { resp -> if (resp.isSuccessful) parse(AppJson.parseToJsonElement(resp.body?.string().orEmpty()).jsonObject) else null }
            }.getOrNull()
            if (r != null) return@withContext r
        }
        null
    }
}

// ---------------------------------------------------------------------------------------------------
// 解锁检测

enum class UnlockService(val title: String) {
    netflix("Netflix"), disney("Disney+"), youtube("YouTube Premium"), chatgpt("ChatGPT"), claude("Claude"),
    gemini("Gemini"), tiktok("TikTok"), spotify("Spotify"), bilibiliHKMOTW("bilibili HK/MO/TW"), bilibiliTW("bilibili TW"),
}

@Serializable
data class UnlockResult(
    val service: UnlockService,
    /** yes | partial | no | failed */
    val status: String,
    val region: String? = null,
    /** a note code (see UnlockNotes) or a raw text such as "HTTP 403" */
    val note: String? = null,
) {
    val flag: String?
        get() {
            val r = region?.uppercase()?.takeIf { it.length == 2 && it.all { c -> c in 'A'..'Z' } } ?: return null
            val sb = StringBuilder(); r.forEach { sb.appendCodePoint(0x1F1E6 + (it - 'A')) }; return sb.toString()
        }
}

object UnlockNotes {
    const val DENIED = "denied"; const val ORIGINALS_ONLY = "originals_only"; const val REGION = "unsupported_region"
    const val WEB_ONLY = "web_only"; const val WAF = "waf_403"; const val UNRECOGNIZED = "unrecognized"
    const val TIMEOUT = "timeout"; const val CONNECT = "connect_failed"; const val TLS = "tls_failed"
}

object UnlockChecker {
    data class Page(val status: Int, val url: String, val body: String)

    private fun get(client: OkHttpClient, url: String, headers: Map<String, String> = emptyMap(), maxBytes: Long = 1_500_000): Page {
        val b = Request.Builder().url(url).header("User-Agent", PolicyProbe.BROWSER_UA).header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")
        headers.forEach { (k, v) -> b.header(k, v) }
        client.newCall(b.build()).execute().use { r ->
            val src = r.body?.source()
            src?.request(maxBytes)
            val bytes = src?.buffer?.let { buf -> buf.readByteArray(minOf(buf.size, maxBytes)) } ?: ByteArray(0)
            return Page(r.code, r.request.url.toString(), String(bytes, Charsets.UTF_8))
        }
    }

    private fun first(pattern: String, s: String): String? = Regex(pattern).find(s)?.groupValues?.getOrNull(1)

    private fun traceLoc(client: OkHttpClient, host: String): String? =
        runCatching { first("(?m)^loc=([A-Z]{2})$", get(client, "https://$host/cdn-cgi/trace", maxBytes = 4096).body) }.getOrNull()

    private fun failed(s: UnlockService, e: Throwable): UnlockResult = UnlockResult(s, "failed", note = when (e) {
        is SocketTimeoutException -> UnlockNotes.TIMEOUT
        is ConnectException, is UnknownHostException -> UnlockNotes.CONNECT
        is SSLException -> UnlockNotes.TLS
        is IOException -> e.message ?: UnlockNotes.CONNECT
        else -> e.message ?: e.toString()
    })

    suspend fun runAll(client: OkHttpClient, services: List<UnlockService> = UnlockService.entries): List<UnlockResult> = coroutineScope {
        services.map { s -> async(Dispatchers.IO) { runCatching { check(s, client) }.getOrElse { failed(s, it) } } }.awaitAll()
    }

    private fun ok(code: Int) = code in 200..399

    fun check(s: UnlockService, c: OkHttpClient): UnlockResult = when (s) {
        UnlockService.netflix -> {
            val p1 = get(c, "https://www.netflix.com/title/81280792")
            val p2 = get(c, "https://www.netflix.com/title/70143836")
            val region = first("data-country=\"([A-Z]{2})\"", p1.body) ?: first("\"requestCountry\":\\{\"id\":\"([A-Z]{2})\"", p1.body)
                ?: first("\"countryCode\":\"([A-Z]{2})\"", p1.body) ?: first("netflix\\.com/([a-z]{2})(?:-[a-z]{2})?/title", p1.url)?.uppercase()
            val no1 = p1.body.contains("Oh no!") || p1.status == 404
            val no2 = p2.body.contains("Oh no!") || p2.status == 404
            when {
                p1.status == 403 || p2.status == 403 -> UnlockResult(s, "no", note = UnlockNotes.DENIED)
                no1 && no2 -> UnlockResult(s, "partial", region, UnlockNotes.ORIGINALS_ONLY)
                ok(p1.status) || ok(p2.status) -> UnlockResult(s, "yes", region ?: if (p1.url.contains("netflix.com/title")) "US" else null)
                else -> UnlockResult(s, "failed", note = "HTTP ${p1.status}")
            }
        }
        UnlockService.disney -> {
            val p = get(c, "https://www.disneyplus.com/")
            val fin = p.url.lowercase()
            when {
                p.status == 403 || fin.contains("unavailable") || fin.contains("unsupported") -> UnlockResult(s, "no")
                !ok(p.status) -> UnlockResult(s, "failed", note = "HTTP ${p.status}")
                else -> UnlockResult(s, "yes", first("disneyplus\\.com/[a-z]{2}-([a-z]{2})(?:/|$)", fin)?.uppercase()
                    ?: first("\"countryCode\":\"([A-Z]{2})\"", p.body) ?: first("\"region\":\"([A-Z]{2})\"", p.body))
            }
        }
        UnlockService.youtube -> {
            val p = get(c, "https://www.youtube.com/premium", mapOf("Cookie" to "CONSENT=YES+cb.20220301-11-p0.en+FX+700; SOCS=CAISOAgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjQwNTI2LjAxX3AwGgV6aC1DTiACGgYIgMnpsgY"))
            val region = first("\"INNERTUBE_CONTEXT_GL\":\"([A-Z]{2})\"", p.body) ?: first("\"countryCode\":\"([A-Z]{2})\"", p.body)
            when {
                p.body.contains("www.google.cn") -> UnlockResult(s, "no", "CN")
                p.body.contains("Premium is not available in your country") -> UnlockResult(s, "no", region)
                p.body.contains("ad-free", ignoreCase = true) -> UnlockResult(s, "yes", region)
                else -> UnlockResult(s, "failed", region, if (p.status == 200) UnlockNotes.UNRECOGNIZED else "HTTP ${p.status}")
            }
        }
        UnlockService.chatgpt -> {
            val region = traceLoc(c, "chatgpt.com")
            val ck = get(c, "https://api.openai.com/compliance/cookie_requirements", mapOf("Authorization" to "Bearer null"), 20_000)
            if (ck.body.contains("unsupported_country")) UnlockResult(s, "no", region, UnlockNotes.REGION)
            else {
                val i = get(c, "https://ios.chat.openai.com/", maxBytes = 200_000)
                when {
                    i.body.contains("unsupported_country") -> UnlockResult(s, "no", region, UnlockNotes.REGION)
                    i.body.contains("VPN") -> UnlockResult(s, "partial", region, UnlockNotes.WEB_ONLY)
                    else -> UnlockResult(s, "yes", region)
                }
            }
        }
        UnlockService.claude -> {
            val region = traceLoc(c, "claude.ai")
            val p = get(c, "https://claude.ai/", maxBytes = 200_000)
            when {
                p.url.contains("app-unavailable-in-region") || p.body.contains("app-unavailable-in-region") -> UnlockResult(s, "no", region, UnlockNotes.REGION)
                ok(p.status) -> UnlockResult(s, "yes", region)
                p.status == 403 -> UnlockResult(s, "failed", region, UnlockNotes.WAF)
                else -> UnlockResult(s, "failed", region, "HTTP ${p.status}")
            }
        }
        UnlockService.gemini -> {
            val p = get(c, "https://gemini.google.com/")
            val region = first(",2,1,200,\"([A-Z]{3})\"", p.body)
            when {
                p.body.contains("45631641,null,true") -> UnlockResult(s, "yes", region)
                p.status == 200 -> UnlockResult(s, "no", region)
                else -> UnlockResult(s, "failed", note = "HTTP ${p.status}")
            }
        }
        UnlockService.tiktok -> {
            val p = get(c, "https://www.tiktok.com/explore")
            val region = first("\"region\":\"([A-Z]{2})\"", p.body)
            when {
                region != null -> UnlockResult(s, "yes", region)
                p.status == 403 || p.url.contains("notfound") || p.url.contains("unavailable") -> UnlockResult(s, "no")
                else -> UnlockResult(s, "failed", note = if (p.status == 200) UnlockNotes.UNRECOGNIZED else "HTTP ${p.status}")
            }
        }
        UnlockService.spotify -> {
            val p = get(c, "https://www.spotify.com/premium/", maxBytes = 100_000)
            when {
                p.url.contains("select-your-country") -> UnlockResult(s, "no")
                !ok(p.status) -> UnlockResult(s, "failed", note = "HTTP ${p.status}")
                else -> UnlockResult(s, "yes", first("spotify\\.com/([a-z]{2})(?:-[a-z]{2})?/premium", p.url)?.uppercase() ?: "US")
            }
        }
        UnlockService.bilibiliHKMOTW -> bilibili(s, c, "avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1&fnver=0&fnval=16&module=bangumi")
        UnlockService.bilibiliTW -> bilibili(s, c, "avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1&fnver=0&fnval=16&module=bangumi")
    }

    private fun bilibili(s: UnlockService, c: OkHttpClient, q: String): UnlockResult {
        val p = get(c, "https://api.bilibili.com/pgc/player/web/playurl?$q", maxBytes = 100_000)
        val code = runCatching { AppJson.parseToJsonElement(p.body).jsonObject["code"]?.jsonPrimitive?.intOrNull }.getOrNull()
            ?: return UnlockResult(s, "failed", note = "HTTP ${p.status}")
        return when (code) {
            0 -> UnlockResult(s, "yes")
            -10403 -> UnlockResult(s, "no")
            else -> UnlockResult(s, "failed", note = "code $code")
        }
    }
}

// ---------------------------------------------------------------------------------------------------

@Serializable
data class ProbeEntry(
    val exit: IpInfo? = null,
    val exitMs: Long? = null,
    val unlock: List<UnlockResult>? = null,
    val unlockMs: Long? = null,
)

/** Per-policy results (exit + 解锁检测), filesDir/probe-results.json (iOS ProbeStore). */
object ProbeStore {
    private const val MAX = 300
    private val file: File get() = File(Paths.root, "probe-results.json")
    private val ser = MapSerializer(String.serializer(), ProbeEntry.serializer())

    private val _entries = MutableStateFlow<Map<String, ProbeEntry>>(emptyMap())
    val entries: StateFlow<Map<String, ProbeEntry>> = _entries.asStateFlow()
    private val _running = MutableStateFlow<Set<String>>(emptySet())
    val running: StateFlow<Set<String>> = _running.asStateFlow()
    private var loaded = false

    fun load() {
        if (loaded) return
        loaded = true
        _entries.value = JsonFiles.read(file, ser) ?: emptyMap()
    }

    fun clear() { _entries.value = emptyMap(); file.delete() }

    private fun put(policy: String, f: (ProbeEntry) -> ProbeEntry) {
        _entries.update { m ->
            var n = m + (policy to f(m[policy] ?: ProbeEntry()))
            if (n.size > MAX) {
                val drop = n.entries.sortedBy { maxOf(it.value.exitMs ?: 0, it.value.unlockMs ?: 0) }.take(n.size - MAX).map { it.key }.toSet()
                n = n.filterKeys { it !in drop }
            }
            n
        }
        runCatching { JsonFiles.write(file, ser, _entries.value) }
    }

    /** Badge "n/m" from the last 解锁检测 (failed checks are not counted). */
    fun badge(policy: String): Pair<Int, Int>? {
        val r = _entries.value[policy]?.unlock?.filter { it.status != "failed" }?.takeIf { it.isNotEmpty() } ?: return null
        return r.count { it.status == "yes" } to r.size
    }

    /** Returns an error code / message, or null. */
    suspend fun probeExit(policy: String): String? {
        _running.update { it + policy }
        return try {
            val info = PolicyProbe.run(policy, 8) { PolicyProbe.fetchExit(it) }
            put(policy) { it.copy(exit = info, exitMs = System.currentTimeMillis()) }
            if (info == null) "no_answer" else null
        } catch (e: PolicyProbe.ProbeException) { e.code } catch (e: Exception) { e.message ?: e.toString() } finally { _running.update { it - policy } }
    }

    suspend fun probeUnlock(policy: String): String? {
        _running.update { it + policy }
        return try {
            val (info, results) = PolicyProbe.run(policy, 10) { c ->
                coroutineScope {
                    val ex = async { PolicyProbe.fetchExit(c) }
                    val un = async { UnlockChecker.runAll(c) }
                    ex.await() to un.await()
                }
            }
            val now = System.currentTimeMillis()
            put(policy) { e -> e.copy(exit = info ?: e.exit, exitMs = if (info != null) now else e.exitMs, unlock = results, unlockMs = now) }
            null
        } catch (e: PolicyProbe.ProbeException) { e.code } catch (e: Exception) { e.message ?: e.toString() } finally { _running.update { it - policy } }
    }
}
