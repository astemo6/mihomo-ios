package io.github.astemo6.mihomo.data.feature2

import android.util.Base64
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.SubscriptionUserInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * 订阅管理 (iOS NodeSubStore, v0.9): node-only subscriptions in <home>/node-subscriptions.json. The bridge
 * reads id / name / url / enabled / groups and merges each enabled, downloaded one into every profile as a
 * file proxy-provider (bridge/nodesubs.go); the app downloads it into <home>/nodesubs/<id>.yaml through
 * ProviderStore(convert "nodes"). Its 节点处理 rules live in subscriptions.json under "nodesub-<id>".
 */
@Serializable
data class NodeSubscription(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    /** null / empty = default groups (select groups with nodes + url-test groups) */
    val groups: List<String>? = null,
    val userAgent: String = "clash.meta",
    val updateIntervalHours: Int = 24,
    /** epoch millis (the iOS file stores a Date; this app only reads its own file) */
    val lastUpdatedMs: Long? = null,
    val userInfo: SubscriptionUserInfo? = null,
    val count: Int? = null,
    val lastError: String? = null,
) {
    val rulesKey: String get() = "nodesub-$id"
    val cacheFile: File get() = File(Paths.home, "nodesubs/$id.yaml")
}

class NodeSubException(message: String) : Exception(message)

object NodeSubStore {
    private val file: File get() = File(Paths.home, "node-subscriptions.json")
    private val ser = ListSerializer(NodeSubscription.serializer())

    private val _subs = MutableStateFlow<List<NodeSubscription>>(emptyList())
    val subs: StateFlow<List<NodeSubscription>> = _subs.asStateFlow()
    private val _updating = MutableStateFlow<Set<String>>(emptySet())
    val updating: StateFlow<Set<String>> = _updating.asStateFlow()

    private val http by lazy {
        OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).followRedirects(true).build()
    }

    fun load() { _subs.value = JsonFiles.read(file, ser) ?: emptyList() }

    private fun persist() = JsonFiles.write(file, ser, _subs.value)

    private fun set(s: NodeSubscription) {
        _subs.update { l -> if (l.any { it.id == s.id }) l.map { if (it.id == s.id) s else it } else l + s }
        persist()
    }

    /** Adds and downloads; throws when the first download fails (nothing is kept then). */
    suspend fun add(url: String, name: String, userAgent: String, intervalHours: Int, groups: List<String>?): NodeSubscription =
        withContext(Dispatchers.IO) {
            val s = download(NodeSubscription(name = name.trim(), url = url.trim(), groups = groups?.ifEmpty { null },
                userAgent = userAgent.ifBlank { "clash.meta" }, updateIntervalHours = intervalHours))
            set(s)
            s
        }

    fun save(s: NodeSubscription) = set(s)

    fun delete(s: NodeSubscription) {
        s.cacheFile.delete()
        SubRulesStore.set(s.rulesKey, null)
        _subs.update { l -> l.filterNot { it.id == s.id } }
        persist()
    }

    /** Returns an error text, null on success. */
    suspend fun refresh(s: NodeSubscription): String? = withContext(Dispatchers.IO) {
        _updating.update { it + s.id }
        try {
            set(download(s)); null
        } catch (e: Exception) {
            val msg = e.message ?: e.toString()
            set(s.copy(lastError = msg)); msg
        } finally {
            _updating.update { it - s.id }
        }
    }

    suspend fun refreshAll(): List<String> = _subs.value.filter { it.enabled }.mapNotNull { s -> refresh(s)?.let { "${s.name}: $it" } }

    /** True when at least one subscription was refreshed (caller reloads). */
    suspend fun autoUpdateIfNeeded(): Boolean {
        val now = System.currentTimeMillis()
        var changed = false
        for (s in _subs.value) {
            if (!s.enabled || s.updateIntervalHours <= 0) continue
            if ((s.lastUpdatedMs ?: 0L) + s.updateIntervalHours * 3_600_000L < now && refresh(s) == null) changed = true
        }
        return changed
    }

    private fun download(input: NodeSubscription): NodeSubscription {
        val uri = runCatching { URI(input.url) }.getOrNull()
        if (uri == null || (uri.scheme != "http" && uri.scheme != "https")) throw NodeSubException("BAD_URL")
        val req = Request.Builder().url(input.url).header("User-Agent", input.userAgent).header("Cache-Control", "no-cache").build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw NodeSubException("HTTP ${resp.code}")
            val data = resp.body?.bytes() ?: ByteArray(0)
            val out = F2Core.providerStore("proxy", input.cacheFile.absolutePath, "nodes", data)
            val o = runCatching { AppJson.parseToJsonElement(out).jsonObject }.getOrNull() ?: throw NodeSubException("EMPTY")
            val err = o["error"]?.jsonPrimitive?.content.orEmpty()
            if (err.isNotEmpty()) throw NodeSubException(err)
            val count = runCatching { o["count"]!!.jsonPrimitive.int }.getOrNull()
            return input.copy(
                name = input.name.ifBlank { nameFromHeaders(resp) ?: uri.host ?: "订阅" },
                count = count,
                userInfo = SubscriptionUserInfo.parse(resp.header("subscription-userinfo")) ?: input.userInfo,
                lastUpdatedMs = System.currentTimeMillis(),
                lastError = null,
            )
        }
    }

    private fun nameFromHeaders(resp: Response): String? {
        resp.header("profile-title")?.takeIf { it.isNotBlank() }?.let { t ->
            if (t.startsWith("base64:")) {
                runCatching { String(Base64.decode(t.removePrefix("base64:"), Base64.DEFAULT)) }.getOrNull()?.let { return it }
            }
            return t
        }
        val cd = resp.header("Content-Disposition") ?: return null
        Regex("filename\\*=UTF-8''([^;]+)", RegexOption.IGNORE_CASE).find(cd)?.let { m ->
            runCatching { URLDecoder.decode(m.groupValues[1], "UTF-8") }.getOrNull()?.takeIf { it.isNotBlank() }
                ?.let { return it.removeSuffix(".yaml").removeSuffix(".yml") }
        }
        return null
    }
}
