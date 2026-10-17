package io.github.astemo6.mihomo.api

import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.Overrides
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import java.net.Proxy
import java.util.concurrent.TimeUnit

class ApiException(val code: Int, message: String) : Exception("HTTP $code $message")

/**
 * mihomo external-controller client (127.0.0.1:<controllerPort>, Bearer secret): REST + the streaming
 * websocket endpoints (/traffic, /memory, /logs, /connections), mirroring the iOS ControllerClient.
 */
object ControllerClient {
    private val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .proxy(Proxy.NO_PROXY)
            .connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .pingInterval(20, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
            .build()
    }

    private val jsonType = "application/json".toMediaType()
    private val ov: Overrides get() = Overrides.load()

    /** Builds http://127.0.0.1:<port>/<segments…>; every segment is percent-encoded by OkHttp. */
    private fun url(segments: List<String>, query: Map<String, String> = emptyMap(), ws: Boolean = false): HttpUrl {
        val b = HttpUrl.Builder().scheme("http").host("127.0.0.1").port(ov.port)
        segments.forEach { b.addPathSegment(it) }
        query.forEach { (k, v) -> b.addQueryParameter(k, v) }
        if (ws) b.addQueryParameter("token", ov.secret)
        return b.build()
    }

    private suspend fun send(
        segments: List<String>,
        method: String = "GET",
        query: Map<String, String> = emptyMap(),
        body: JsonObject? = null,
        timeoutMs: Long = 8000,
    ): String = withContext(Dispatchers.IO) {
        val rb: RequestBody? = body?.toString()?.toRequestBody(jsonType)
            ?: if (method == "PUT" || method == "PATCH" || method == "POST") ByteArray(0).toRequestBody(null) else null
        val req = Request.Builder()
            .url(url(segments, query))
            .header("Authorization", "Bearer ${ov.secret}")
            .method(method, rb)
            .build()
        val call = client.newBuilder().callTimeout(timeoutMs, TimeUnit.MILLISECONDS).build().newCall(req)
        call.execute().use { resp: Response ->
            val text = resp.body?.string().orEmpty()
            if (!resp.isSuccessful) throw ApiException(resp.code, text)
            text
        }
    }

    private suspend fun <T> get(strategy: DeserializationStrategy<T>, vararg segments: String): T =
        AppJson.decodeFromString(strategy, send(segments.toList()))

    // ---- API ----------------------------------------------------------------------------------

    suspend fun version(): String =
        AppJson.parseToJsonElement(send(listOf("version"))).jsonObject["version"]?.jsonPrimitive?.contentOrNull ?: "?"

    private val hiddenNames = setOf("__MITM__", "MIHOMO-PROBE")

    suspend fun proxies(): Map<String, ProxyItem> {
        val p = get(ProxiesResponse.serializer(), "proxies").proxies.toMutableMap()
        hiddenNames.forEach { p.remove(it) }
        return p.mapValues { (_, v) ->
            if (v.all?.any { it in hiddenNames } == true) v.copy(all = v.all.orEmpty().filterNot { it in hiddenNames }) else v
        }
    }

    suspend fun select(group: String, node: String) {
        send(listOf("proxies", group), "PUT", body = buildJsonObject { put("name", node) })
    }

    suspend fun unpin(group: String) {
        send(listOf("proxies", group), "DELETE")
    }

    /** GET /group/{name}/delay: name → ms for members that answered (missing = timeout). Empty on 504. */
    suspend fun groupDelay(group: String): Map<String, Int> {
        val o = ov
        return try {
            val text = send(listOf("group", group, "delay"),
                query = mapOf("url" to o.testUrlOrDefault, "timeout" to o.testTimeout.toString()),
                timeoutMs = o.testTimeout + 10_000L)
            AppJson.parseToJsonElement(text).jsonObject.mapNotNull { (k, v) ->
                runCatching { v.jsonPrimitive.intOrNull }.getOrNull()?.let { k to it }
            }.toMap()
        } catch (e: ApiException) {
            if (e.code == 504) emptyMap() else throw e
        }
    }

    /** GET /proxies/{name}/delay; 0 = timeout / failure. */
    suspend fun proxyDelay(name: String): Int {
        val o = ov
        return try {
            val text = send(listOf("proxies", name, "delay"),
                query = mapOf("url" to o.testUrlOrDefault, "timeout" to o.testTimeout.toString()),
                timeoutMs = o.testTimeout + 5_000L)
            AppJson.parseToJsonElement(text).jsonObject["delay"]?.jsonPrimitive?.intOrNull ?: 0
        } catch (e: ApiException) {
            if (e.code == 504 || e.code == 503 || e.code == 408) 0 else throw e
        }
    }

    suspend fun connections(): ConnectionsResponse = get(ConnectionsResponse.serializer(), "connections")
    suspend fun closeConnection(id: String) { send(listOf("connections", id), "DELETE") }
    suspend fun closeAllConnections() { send(listOf("connections"), "DELETE") }

    suspend fun rules(): List<RuleItem> = get(RulesResponse.serializer(), "rules").rules

    suspend fun proxyProviders(): List<ProviderItem> =
        get(ProvidersResponse.serializer(), "providers", "proxies").providers.values
            .filter { it.vehicleType != "Compatible" }.sortedBy { it.name }

    suspend fun ruleProviders(): List<ProviderItem> =
        get(ProvidersResponse.serializer(), "providers", "rules").providers.values.sortedBy { it.name }

    suspend fun updateProxyProvider(name: String) { send(listOf("providers", "proxies", name), "PUT", timeoutMs = 30_000) }
    suspend fun updateRuleProvider(name: String) { send(listOf("providers", "rules", name), "PUT", timeoutMs = 30_000) }

    suspend fun setMode(mode: String) { send(listOf("configs"), "PATCH", body = buildJsonObject { put("mode", mode) }) }

    suspend fun configs(): JsonObject = AppJson.parseToJsonElement(send(listOf("configs"))).jsonObject

    suspend fun setLogLevel(level: String) {
        send(listOf("configs"), "PATCH", body = buildJsonObject { put("log-level", level) })
    }

    /** GET /dns/query?name=&type= (mihomo's resolver, follows the profile's DNS): raw JSON {Status, Answer:[{name,type,TTL,data}]}. */
    suspend fun dnsQuery(name: String, type: String): JsonObject =
        AppJson.parseToJsonElement(send(listOf("dns", "query"), query = mapOf("name" to name, "type" to type), timeoutMs = 15_000)).jsonObject

    /** GET /mitm/status of the HTTP engine (core/mitm/api.go). */
    suspend fun mitmStatus(): JsonObject = AppJson.parseToJsonElement(send(listOf("mitm", "status"))).jsonObject

    /** GET /mitm/logs?since=: script console lines [{id, time, level, script, msg}]. */
    suspend fun mitmLogs(since: Long = 0): String = send(listOf("mitm", "logs"), query = mapOf("since" to since.toString()))
    suspend fun mitmClearLogs() { send(listOf("mitm", "logs"), "DELETE") }

    // ---- websocket streams --------------------------------------------------------------------

    /** Streams decoded JSON frames from a websocket endpoint; the flow ends when the socket closes. */
    fun <T> stream(path: String, strategy: DeserializationStrategy<T>, query: Map<String, String> = emptyMap()): Flow<T> =
        callbackFlow {
            val req = Request.Builder().url(url(listOf(path), query, ws = true))
                .header("Authorization", "Bearer ${ov.secret}").build()
            val ws = client.newWebSocket(req, object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, text: String) {
                    runCatching { AppJson.decodeFromString(strategy, text) }.onSuccess { trySend(it) }
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    close()
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    close(t)
                }
            })
            awaitClose { ws.cancel() }
        }

    fun traffic(): Flow<TrafficSample> = stream("traffic", TrafficSample.serializer())
    fun memory(): Flow<MemorySample> = stream("memory", MemorySample.serializer())
    fun logs(level: String): Flow<LogPayload> = stream("logs", LogPayload.serializer(), mapOf("level" to level))
    fun connectionsStream(intervalMs: Int = 1000): Flow<ConnectionsResponse> =
        stream("connections", ConnectionsResponse.serializer(), mapOf("interval" to intervalMs.toString()))
}
