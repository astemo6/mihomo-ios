package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.api.ApiException
import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import libmihomo.Libmihomo
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.Proxy
import java.util.concurrent.TimeUnit

// HTTP engine controller endpoints the shared ControllerClient does not expose (core/mitm/api.go):
// /mitm/requests, /mitm/requests/{id}, DELETE /mitm/requests, /mitm/hosts, POST /mitm/requests/{id}/replay.

/** GET /mitm/requests row (mitm.Summary). */
@Serializable
data class HttpReqSummary(
    val id: Long = 0, val time: Double = 0.0, val method: String = "", val url: String = "", val host: String = "",
    val mitm: Boolean = false, val status: Int = 0, val matched: List<String>? = null, val notes: List<String>? = null,
    val local: Boolean = false, val done: Boolean = false, val duration: Double? = null, val bytes: Long = 0,
) {
    /** Path + query of [url] for the list. */
    val path: String get() = url.substringAfter("://").let { r -> r.indexOf('/').let { if (it < 0) "/" else r.substring(it) } }
}

/** GET /mitm/requests/{id} (mitm.Entry). */
@Serializable
data class HttpReqDetail(
    val id: Long = 0, val time: Double = 0.0, val method: String = "", val url: String = "", val host: String = "",
    val mitm: Boolean = false, val status: Int = 0, val matched: List<String>? = null, val notes: List<String>? = null,
    val local: Boolean = false, val done: Boolean = false, val duration: Double? = null, val bytes: Long = 0,
    val reqHeaders: Map<String, String>? = null, val respHeaders: Map<String, String>? = null,
    val reqBody: String? = null, val respBody: String? = null,
    val reqBodyBinary: Int = 0, val reqBodyLength: Int = 0, val respBodyLength: Int = 0, val respBodyBinary: Int = 0,
    val respEncoding: String? = null, val bodiesDropped: Boolean = false,
) {
    /** Same rule as iOS: no TLS-only entries, no binary / truncated (>32 KB) / dropped request bodies. */
    val canReplay: Boolean
        get() = method != "TLS" && reqBodyBinary == 0 && !bodiesDropped &&
            (reqBodyLength == 0 || reqBodyLength <= (reqBody?.toByteArray()?.size ?: 0))

    val curl: String
        get() {
            fun q(s: String) = "'" + s.replace("'", "'\\''") + "'"
            val sb = StringBuilder("curl")
            if (method != "GET") sb.append(" -X ").append(method)
            sb.append(' ').append(q(url))
            reqHeaders.orEmpty().toSortedMap().forEach { (k, v) ->
                if (!k.equals("content-length", true)) sb.append(" \\\n  -H ").append(q("$k: $v"))
            }
            if (!reqBody.isNullOrEmpty()) sb.append(" \\\n  --data-raw ").append(q(reqBody))
            return sb.toString()
        }
}

@Serializable
data class ReplayEdit(val method: String? = null, val url: String? = null, val headers: Map<String, String>? = null, val body: String? = null)

@Serializable
data class ReplayResult(
    val id: Long = 0, val status: Int = 0, val headers: Map<String, String> = emptyMap(), val body: String? = null,
    val binary: Int = 0, val length: Int = 0, val duration: Double = 0.0, val error: String? = null,
)

object EngineApi {
    private val client by lazy {
        OkHttpClient.Builder().proxy(Proxy.NO_PROXY).connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(40, TimeUnit.SECONDS).callTimeout(45, TimeUnit.SECONDS).build()
    }
    private val jsonType = "application/json".toMediaType()

    private suspend fun send(segments: List<String>, method: String = "GET", query: Map<String, String> = emptyMap(), body: String? = null): String =
        withContext(Dispatchers.IO) {
            val ov = Overrides.load()
            val b = HttpUrl.Builder().scheme("http").host("127.0.0.1").port(ov.port)
            segments.forEach { b.addPathSegment(it) }
            query.forEach { (k, v) -> b.addQueryParameter(k, v) }
            val rb = when {
                body != null -> body.toRequestBody(jsonType)
                method == "POST" -> ByteArray(0).toRequestBody(null)
                else -> null
            }
            val req = Request.Builder().url(b.build()).header("Authorization", "Bearer ${ov.secret}").method(method, rb).build()
            client.newCall(req).execute().use { r ->
                val text = r.body?.string().orEmpty()
                if (!r.isSuccessful) throw ApiException(r.code, text.trim())
                text
            }
        }

    suspend fun requests(since: Long = 0): List<HttpReqSummary> =
        AppJson.decodeFromString(ListSerializer(HttpReqSummary.serializer()),
            send(listOf("mitm", "requests"), query = if (since > 0) mapOf("since" to since.toString()) else emptyMap()))

    suspend fun request(id: Long): HttpReqDetail =
        AppJson.decodeFromString(HttpReqDetail.serializer(), send(listOf("mitm", "requests", id.toString())))

    suspend fun clearRequests() { send(listOf("mitm", "requests"), "DELETE") }

    /** host → matched rule labels of recent requests. */
    suspend fun hosts(): Map<String, List<String>> =
        AppJson.decodeFromString(MapSerializer(String.serializer(), ListSerializer(String.serializer())), send(listOf("mitm", "hosts")))

    suspend fun replay(id: Long, edit: ReplayEdit?): ReplayResult =
        AppJson.decodeFromString(ReplayResult.serializer(),
            send(listOf("mitm", "requests", id.toString(), "replay"), "POST",
                body = edit?.let { AppJson.encodeToString(ReplayEdit.serializer(), it) }))
}

// ---- 脚本调试 (ScriptDebugRun, app process, no tunnel needed) --------------------------------------

@Serializable
data class DebugHttp(
    val url: String? = null, val method: String? = null, val status: Int? = null,
    val headers: Map<String, String>? = null, val body: String? = null, val bodyBase64: Boolean? = null,
)

@Serializable
data class DebugInput(
    val code: String, val path: String? = null, val name: String? = null, val type: String,
    val argument: String? = null, val timeout: Int = 10, val binary: Boolean = false,
    val request: DebugHttp? = null, val response: DebugHttp? = null,
)

@Serializable
data class DebugOutput(
    val ok: Boolean = false, val error: String? = null, val durationMs: Long = 0, val done: Boolean = false,
    val doneJSON: String? = null, val summary: List<String> = emptyList(), val result: DebugHttp? = null,
    val mock: DebugHttp? = null, val logs: List<Log> = emptyList(), val notifications: List<Map<String, String>> = emptyList(),
) {
    @Serializable
    data class Log(val t: Long = 0, val level: String = "", val msg: String = "")
}

/** The sample a debug run executes against (edited in the debug panel; can be filled from a captured request). */
data class DebugSample(
    val type: String = "http-response",
    val url: String = "https://api.example.com/v1/feed",
    val method: String = "GET",
    val requestHeaders: String = "User-Agent: Mozilla/5.0\nAccept: application/json",
    val requestBody: String = "",
    val status: String = "200",
    val responseHeaders: String = "Content-Type: application/json",
    val responseBody: String = "{\"ad\":true,\"data\":[1,2,3]}",
    val argument: String = "",
    val useArgument: Boolean = false,
    val timeout: Int = 10,
    val binary: Boolean = false,
) {
    companion object {
        fun headerText(h: Map<String, String>?): String =
            h.orEmpty().entries.sortedBy { it.key.lowercase() }.joinToString("\n") { "${it.key}: ${it.value}" }

        fun headers(text: String): Map<String, String> = text.lines().mapNotNull { line ->
            val i = line.indexOf(':')
            if (i <= 0) null else line.substring(0, i).trim().takeIf { it.isNotEmpty() }?.let { it to line.substring(i + 1).trim() }
        }.toMap()

        fun from(d: HttpReqDetail) = DebugSample(
            type = if (!d.respBody.isNullOrEmpty() || d.status > 0) "http-response" else "http-request",
            url = d.url, method = d.method, requestHeaders = headerText(d.reqHeaders), requestBody = d.reqBody.orEmpty(),
            status = (if (d.status > 0) d.status else 200).toString(), responseHeaders = headerText(d.respHeaders),
            responseBody = d.respBody.orEmpty(),
        )
    }
}

object ScriptDebugger {
    val types = listOf("http-request", "http-response", "generic", "cron")

    suspend fun run(code: String, path: String?, name: String, s: DebugSample): DebugOutput = withContext(Dispatchers.IO) {
        val http = s.type == "http-request" || s.type == "http-response"
        val input = DebugInput(
            code = code, path = path, name = name, type = s.type,
            argument = if (s.useArgument) s.argument else null, timeout = s.timeout.coerceIn(1, 60), binary = s.binary,
            request = if (http) DebugHttp(url = s.url, method = s.method, headers = DebugSample.headers(s.requestHeaders), body = s.requestBody) else null,
            response = if (s.type == "http-response")
                DebugHttp(status = s.status.toIntOrNull() ?: 200, headers = DebugSample.headers(s.responseHeaders), body = s.responseBody) else null,
        )
        val out = Libmihomo.scriptDebugRun(Paths.home.absolutePath, AppJson.encodeToString(DebugInput.serializer(), input))
        runCatching { AppJson.decodeFromString(DebugOutput.serializer(), out) }.getOrElse { DebugOutput(error = out.ifEmpty { it.message }) }
    }
}
