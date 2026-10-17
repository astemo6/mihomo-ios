package io.github.astemo6.mihomo.data.feature2

import io.github.astemo6.mihomo.api.ApiException
import io.github.astemo6.mihomo.data.Overrides
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.Proxy
import java.util.concurrent.TimeUnit

/**
 * Extra external-controller GETs the shared ControllerClient does not expose (/dns/query, /smart …).
 * Same base URL and Bearer secret as ControllerClient.
 */
object F2Api {
    private val client by lazy {
        OkHttpClient.Builder().proxy(Proxy.NO_PROXY).connectTimeout(4, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS).callTimeout(20, TimeUnit.SECONDS).build()
    }

    suspend fun get(segments: List<String>, query: Map<String, String> = emptyMap()): String = withContext(Dispatchers.IO) {
        val ov = Overrides.load()
        val b = HttpUrl.Builder().scheme("http").host("127.0.0.1").port(ov.port)
        segments.forEach { b.addPathSegment(it) }
        query.forEach { (k, v) -> b.addQueryParameter(k, v) }
        val req = Request.Builder().url(b.build()).header("Authorization", "Bearer ${ov.secret}").build()
        client.newCall(req).execute().use { r ->
            val text = r.body?.string().orEmpty()
            if (!r.isSuccessful) throw ApiException(r.code, text)
            text
        }
    }
}
