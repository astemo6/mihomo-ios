package io.github.astemo6.mihomo.ui.components

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.LruCache
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.Dp
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.Overrides
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/**
 * Memory + disk cache for small remote images (policy-group `icon:` URLs), like the iOS IconCache:
 * files in filesDir/icon-cache/<sha256>.png, downscaled to 128 px, raw.githubusercontent.com fetched
 * through the jsDelivr mirror unless the user picked GitHub for downloads. Failures are remembered for
 * the session so a dead URL is not retried on every recomposition.
 */
object IconCache {
    private val memory = LruCache<String, Bitmap>(200)
    private val failed = ConcurrentHashMap.newKeySet<String>()
    private val locks = ConcurrentHashMap<String, Mutex>()
    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS).readTimeout(15, TimeUnit.SECONDS).build()
    }

    private val dir: File get() = File(Paths.root, "icon-cache").apply { mkdirs() }

    private fun key(url: String): String =
        MessageDigest.getInstance("SHA-256").digest(url.toByteArray()).take(16).joinToString("") { "%02x".format(it) }

    fun isImageUrl(s: String?): Boolean {
        val t = s?.trim().orEmpty()
        return t.startsWith("http://", true) || t.startsWith("https://", true)
    }

    fun mirrored(s: String): String {
        if (Overrides.load().geoMirror == "github") return s
        val u = runCatching { java.net.URI(s) }.getOrNull() ?: return s
        if (u.host != "raw.githubusercontent.com") return s
        val parts = u.path.split('/').filter { it.isNotEmpty() }
        if (parts.size < 4) return s
        return "https://testingcf.jsdelivr.net/gh/${parts[0]}/${parts[1]}@${parts[2]}/${parts.drop(3).joinToString("/")}"
    }

    fun cached(url: String): Bitmap? = memory.get(url)

    suspend fun load(url: String): Bitmap? {
        memory.get(url)?.let { return it }
        if (url in failed) return null
        return locks.getOrPut(url) { Mutex() }.withLock {
            memory.get(url)?.let { return@withLock it }
            withContext(Dispatchers.IO) {
                val f = File(dir, key(url) + ".png")
                var bmp = if (f.exists()) BitmapFactory.decodeFile(f.absolutePath) else null
                if (bmp == null) {
                    bmp = runCatching {
                        http.newCall(Request.Builder().url(mirrored(url.trim())).build()).execute().use { r ->
                            if (!r.isSuccessful) return@use null
                            val bytes = r.body?.bytes() ?: return@use null
                            if (bytes.size > 2_000_000) return@use null
                            val raw = BitmapFactory.decodeByteArray(bytes, 0, bytes.size) ?: return@use null
                            val scaled = downscale(raw, 128)
                            runCatching { f.outputStream().use { scaled.compress(Bitmap.CompressFormat.PNG, 100, it) } }
                            scaled
                        }
                    }.getOrNull()
                }
                if (bmp != null) memory.put(url, bmp) else failed += url
                bmp
            }
        }
    }

    private fun downscale(b: Bitmap, max: Int): Bitmap {
        val m = maxOf(b.width, b.height)
        if (m <= max) return b
        val s = max.toFloat() / m
        return Bitmap.createScaledBitmap(b, (b.width * s).toInt().coerceAtLeast(1), (b.height * s).toInt().coerceAtLeast(1), true)
    }

    fun clear() {
        memory.evictAll(); failed.clear()
        dir.listFiles()?.forEach { it.delete() }
    }
}

/** The group's profile `icon:` image; [fallback] while loading or when there is none / it fails. */
@Composable
fun GroupIcon(url: String?, size: Dp, fallback: @Composable () -> Unit) {
    if (!IconCache.isImageUrl(url)) { fallback(); return }
    val u = url!!.trim()
    var bmp by remember(u) { mutableStateOf(IconCache.cached(u)) }
    LaunchedEffect(u) { if (bmp == null) bmp = IconCache.load(u) }
    val b = bmp
    if (b == null) fallback()
    else Image(b.asImageBitmap(), contentDescription = null, contentScale = ContentScale.Fit, modifier = Modifier.size(size))
}
