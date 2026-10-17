package io.github.astemo6.mihomo.data

import android.util.Base64
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.intOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.util.UUID
import java.util.concurrent.TimeUnit

class ImportException(message: String) : Exception(message)

/** Profiles (subscriptions and local files): index in filesDir/profiles.json, YAML in filesDir/profiles/<id>.yaml. */
object ProfileStore {
    private val _profiles = MutableStateFlow<List<Profile>>(emptyList())
    val profiles: StateFlow<List<Profile>> = _profiles.asStateFlow()

    private val _activeId = MutableStateFlow<String?>(null)
    val activeId: StateFlow<String?> = _activeId.asStateFlow()

    private val _updating = MutableStateFlow<Set<String>>(emptySet())
    val updating: StateFlow<Set<String>> = _updating.asStateFlow()

    /** Called after the active profile file changed (switch / update): the VPN reloads when running. */
    var onActiveChanged: (() -> Unit)? = null

    const val MANUAL_ID = "manual-nodes"

    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .followRedirects(true)
            .build()
    }

    val active: Profile? get() = _profiles.value.firstOrNull { it.id == _activeId.value }

    fun init() {
        val list = runCatching {
            AppJson.decodeFromString(ListSerializer(Profile.serializer()), Paths.profilesIndex.readText())
        }.getOrDefault(emptyList())
        _profiles.value = list
        var a = AppSettings.activeProfileId
        if (a == null || list.none { it.id == a }) {
            a = list.firstOrNull()?.id
            AppSettings.activeProfileId = a
        }
        _activeId.value = a
    }

    private fun persist() {
        val tmp = File(Paths.root, "profiles.json.tmp")
        tmp.writeText(AppJson.encodeToString(ListSerializer(Profile.serializer()), _profiles.value))
        if (!tmp.renameTo(Paths.profilesIndex)) {
            Paths.profilesIndex.writeText(tmp.readText()); tmp.delete()
        }
    }

    fun setActive(p: Profile) {
        if (_activeId.value == p.id) return
        _activeId.value = p.id
        AppSettings.activeProfileId = p.id
        onActiveChanged?.invoke()
    }

    fun delete(p: Profile) {
        p.file.delete()
        File(Paths.profiles, "${p.id}.selected.json").delete()
        _profiles.update { l -> l.filterNot { it.id == p.id } }
        if (_activeId.value == p.id) {
            val next = _profiles.value.firstOrNull()?.id
            _activeId.value = next
            AppSettings.activeProfileId = next
            onActiveChanged?.invoke()
        }
        persist()
    }

    fun rename(p: Profile, name: String) = replace(p.copy(name = name.ifBlank { p.name }))

    fun setInterval(p: Profile, hours: Int) = replace(p.copy(updateIntervalHours = hours.coerceAtLeast(0)))

    private fun replace(p: Profile) {
        _profiles.update { l -> l.map { if (it.id == p.id) p else it } }
        persist()
    }

    fun content(p: Profile): String = runCatching { p.file.readText() }.getOrDefault("")

    // ---- conversion / validation -------------------------------------------------------------

    data class Normalized(val yaml: String, val note: String? = null)

    /**
     * Routes any text into a mihomo profile, without an external parser: ClassifyText decides,
     * ImportConf converts full Surge / QX configs, ConvertShareLinks handles share links, proxy lines,
     * base64 subscriptions and SIP008 JSON.
     */
    fun normalize(text: String): Normalized {
        val kind = Core.classify(text)
        return when {
            kind == "profile" -> Normalized(text)
            kind == "conf" -> {
                val obj = runCatching { AppJson.parseToJsonElement(Core.importConf(text)).jsonObject }
                    .getOrElse { throw ImportException("配置转换失败") }
                val err = obj["error"]?.jsonPrimitive?.content.orEmpty()
                if (err.isNotEmpty()) throw ImportException(err)
                val yaml = obj["yaml"]?.jsonPrimitive?.content.orEmpty()
                if (yaml.isBlank()) throw ImportException("配置转换失败")
                val rep = obj["report"]?.jsonObject
                val note = rep?.let {
                    val fmt = it["format"]?.jsonPrimitive?.content.orEmpty().uppercase()
                    val proxies = it["proxies"]?.jsonPrimitive?.intOrNull ?: 0
                    val groups = it["groups"]?.jsonPrimitive?.intOrNull ?: 0
                    val rules = it["rules"]?.jsonPrimitive?.intOrNull ?: 0
                    "$fmt → mihomo: $proxies / $groups / $rules"
                }
                Normalized(yaml, note)
            }
            kind.startsWith("module:") -> throw ImportException("MODULE:" + kind.removePrefix("module:"))
            else -> {
                val y = Core.convertShareLinks(text)
                if (y.isBlank()) throw ImportException(Core.lastError.ifEmpty { "UNRECOGNIZED" })
                Normalized(y)
            }
        }
    }

    private fun validateText(yaml: String): String? {
        val tmp = File(Paths.home, "validate-${UUID.randomUUID()}.yaml")
        return try {
            tmp.writeText(yaml)
            Core.validate(tmp.absolutePath).ifEmpty { null }
        } finally {
            tmp.delete()
        }
    }

    // ---- add / import ---------------------------------------------------------------------------

    suspend fun addLocal(name: String, text: String): Pair<Profile, String?> = withContext(Dispatchers.IO) {
        val n = normalize(text)
        validateText(n.yaml)?.let { throw ImportException(it) }
        val p = Profile(name = name.ifBlank { "本地配置" }, kind = Profile.Kind.local)
        p.file.writeText(n.yaml)
        Core.migrateProfileProviders(p.file.absolutePath)
        _profiles.update { it + p }
        persist()
        if (_activeId.value == null) setActive(p)
        p to n.note
    }

    suspend fun saveLocalEdit(p: Profile, text: String) = withContext(Dispatchers.IO) {
        validateText(text)?.let { throw ImportException(it) }
        p.file.writeText(text)
        if (p.id == _activeId.value) onActiveChanged?.invoke()
    }

    suspend fun addRemote(url: String, name: String = "", userAgent: String = "clash.meta", intervalHours: Int = 24): Profile =
        withContext(Dispatchers.IO) {
            var p = Profile(name = name, kind = Profile.Kind.remote, url = url.trim(),
                userAgent = userAgent.ifBlank { "clash.meta" }, updateIntervalHours = intervalHours)
            p = download(p)
            _profiles.update { it + p }
            persist()
            if (_activeId.value == null) setActive(p)
            p
        }

    /** Downloads a remote profile (UA clash.meta), parses subscription-userinfo, validates and writes it. */
    private fun download(input: Profile): Profile {
        val s = input.url ?: throw ImportException("BAD_URL")
        val uri = runCatching { URI(s) }.getOrNull()
        if (uri == null || (uri.scheme != "http" && uri.scheme != "https")) throw ImportException("BAD_URL")
        val req = Request.Builder().url(s).header("User-Agent", input.userAgent).header("Cache-Control", "no-cache").build()
        http.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ImportException("HTTP ${resp.code}")
            val text = resp.body?.string().orEmpty()
            if (text.isBlank()) throw ImportException("EMPTY")
            val n = normalize(text)
            validateText(n.yaml)?.let { throw ImportException(it) }
            input.file.writeText(n.yaml)
            Core.migrateProfileProviders(input.file.absolutePath)
            val info = SubscriptionUserInfo.parse(resp.header("subscription-userinfo")) ?: input.userInfo
            val name = input.name.ifBlank { nameFromHeaders(resp) ?: uri.host ?: "订阅" }
            val interval = resp.header("profile-update-interval")?.trim()?.toIntOrNull()
            return input.copy(
                name = name,
                userInfo = info,
                lastUpdated = System.currentTimeMillis(),
                updateIntervalHours = if (input.lastUpdated == null && interval != null && interval > 0) interval else input.updateIntervalHours,
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
            val dec = runCatching { URLDecoder.decode(m.groupValues[1], "UTF-8") }.getOrNull()
            if (!dec.isNullOrBlank()) return dec.removeSuffix(".yaml").removeSuffix(".yml")
        }
        Regex("filename=\"?([^\";]+)\"?", RegexOption.IGNORE_CASE).find(cd)?.let { m ->
            val raw = m.groupValues[1].trim()
            if (raw.isNotEmpty()) return raw.removeSuffix(".yaml").removeSuffix(".yml")
        }
        return null
    }

    /** Re-downloads a subscription. Returns an error message or null. */
    suspend fun refresh(p: Profile): String? = withContext(Dispatchers.IO) {
        if (!p.isRemote) return@withContext null
        _updating.update { it + p.id }
        try {
            val np = download(p)
            replace(np)
            if (np.id == _activeId.value) onActiveChanged?.invoke()
            null
        } catch (e: Exception) {
            e.message ?: e.toString()
        } finally {
            _updating.update { it - p.id }
        }
    }

    suspend fun refreshAll(): List<String> {
        val errors = mutableListOf<String>()
        for (p in _profiles.value.filter { it.isRemote }) {
            refresh(p)?.let { errors += "${p.name}: $it" }
        }
        return errors
    }

    /** Updates subscriptions whose interval elapsed (on app foreground and on VPN start). */
    suspend fun autoUpdateIfNeeded() {
        val now = System.currentTimeMillis()
        for (p in _profiles.value) {
            if (!p.isRemote || p.updateIntervalHours <= 0) continue
            val due = (p.lastUpdated ?: 0L) + p.updateIntervalHours * 3_600_000L
            if (due < now) refresh(p)
        }
    }
}
