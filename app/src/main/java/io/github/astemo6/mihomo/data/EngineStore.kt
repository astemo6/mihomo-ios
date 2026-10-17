package io.github.astemo6.mihomo.data

import android.net.Uri
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonElement
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

// Mirrors the iOS EngineShared.swift / EngineStore.swift: the app owns <home>/engine/engine.json,
// <home>/engine/modules/<id>.txt and <home>/engine/scripts; the Go engine (core/mitm) reads the same layout.

/** One user rewrite / script line with an enable switch (Surge, QX, Loon syntax). */
@Serializable
data class EngineItem(
    val id: String = UUID.randomUUID().toString().uppercase(),
    val enabled: Boolean = true,
    val line: String,
    val note: String? = null,
)

/** An imported module (.sgmodule / QX snippet / Loon plugin / Stash override / rewrite list). */
@Serializable
data class EngineModule(
    val id: String = UUID.randomUUID().toString().uppercase(),
    val name: String,
    val url: String = "",
    val enabled: Boolean = true,
    val args: Map<String, String>? = null,
    val policies: Map<String, String>? = null,
    val updatedAt: Double? = null,
    val interval: Int? = null,
)

/** <home>/engine/engine.json (core/mitm/config.go Config). */
@Serializable
data class EngineConfig(
    val enabled: Boolean = false,
    val mitm: Boolean = false,
    val skipCertVerify: Boolean = false,
    val h2: Boolean? = true,
    val captureBodies: Boolean? = true,
    val hostnames: List<String> = emptyList(),
    val rules: List<EngineItem> = emptyList(),
    val scripts: List<EngineItem> = emptyList(),
    val modules: List<EngineModule> = emptyList(),
    val scriptResources: Map<String, JsonElement>? = null,
    val quic: String? = null,
    val quicAllow: List<String>? = null,
)

/** Result of EngineParseText / EngineParseLine. */
@Serializable
data class ParsedEngineText(
    val name: String = "",
    val desc: String = "",
    val format: String = "",
    val rules: List<Rule> = emptyList(),
    val hostnames: List<String> = emptyList(),
    val coreRules: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
    val unsupported: List<String> = emptyList(),
    val tasks: List<Task>? = null,
    val panels: List<PanelItem>? = null,
    val arguments: List<ModArg> = emptyList(),
) {
    /** Surge #!arguments / Loon [Argument] / Egern compat_arguments entry (core/mitm ModArg). */
    @Serializable
    data class ModArg(
        val key: String = "", val default: String = "", val desc: String? = null,
        val type: String? = null, val options: List<String>? = null,
    )

    @Serializable
    data class Rule(
        val kind: String = "", val phase: String = "", val pattern: String = "", val desc: String = "",
        val line: String = "", val script: String? = null, val path: String? = null,
    )

    @Serializable
    data class Task(
        val kind: String = "", val name: String = "", val cron: String? = null, val event: String? = null,
        val path: String = "", val desc: String = "", val line: String = "",
    )

    @Serializable
    data class PanelItem(val name: String = "", val title: String = "", val script: String? = null)

    val isEmpty: Boolean
        get() = rules.isEmpty() && hostnames.isEmpty() && coreRules.isEmpty() && tasks.isNullOrEmpty() && panels.isNullOrEmpty()

    companion object {
        fun parse(json: String): ParsedEngineText? =
            runCatching { AppJson.decodeFromString(serializer(), json) }.getOrNull()
    }
}

@Serializable
data class CAInfo(
    val exists: Boolean = false,
    val subject: String? = null,
    val fingerprint: String? = null,
    val sha1: String? = null,
    val notBefore: String? = null,
    val notAfter: String? = null,
    val algorithm: String? = null,
)

/** A rewrite / script line shown in the 重写规则 panel, with where it came from. */
data class RewriteEntry(val rule: ParsedEngineText.Rule, val source: String, val enabled: Boolean)

class EngineException(message: String) : Exception(message)

object EngineStore {
    private val _config = MutableStateFlow(EngineConfig())
    val config: StateFlow<EngineConfig> = _config.asStateFlow()

    /** Parsed module summaries by module id. */
    private val _moduleInfo = MutableStateFlow<Map<String, ParsedEngineText>>(emptyMap())
    val moduleInfo: StateFlow<Map<String, ParsedEngineText>> = _moduleInfo.asStateFlow()

    private val _ca = MutableStateFlow(CAInfo())
    val ca: StateFlow<CAInfo> = _ca.asStateFlow()

    private val _busy = MutableStateFlow<Set<String>>(emptySet())
    val busy: StateFlow<Set<String>> = _busy.asStateFlow()

    /** Called after engine.json changed: the VPN reloads when running (set by MihomoApp). */
    var onChanged: (() -> Unit)? = null

    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder().connectTimeout(15, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).followRedirects(true).build()
    }

    private val home: String get() = Paths.home.absolutePath
    val dir: File get() = File(Paths.home, "engine").apply { mkdirs() }
    private val configFile: File get() = File(dir, "engine.json")
    private val modulesDir: File get() = File(dir, "modules").apply { mkdirs() }
    val scriptsDir: File get() = File(dir, "scripts").apply { mkdirs() }

    private fun safe(s: String) = s.map { c -> if (c.isLetterOrDigit() && c.code < 128 || c in "-_.") c else '_' }.joinToString("")
    fun moduleFile(id: String) = File(modulesDir, safe(id) + ".txt")

    fun init() {
        _config.value = runCatching { AppJson.decodeFromString(EngineConfig.serializer(), configFile.readText()) }
            .getOrDefault(EngineConfig())
        reparseModules()
        refreshCA()
    }

    // ---- config -------------------------------------------------------------------------------

    @Synchronized
    fun update(reload: Boolean = true, f: (EngineConfig) -> EngineConfig) {
        val c = f(_config.value)
        _config.value = c
        val tmp = File(dir, "engine.json.tmp")
        tmp.writeText(AppJson.encodeToString(EngineConfig.serializer(), c))
        if (!tmp.renameTo(configFile)) { configFile.writeText(tmp.readText()); tmp.delete() }
        if (reload) onChanged?.invoke()
    }

    fun setEnabled(on: Boolean) = update { it.copy(enabled = on) }
    fun setMitm(on: Boolean) = update { it.copy(mitm = on) }
    fun setSkipCertVerify(on: Boolean) = update { it.copy(skipCertVerify = on) }
    fun setQuicAll(all: Boolean) = update { it.copy(quic = if (all) "all" else null) }

    // ---- user rules / scripts / hostnames ------------------------------------------------------

    /** Splits pasted text into items; hostname lines go to the MitM list. Returns how many were added. */
    fun addLines(text: String, toScripts: Boolean): Int {
        var n = 0
        val hosts = _config.value.hostnames.toMutableList()
        val rules = _config.value.rules.toMutableList()
        val scripts = _config.value.scripts.toMutableList()
        for (raw in text.lines()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#") || line.startsWith(";") || line.startsWith("[")) continue
            if (line.lowercase().startsWith("hostname") && line.contains('=')) {
                line.substringAfter('=').split(',').map {
                    it.trim().replace("%APPEND%", "").replace("%INSERT%", "").trim()
                }.filter { it.isNotEmpty() }.forEach { if (it !in hosts) hosts += it }
                continue
            }
            val p = ParsedEngineText.parse(Core.engineParseLine(line, if (toScripts) "script" else ""))
            if (p?.rules?.firstOrNull()?.kind == "script") scripts += EngineItem(line = line) else rules += EngineItem(line = line)
            n++
        }
        update { it.copy(hostnames = hosts, rules = rules, scripts = scripts) }
        return n
    }

    /** (desc, kind, error) for one line, like the iOS EngineStore.describe. */
    fun describe(line: String, section: String = ""): Triple<String, String, String?> {
        val p = ParsedEngineText.parse(Core.engineParseLine(line, section)) ?: return Triple("?", "", "?")
        p.rules.firstOrNull()?.let { return Triple(it.desc, it.kind, null) }
        p.tasks?.firstOrNull()?.let { return Triple(it.desc, it.kind, null) }
        p.errors.firstOrNull()?.let { return Triple("", "", it) }
        if (p.coreRules.isNotEmpty()) return Triple(p.coreRules[0], "core", null)
        if (p.hostnames.isNotEmpty()) return Triple("hostname", "hostname", null)
        return Triple("", "", "unsupported")
    }

    fun toggleItem(id: String, scripts: Boolean) = update { c ->
        if (scripts) c.copy(scripts = c.scripts.map { if (it.id == id) it.copy(enabled = !it.enabled) else it })
        else c.copy(rules = c.rules.map { if (it.id == id) it.copy(enabled = !it.enabled) else it })
    }

    fun deleteItem(id: String) = update { c -> c.copy(rules = c.rules.filter { it.id != id }, scripts = c.scripts.filter { it.id != id }) }

    fun addHostname(h: String) {
        val v = h.trim()
        if (v.isEmpty() || v in _config.value.hostnames) return
        update { it.copy(hostnames = it.hostnames + v) }
    }

    fun removeHostname(h: String) = update { it.copy(hostnames = it.hostnames - h) }

    // ---- modules ------------------------------------------------------------------------------

    fun reparseModules() {
        val out = mutableMapOf<String, ParsedEngineText>()
        for (m in _config.value.modules) {
            val f = moduleFile(m.id)
            if (!f.exists()) continue
            val args = AppJson.encodeToString(MapSerializer(String.serializer(), String.serializer()), m.args ?: emptyMap())
            ParsedEngineText.parse(runCatching { Core.engineParseText(f.readText(), args) }.getOrDefault(""))?.let { out[m.id] = it }
        }
        _moduleInfo.value = out
    }

    private fun download(url: String): String {
        val u = url.trim()
        val uri = runCatching { Uri.parse(u) }.getOrNull()
        if (uri?.scheme != "http" && uri?.scheme != "https") throw EngineException("BAD_URL")
        val req = Request.Builder().url(u).header("User-Agent", "Surge iOS/3000").build()
        http.newCall(req).execute().use { r ->
            if (!r.isSuccessful) throw EngineException("HTTP ${r.code}")
            return r.body?.string().orEmpty()
        }
    }

    private fun nameFromUrl(url: String): String =
        Uri.parse(url).lastPathSegment?.substringBeforeLast('.')?.ifBlank { null } ?: "Module"

    /** Downloads and adds a module. Returns the parsed summary (for the toast). */
    suspend fun addModule(url: String): Pair<EngineModule, ParsedEngineText> = withContext(Dispatchers.IO) {
        if (_config.value.modules.any { it.url == url.trim() }) throw EngineException("DUPLICATE")
        _busy.value = _busy.value + "add"
        try {
            val text = download(url)
            addParsed(text, url.trim(), nameFromUrl(url))
        } finally {
            _busy.value = _busy.value - "add"
        }
    }

    /** Adds a module from text (file / clipboard / ClassifyText module:*). */
    suspend fun addModuleText(text: String, name: String, url: String = ""): Pair<EngineModule, ParsedEngineText> =
        withContext(Dispatchers.IO) { addParsed(text, url, name) }

    private fun addParsed(text: String, url: String, fallbackName: String): Pair<EngineModule, ParsedEngineText> {
        val p = ParsedEngineText.parse(Core.engineParseText(text, "{}"))
        if (p == null || p.isEmpty) throw EngineException("EMPTY_MODULE")
        val m = EngineModule(name = p.name.ifBlank { fallbackName.ifBlank { "Module" } }, url = url,
            updatedAt = System.currentTimeMillis() / 1000.0)
        moduleFile(m.id).writeText(text)
        update(reload = false) { it.copy(modules = it.modules + m, enabled = true) }
        reparseModules()
        onChanged?.invoke()
        return m to p
    }

    /** QX [rewrite_remote] / ImportConf rewriteRemotes: kept even when the download fails. Returns an error or null. */
    suspend fun addRemoteModule(url: String, name: String, enabled: Boolean, interval: Int): String? = withContext(Dispatchers.IO) {
        if (_config.value.modules.any { it.url == url }) return@withContext null
        var m = EngineModule(name = name.ifBlank { nameFromUrl(url) }, url = url, enabled = enabled,
            interval = interval.takeIf { it > 0 })
        var err: String? = null
        try {
            moduleFile(m.id).writeText(download(url))
            m = m.copy(updatedAt = System.currentTimeMillis() / 1000.0)
        } catch (e: Exception) {
            err = e.message ?: e.toString()
            moduleFile(m.id).writeText("")
        }
        update(reload = false) { it.copy(modules = it.modules + m, enabled = it.enabled || enabled) }
        reparseModules()
        onChanged?.invoke()
        err
    }

    suspend fun updateModule(m: EngineModule): String? = withContext(Dispatchers.IO) {
        if (m.url.isBlank()) return@withContext null
        _busy.value = _busy.value + m.id
        try {
            moduleFile(m.id).writeText(download(m.url))
            update(reload = false) { c ->
                c.copy(modules = c.modules.map { if (it.id == m.id) it.copy(updatedAt = System.currentTimeMillis() / 1000.0) else it })
            }
            reparseModules()
            onChanged?.invoke()
            null
        } catch (e: Exception) {
            e.message ?: e.toString()
        } finally {
            _busy.value = _busy.value - m.id
        }
    }

    suspend fun updateAll(): List<String> = _config.value.modules.filter { it.url.isNotBlank() }
        .mapNotNull { m -> updateModule(m)?.let { "${m.name}: $it" } }

    fun setModuleEnabled(m: EngineModule, on: Boolean) = update { c ->
        c.copy(modules = c.modules.map { if (it.id == m.id) it.copy(enabled = on) else it }, enabled = c.enabled || on)
    }

    fun deleteModule(m: EngineModule) {
        update(reload = false) { c -> c.copy(modules = c.modules.filter { it.id != m.id }) }
        moduleFile(m.id).delete()
        reparseModules()
        onChanged?.invoke()
    }

    fun moduleText(m: EngineModule): String = runCatching { moduleFile(m.id).readText() }.getOrDefault("")

    /** Hostnames contributed by enabled modules (read-only in the MitM page). */
    fun moduleHostnames(): List<String> {
        val info = _moduleInfo.value
        return _config.value.modules.filter { it.enabled }.flatMap { info[it.id]?.hostnames.orEmpty() }.distinct()
    }

    /** Everything the 重写规则 panel lists: user lines first, then each module's parsed rules. */
    fun rewriteEntries(): List<RewriteEntry> {
        val c = _config.value
        val out = mutableListOf<RewriteEntry>()
        for (it in c.rules + c.scripts) {
            val p = ParsedEngineText.parse(Core.engineParseLine(it.line, if (it in c.scripts) "script" else ""))
            val r = p?.rules?.firstOrNull() ?: ParsedEngineText.Rule(kind = "?", desc = it.line, line = it.line)
            out += RewriteEntry(r, "", c.enabled && it.enabled)
        }
        val info = _moduleInfo.value
        for (m in c.modules) {
            info[m.id]?.rules?.forEach { r -> out += RewriteEntry(r, m.name, c.enabled && m.enabled) }
        }
        return out
    }

    // ---- scripts ------------------------------------------------------------------------------

    fun localScripts(): List<String> = scriptsDir.list()?.filter { it.endsWith(".js") }?.sorted().orEmpty()

    // ---- CA -----------------------------------------------------------------------------------

    fun refreshCA() {
        _ca.value = runCatching { AppJson.decodeFromString(CAInfo.serializer(), Core.caInfo()) }.getOrDefault(CAInfo())
    }

    /** Generates (or replaces) the root CA. Throws with the core's message on failure. */
    suspend fun generateCA() = withContext(Dispatchers.IO) {
        Core.caGenerate()
        refreshCA()
        onChanged?.invoke()
    }

    /** DER bytes of the root certificate (for export to Downloads). */
    suspend fun certDer(): ByteArray = withContext(Dispatchers.IO) { Core.caCertDer() }
}
