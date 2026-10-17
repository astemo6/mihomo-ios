package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import libmihomo.Libmihomo
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate

// A2 engine extras (module arguments / policy mapping, local scripts, p12, CA trust check). Kept apart from
// EngineStore.kt; same files as the iOS EngineShared / EngineStore (engine.json modules[].args / .policies).

private val stringMap = MapSerializer(String.serializer(), String.serializer())
private val stringList = ListSerializer(String.serializer())

/** Path of the active profile file, or null when there is none. */
internal fun activeProfilePath(): String? = ProfileStore.active?.file?.takeIf { it.exists() }?.absolutePath

/** Where a root CA is found in the Android trust store (AndroidCAStore). */
enum class CaTrust { NO_CA, NOT_INSTALLED, USER, SYSTEM, UNKNOWN }

object EngineExtras {
    private val home: String get() = Paths.home.absolutePath

    // ---- module arguments ---------------------------------------------------------------------

    /** Saves the module's #!arguments values (merged over earlier ones) and re-parses with them. */
    fun setModuleArgs(moduleId: String, values: Map<String, String>) {
        EngineStore.update(reload = false) { c ->
            c.copy(modules = c.modules.map { m ->
                if (m.id != moduleId) m else m.copy(args = ((m.args ?: emptyMap()) + values).ifEmpty { null })
            })
        }
        EngineStore.reparseModules()
        EngineStore.onChanged?.invoke()
    }

    /** Clears user argument values (back to the module's defaults). */
    fun resetModuleArgs(moduleId: String) {
        EngineStore.update(reload = false) { c ->
            c.copy(modules = c.modules.map { if (it.id == moduleId) it.copy(args = null) else it })
        }
        EngineStore.reparseModules()
        EngineStore.onChanged?.invoke()
    }

    // ---- module policy mapping ----------------------------------------------------------------

    /** group = null / "" removes the mapping (the engine then uses the first select group). */
    fun setModulePolicy(moduleId: String, policy: String, group: String?) = EngineStore.update { c ->
        c.copy(modules = c.modules.map { m ->
            if (m.id != moduleId) m else {
                val p = (m.policies ?: emptyMap()).toMutableMap()
                if (group.isNullOrEmpty()) p.remove(policy) else p[policy] = group
                m.copy(policies = p.ifEmpty { null })
            }
        })
    }

    /** Policies the module's [Rule] lines name that the active profile lacks (sorted). */
    suspend fun moduleUnresolved(m: EngineModule): List<String> = withContext(Dispatchers.IO) {
        val profile = activeProfilePath() ?: return@withContext emptyList()
        val args = AppJson.encodeToString(stringMap, m.args ?: emptyMap())
        runCatching {
            AppJson.decodeFromString(stringList, Libmihomo.moduleUnresolved(home, profile, EngineStore.moduleText(m), args))
        }.getOrDefault(emptyList()).sorted()
    }

    /** Policy groups of the active profile (targets for the mapping picker). */
    suspend fun profileGroups(): List<String> = withContext(Dispatchers.IO) {
        val profile = activeProfilePath() ?: return@withContext emptyList()
        runCatching { AppJson.decodeFromString(stringList, Libmihomo.profileGroups(home, profile)) }.getOrDefault(emptyList())
    }

    // ---- local scripts (engine/scripts/*.js) -------------------------------------------------

    private fun scriptFile(name: String): File {
        val n = name.trim().replace('/', '_').replace('\\', '_').let { if (it.endsWith(".js")) it else "$it.js" }
        return File(EngineStore.scriptsDir, n)
    }

    fun readLocalScript(name: String): String = runCatching { scriptFile(name).readText() }.getOrDefault("")

    /** Writes engine/scripts/<name>.js; returns the final file name. Reloads so running scripts pick it up. */
    fun saveLocalScript(name: String, code: String): String {
        val f = scriptFile(name)
        f.writeText(code)
        EngineStore.onChanged?.invoke()
        return f.name
    }

    fun deleteLocalScript(name: String) {
        scriptFile(name).delete()
    }

    /** Code of a local script name or the engine's cached copy of a remote script URL; null + error otherwise. */
    suspend fun scriptSource(path: String): Result<String> = withContext(Dispatchers.IO) {
        val s = Libmihomo.scriptSource(home, path)
        if (s.isEmpty()) Result.failure(EngineException(Libmihomo.lastError().ifEmpty { "?" })) else Result.success(s)
    }

    // ---- CA p12 + trust check -----------------------------------------------------------------

    suspend fun exportP12(password: String): ByteArray = withContext(Dispatchers.IO) { Libmihomo.caExportP12(home, password) }

    /** Replaces the root CA with the one in a .p12 (throws with the core's message). */
    suspend fun importP12(data: ByteArray, password: String) = withContext(Dispatchers.IO) {
        Libmihomo.caImportP12(home, data, password)
        EngineStore.refreshCA()
        EngineStore.onChanged?.invoke()
    }

    /**
     * Looks the root certificate up in AndroidCAStore: aliases "user:…" are user-installed CAs, "system:…"
     * the system store. Matching is by SHA-256 of the DER encoding.
     */
    suspend fun caTrust(): CaTrust = withContext(Dispatchers.IO) {
        val der = runCatching { Libmihomo.caCertDER(home) }.getOrNull() ?: return@withContext CaTrust.NO_CA
        if (der.isEmpty()) return@withContext CaTrust.NO_CA
        val want = sha256(der)
        runCatching {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            var found: CaTrust = CaTrust.NOT_INSTALLED
            for (alias in ks.aliases()) {
                val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
                if (sha256(cert.encoded).contentEquals(want)) {
                    found = if (alias.startsWith("system:")) CaTrust.SYSTEM else CaTrust.USER
                    break
                }
            }
            found
        }.getOrDefault(CaTrust.UNKNOWN)
    }

    private fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
}
