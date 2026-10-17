package io.github.astemo6.mihomo.data.feature2

import android.content.Context
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import libmihomo.Libmihomo

/**
 * A2 bridge calls (gomobile `libmihomo.Libmihomo`) used by the feature2 screens. Kept apart from
 * core/Core.kt so this branch does not touch shared files. Everything may block: call from IO.
 */
object F2Core {
    val home: String get() = Paths.home.absolutePath

    /** The active profile file, or null when there is none. */
    val activePath: String? get() = ProfileStore.active?.file?.absolutePath
    val activeId: String? get() = ProfileStore.active?.id

    val isConnected: Boolean get() = VpnState.info.value.isRunning

    /** Reloads the running core so edits to the override stores take effect (no-op when stopped). */
    fun reload(context: Context) = VpnController.reload(context)

    suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    // ---- node subscriptions / sub rules ---------------------------------------------------------
    fun providerStore(kind: String, cachePath: String, convert: String, data: ByteArray): String =
        Libmihomo.providerStore(home, kind, cachePath, convert, data)

    fun nodeSubPath(id: String): String = Libmihomo.nodeSubPath(home, id)
    fun subPreview(profilePath: String, rulesJson: String): String = Libmihomo.subPreview(home, profilePath, rulesJson)
    fun detectRegion(name: String): String = runCatching { Libmihomo.detectRegion(name) }.getOrDefault("")

    // ---- custom rules ---------------------------------------------------------------------------
    fun checkCustomRules(profilePath: String): String = Libmihomo.checkCustomRules(home, profilePath)
    fun checkRuleLine(profilePath: String, line: String): String = Libmihomo.checkRuleLine(home, profilePath, line)
    fun profileGroups(profilePath: String): String = Libmihomo.profileGroups(home, profilePath)

    // ---- group edits / smart / chains -----------------------------------------------------------
    fun groupSpecs(profilePath: String): String = Libmihomo.groupSpecs(home, profilePath)
    fun groupEditCheck(profilePath: String, editsJson: String): String = Libmihomo.groupEditCheck(home, profilePath, editsJson)
    fun setGroupChain(profilePath: String, group: String, via: String): String = Libmihomo.setGroupChain(home, profilePath, group, via)
    fun chainCandidates(profilePath: String, kind: String, name: String): String =
        Libmihomo.chainCandidates(home, profilePath, kind, name)

    // ---- manual nodes / share links -------------------------------------------------------------
    fun manualList(path: String): String = Libmihomo.manualList(path)
    fun manualAddText(path: String, text: String): Int = Libmihomo.manualAddText(path, text)
    fun manualUpsert(path: String, nodeJson: String, oldName: String): String = Libmihomo.manualUpsert(path, nodeJson, oldName)
    fun manualDelete(path: String, name: String): String = Libmihomo.manualDelete(path, name)
    fun manualSubscription(path: String): String = Libmihomo.manualSubscription(path)
    fun nodeShareLink(nodeJson: String): String = Libmihomo.nodeShareLink(nodeJson)
    fun nodeShareLinkByName(profilePath: String, name: String): String = Libmihomo.nodeShareLinkByName(home, profilePath, name)
    fun lastError(): String = Libmihomo.lastError()

    // ---- probe / diagnostics / traffic -----------------------------------------------------------
    fun probePort(): Int = runCatching { Libmihomo.probePort(home).trim().toInt() }.getOrDefault(7899)
    const val PROBE_GROUP = "MIHOMO-PROBE"

    fun writeDiagnosticBundle(profilePath: String, appInfo: String, outPath: String) =
        Libmihomo.writeDiagnosticBundle(home, profilePath, appInfo, outPath)

    fun diagnosticSummary(profilePath: String, appInfo: String): String = Libmihomo.diagnosticSummary(home, profilePath, appInfo)
    fun dumpDiagnostics() = runCatching { Libmihomo.dumpDiagnostics() }

    /** (up, down) bytes since the core started, or null when it is not running. */
    fun trafficTotals(): Pair<Long, Long>? = runCatching {
        if (!Libmihomo.isRunning()) return@runCatching null
        val p = Libmihomo.trafficTotals().split(',')
        p[0].trim().toLong() to p[1].trim().toLong()
    }.getOrNull()

    fun memoryStats(): String = runCatching { Libmihomo.memoryStats() }.getOrDefault("")
}
