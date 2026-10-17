package io.github.astemo6.mihomo.core

import libmihomo.Libmihomo
import libmihomo.SocketProtector
import java.util.TimeZone

/**
 * Thin Kotlin facade over the gomobile binding of core/ (Go package `libmihomo` → Java class
 * `libmihomo.Libmihomo`). Go `int` maps to Java `long`, `int32` to `int`, an `error` result to a
 * thrown Exception. Everything here may block; call it off the main thread.
 */
object Core {
    fun start(configPath: String, tunFd: Int) = Libmihomo.start(Paths.home.absolutePath, configPath, tunFd)
    fun reload(configPath: String) = Libmihomo.reload(configPath)
    fun stop() = Libmihomo.stop()
    val isRunning: Boolean get() = Libmihomo.isRunning()
    val version: String get() = runCatching { Libmihomo.version() }.getOrDefault("")
    val lastError: String get() = Libmihomo.lastError()

    fun setProtector(protector: ((Int) -> Boolean)?) {
        Libmihomo.setSocketProtector(protector?.let { p -> SocketProtector { fd -> p(fd) } })
    }

    fun setTunStack(stack: String) = Libmihomo.setTunStack(stack)
    fun setNetworkIPv6(on: Boolean) = Libmihomo.setNetworkIPv6(on)
    fun setNetworkState(type: String, ssid: String): String = Libmihomo.setNetworkState(type, ssid)
    fun notifyNetworkChanged(infoJson: String) { Libmihomo.notifyNetworkChanged(infoJson) }
    fun freeMemory() = Libmihomo.freeMemory()

    fun initLogging() {
        val tz = TimeZone.getDefault()
        val offset = tz.getOffset(System.currentTimeMillis()) / 1000
        runCatching {
            Libmihomo.setStageLog(Paths.stageLog.absolutePath, offset.toLong())
            Libmihomo.setTimeZone(tz.id, offset.toLong())
        }
    }

    /** "" when valid, otherwise the parser's error. */
    fun validate(path: String): String = Libmihomo.validateConfigIn(Paths.home.absolutePath, path)

    /** "profile" | "conf" | "module:<fmt>" | "nodes" | "" */
    fun classify(text: String): String = Libmihomo.classifyText(text)

    /** JSON {yaml, module, rewriteRemotes, report, error} */
    fun importConf(text: String): String = Libmihomo.importConf(text)

    /** mihomo YAML or "" (see [lastError]). Also handles SIP008 JSON (core side). */
    fun convertShareLinks(text: String): String = Libmihomo.convertShareLinks(text)

    fun inspectProfile(path: String): String = Libmihomo.inspectProfile(Paths.home.absolutePath, path)
    fun saveSelection(profilePath: String, group: String, node: String): String =
        Libmihomo.saveSelection(profilePath, group, node)

    fun testDelayByName(profilePath: String, name: String, url: String, timeoutMs: Int): Int =
        Libmihomo.testDelayByName(Paths.home.absolutePath, profilePath, name, url, timeoutMs.toLong()).toInt()

    fun migrateProfileProviders(path: String) { Libmihomo.migrateProfileProviders(path) }
    // ---- HTTP engine (core/mitm): modules, rewrite, scripts, MitM CA ----
    /** JSON ParsedEngineText for a whole module / snippet; argsJSON = module arguments. */
    fun engineParseText(text: String, argsJson: String): String = Libmihomo.engineParseText(text, argsJson)
    /** JSON ParsedEngineText for one line; section "script" forces the script reading. */
    fun engineParseLine(line: String, section: String): String = Libmihomo.engineParseLine(line, section)
    fun caInfo(): String = Libmihomo.caInfo(Paths.home.absolutePath)
    fun caGenerate(): String = Libmihomo.caGenerate(Paths.home.absolutePath)
    fun caCertDer(): ByteArray = Libmihomo.caCertDER(Paths.home.absolutePath)
    fun caExportP12(password: String): ByteArray = Libmihomo.caExportP12(Paths.home.absolutePath, password)
    /** "" when the hosts entry is valid, otherwise the reason. */
    fun validateHostEntry(domain: String, value: String): String = Libmihomo.validateHostEntry(domain, value)

    fun friendlyError(msg: String): String = runCatching { Libmihomo.friendlyError(msg) }.getOrDefault(msg).ifEmpty { msg }
}
