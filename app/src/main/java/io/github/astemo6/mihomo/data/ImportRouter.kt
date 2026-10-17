package io.github.astemo6.mihomo.data

import android.net.Uri

/**
 * One entry point for everything that arrives from outside: clash:// and mihomo:// links,
 * pasted subscription URLs, share links / node lines and opened files.
 */
object ImportRouter {
    sealed interface Request {
        data class Remote(val url: String, val name: String = "") : Request
        data class Text(val text: String, val name: String = "") : Request
        /** A rewrite / MitM / script module (.sgmodule, .plugin, .stoverride, QX snippet …) → EngineStore (A2). */
        data class ModuleUrl(val url: String) : Request
        data class ModuleText(val text: String, val name: String = "") : Request
    }

    private val moduleHosts = setOf("install-module", "install-plugin", "install-override", "import-module")
    val moduleExtensions = setOf("sgmodule", "plugin", "lpx", "stoverride", "snippet", "module")

    private val installHosts = setOf("install-config", "install-profile", "import-profile", "subscribe")

    /** clash://install-config?url=…&name=…  mihomo://install-config?url=…  clashmeta://install-config?url=… */
    fun fromUri(uri: Uri): Request? {
        val scheme = uri.scheme?.lowercase() ?: return null
        if (scheme !in setOf("clash", "clashmeta", "mihomo")) return null
        val host = uri.host?.lowercase().orEmpty()
        if (host !in installHosts && host !in moduleHosts) return null
        val url = uri.getQueryParameter("url")?.trim().orEmpty()
        if (!url.startsWith("http://", true) && !url.startsWith("https://", true)) return null
        if (host in moduleHosts) return Request.ModuleUrl(url)
        return Request.Remote(url, uri.getQueryParameter("name").orEmpty())
    }

    /** Text from the clipboard / share sheet / paste box. */
    fun fromText(raw: String): Request? {
        val t = raw.trim().removePrefix("\uFEFF")
        if (t.isEmpty()) return null
        val single = !t.contains('\n') && !t.contains(' ')
        if (single) {
            if (t.startsWith("clash://", true) || t.startsWith("mihomo://", true) || t.startsWith("clashmeta://", true)) {
                return fromUri(Uri.parse(t))
            }
            if (t.startsWith("http://", true) || t.startsWith("https://", true)) {
                val ext = Uri.parse(t).lastPathSegment?.substringAfterLast('.', "")?.lowercase().orEmpty()
                return if (ext in moduleExtensions) Request.ModuleUrl(t) else Request.Remote(t)
            }
        }
        return Request.Text(t)
    }

    /** Whether clipboard text looks importable (for the paste banner). */
    fun looksImportable(raw: String): Boolean {
        val t = raw.trim()
        if (t.isEmpty() || t.length > 2_000_000) return false
        val schemes = listOf("http://", "https://", "clash://", "mihomo://", "ss://", "ssr://", "vmess://", "vless://",
            "trojan://", "hysteria2://", "hy2://", "tuic://", "anytls://", "socks5://", "wireguard://")
        return schemes.any { t.startsWith(it, true) } || t.contains("proxies:") || t.contains("[Proxy]") || t.contains("[server_local]")
    }
}
