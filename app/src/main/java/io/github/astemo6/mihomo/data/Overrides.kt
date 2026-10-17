package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.core.Paths
import kotlinx.serialization.Serializable
import java.io.File
import java.security.SecureRandom

/**
 * <home>/overrides.json — the same fields (names and defaults) as the iOS app's CoreOverrides, read by
 * the Go bridge (readOverrides). iOS-only fields (tunnel scope, skip-proxy …) are kept so a file moved
 * between the two apps round-trips; the Android core ignores what does not apply.
 */
@Serializable
data class Overrides(
    val logLevel: String = "info",
    val ipv6: Boolean = false,
    val allowLan: Boolean = false,
    val dnsMode: String = "fake-ip",
    val sniffer: Boolean = true,
    val controllerPort: Int = 9090,
    val secret: String = "",
    val mode: String = "rule",
    val memoryLimitMB: Int = 26,
    val tunnelMode: String = "tun",
    val mixedPort: Int = 7890,
    val tunMTU: Int = 4064,
    val geoMirror: String = "jsdelivr",
    val geoURLs: Map<String, String> = emptyMap(),
    val mergeManual: Boolean = false,
    val safeMode: Boolean = false,
    val testURL: String = DEFAULT_TEST_URL,
    val testTimeoutMs: Int = 5000,
    val overrideHealthCheck: Boolean = false,
    val includedRoutes: List<String> = listOf("0.0.0.0/0", "::/0"),
    val excludedRoutes: List<String> = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"),
    val skipProxy: List<String> = listOf("localhost", "*.local", "127.0.0.1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "captive.apple.com"),
    val blockQUIC: String = "nondirect",
    val includeAllNetworks: Boolean = false,
    val excludeLocalNetworks: Boolean = true,
    val excludeAPNs: Boolean = true,
    val excludeCellularServices: Boolean = true,
    val excludeDeviceCommunication: Boolean = true,
    val lanAuth: LanAuth = LanAuth(),
    val lanLocalOnly: Boolean = true,
    val ipv6Mode: String = "off",
    val ipPreference: String = "dual",
) {
    @Serializable
    data class LanAuth(val username: String = "", val password: String = "")

    val testUrlOrDefault: String get() = if (isValidTestURL(testURL)) testURL.trim() else DEFAULT_TEST_URL
    val testTimeout: Int get() = testTimeoutMs.coerceIn(1000, 30000)
    val port: Int get() = if (controllerPort in 1..65535) controllerPort else 9090

    companion object {
        const val DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"
        val testURLPresets = listOf(
            "https://www.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "https://www.apple.com/library/test/success.html",
            "http://connectivitycheck.platform.hicloud.com/generate_204",
            "http://www.gstatic.com/generate_204",
            "https://www.google.com/generate_204",
        )
        val logLevels = listOf("silent", "error", "warning", "info", "debug")

        fun isValidTestURL(s: String): Boolean {
            val u = runCatching { java.net.URI(s.trim()) }.getOrNull() ?: return false
            val sc = u.scheme?.lowercase()
            return (sc == "http" || sc == "https") && !u.host.isNullOrEmpty()
        }

        private val file: File get() = Paths.overrides

        @Synchronized
        fun load(): Overrides {
            val f = file
            if (!f.exists()) return ensureSecret(Overrides())
            val o = runCatching { AppJson.decodeFromString(serializer(), f.readText()) }.getOrElse { Overrides() }
            return ensureSecret(o)
        }

        @Synchronized
        fun save(o: Overrides) {
            val f = file
            f.parentFile?.mkdirs()
            val tmp = File(f.parentFile, "overrides.json.tmp")
            tmp.writeText(AppJson.encodeToString(serializer(), o))
            if (!tmp.renameTo(f)) {
                f.writeText(tmp.readText()); tmp.delete()
            }
        }

        fun update(block: (Overrides) -> Overrides): Overrides {
            val n = block(load())
            save(n)
            return n
        }

        /** The controller is reachable by every app on the device (127.0.0.1): always use a secret. */
        private fun ensureSecret(o: Overrides): Overrides {
            if (o.secret.isNotEmpty()) return o
            val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val n = o.copy(secret = bytes.joinToString("") { "%02x".format(it) })
            runCatching { save(n) }
            return n
        }
    }
}
