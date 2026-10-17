package io.github.astemo6.mihomo.data.feature2

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Debug
import androidx.core.os.LocaleListCompat
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.vpn.VpnState
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 诊断 → 导出诊断包 (iOS DiagnosticsExporter): flushes the core-log / memory rings, collects the app's own
 * state as key=value lines, and lets the Go bridge write one redacted zip (diagbundle.go + redact.go).
 */
object Diagnostics {
    fun appInfo(context: Context): String {
        val pm = context.packageManager
        val pi = runCatching { pm.getPackageInfo(context.packageName, 0) }.getOrNull()
        @Suppress("DEPRECATION")
        val ver = pi?.let { "${it.versionName} (${if (Build.VERSION.SDK_INT >= 28) it.longVersionCode else it.versionCode.toLong()})" } ?: "?"
        val o = Overrides.load()
        val vpn = VpnState.info.value
        val am = context.getSystemService(ActivityManager::class.java)
        val mi = ActivityManager.MemoryInfo().also { runCatching { am?.getMemoryInfo(it) } }
        val pss = runCatching { Debug.getPss() }.getOrDefault(-1L)
        val langs = LocaleListCompat.getAdjustedDefault().toLanguageTags()
        val lines = mutableListOf(
            "app=$ver",
            "android=${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            "device=${Build.MANUFACTURER} ${Build.MODEL} abi=${Build.SUPPORTED_ABIS.joinToString(",")}",
            "language=${langs.split(',').take(3).joinToString(",")}",
            "app.id=${context.packageName}",
            "vpn.status=${vpn.status} since=${vpn.since ?: "-"}",
            "vpn.lastError=${vpn.error ?: "-"}",
            "mode=${o.tunnelMode} dns=${o.dnsMode} ipv6=${o.ipv6Mode} ipPref=${o.ipPreference} mtu=${o.tunMTU} memlimit=${o.memoryLimitMB}MB " +
                "testURL=${o.testURL} hcOverride=${o.overrideHealthCheck} loglevel=${o.logLevel} sniffer=${o.sniffer} allowLan=${o.allowLan} " +
                "mergeManual=${o.mergeManual} safeMode=${o.safeMode} blockQUIC=${o.blockQUIC}",
            "android.settings=theme=${AppSettings.theme.value} stack=${AppSettings.tunStack} perApp=${AppSettings.perAppMode} (${AppSettings.perAppPackages.size})",
            "profiles=${ProfileStore.profiles.value.size} active=${ProfileStore.active?.kind ?: "none"}",
            "nodesubs=${NodeSubStore.subs.value.count { it.enabled }}/${NodeSubStore.subs.value.size} customRules=${CustomRulesStore.load().size}",
            "app.memory=pss ${if (pss >= 0) "%.1f MB".format(Locale.US, pss / 1024.0) else "-"}, avail ${"%.0f MB".format(Locale.US, mi.availMem / 1048576.0)}, low=${mi.lowMemory}",
            "core.memory=${F2Core.memoryStats().ifBlank { "-" }}",
        )
        ProfileStore.active?.let { p ->
            lines += "active.profile.name=${p.name} updated=${p.lastUpdated?.let { SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US).format(Date(it)) } ?: "-"}"
        }
        return lines.joinToString("\n")
    }

    /** Writes the redacted zip into cacheDir/diagnostics/ and returns it. */
    fun export(context: Context): File {
        F2Core.dumpDiagnostics()
        val dir = File(context.cacheDir, "diagnostics")
        dir.deleteRecursively()
        dir.mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val out = File(dir, "Mihomo-diagnostics-$stamp.zip")
        F2Core.writeDiagnosticBundle(F2Core.activePath.orEmpty(), appInfo(context), out.absolutePath)
        return out
    }

    fun summary(context: Context): String {
        F2Core.dumpDiagnostics()
        return F2Core.diagnosticSummary(F2Core.activePath.orEmpty(), appInfo(context))
    }
}
