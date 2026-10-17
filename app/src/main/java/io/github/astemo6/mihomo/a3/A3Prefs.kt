package io.github.astemo6.mihomo.a3

import android.content.Context
import android.content.SharedPreferences
import io.github.astemo6.mihomo.data.AppJson
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.util.UUID

/**
 * 按网络切换 rule: when the current physical network matches [kind] (and [ssid] for SSID rules), apply
 * [target]: "mode:rule" | "mode:global" | "mode:direct" | "profile:<profile id>".
 */
@Serializable
data class NetRule(
    val id: String = UUID.randomUUID().toString(),
    /** "ssid" | "wifi" | "cellular" | "ethernet" */
    val kind: String,
    val ssid: String = "",
    val target: String,
    val enabled: Boolean = true,
) {
    companion object {
        const val KIND_SSID = "ssid"
        const val KIND_WIFI = "wifi"
        const val KIND_CELLULAR = "cellular"
        const val KIND_ETHERNET = "ethernet"
        val kinds = listOf(KIND_SSID, KIND_WIFI, KIND_CELLULAR, KIND_ETHERNET)
    }
}

/** A3 Android extras settings ("a3" shared prefs; separate from AppSettings so no shared file changes). */
object A3Prefs {
    private lateinit var prefs: SharedPreferences
    private val _rules = MutableStateFlow<List<NetRule>>(emptyList())
    val rules: StateFlow<List<NetRule>> = _rules.asStateFlow()
    private val _netEnabled = MutableStateFlow(false)
    val netEnabled: StateFlow<Boolean> = _netEnabled.asStateFlow()

    fun init(context: Context) {
        if (::prefs.isInitialized) return
        prefs = context.getSharedPreferences("a3", Context.MODE_PRIVATE)
        _rules.value = runCatching {
            AppJson.decodeFromString(ListSerializer(NetRule.serializer()), prefs.getString("netRules", "[]") ?: "[]")
        }.getOrDefault(emptyList())
        _netEnabled.value = prefs.getBoolean("netEnabled", false)
    }

    /** 开机自启: start the VPN after BOOT_COMPLETED (and after an app update when it was running). */
    var bootStart: Boolean
        get() = prefs.getBoolean("bootStart", false)
        set(v) = prefs.edit().putBoolean("bootStart", v).apply()

    fun setNetEnabled(v: Boolean) {
        prefs.edit().putBoolean("netEnabled", v).apply()
        _netEnabled.value = v
    }

    fun setRules(list: List<NetRule>) {
        prefs.edit().putString("netRules", AppJson.encodeToString(ListSerializer(NetRule.serializer()), list)).apply()
        _rules.value = list
    }

    /** What to do when no rule matches: "keep" (leave as is) or a target like "mode:rule". */
    var netDefault: String
        get() = prefs.getString("netDefault", "keep") ?: "keep"
        set(v) = prefs.edit().putString("netDefault", v).apply()

    /** Selected policy group for the node widget ("" = first selectable group). */
    var widgetGroup: String
        get() = prefs.getString("widgetGroup", "") ?: ""
        set(v) = prefs.edit().putString("widgetGroup", v).apply()

    /** Last always-on / lockdown status the service saw (VpnService.isAlwaysOn, API 29+). */
    var lastAlwaysOn: Boolean
        get() = prefs.getBoolean("lastAlwaysOn", false)
        set(v) = prefs.edit().putBoolean("lastAlwaysOn", v).apply()
    var lastLockdown: Boolean
        get() = prefs.getBoolean("lastLockdown", false)
        set(v) = prefs.edit().putBoolean("lastLockdown", v).apply()
}
