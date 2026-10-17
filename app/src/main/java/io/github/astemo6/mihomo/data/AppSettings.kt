package io.github.astemo6.mihomo.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Android-only app settings (not read by the core). */
object AppSettings {
    private lateinit var prefs: SharedPreferences

    enum class Theme { SYSTEM, LIGHT, DARK }
    enum class PerAppMode { OFF, ALLOW, DENY }

    private val _theme = MutableStateFlow(Theme.SYSTEM)
    val theme: StateFlow<Theme> = _theme.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        _theme.value = runCatching { Theme.valueOf(prefs.getString("theme", "SYSTEM")!!) }.getOrDefault(Theme.SYSTEM)
    }

    fun setTheme(t: Theme) {
        prefs.edit().putString("theme", t.name).apply()
        _theme.value = t
    }

    var activeProfileId: String?
        get() = prefs.getString("activeProfileID", null)
        set(v) = prefs.edit().putString("activeProfileID", v).apply()

    /** 协议栈: gvisor (default) | system | mixed (SetTunStack). */
    var tunStack: String
        get() = prefs.getString("tunStack", "gvisor") ?: "gvisor"
        set(v) = prefs.edit().putString("tunStack", v).apply()

    var perAppMode: PerAppMode
        get() = runCatching { PerAppMode.valueOf(prefs.getString("perAppMode", "OFF")!!) }.getOrDefault(PerAppMode.OFF)
        set(v) = prefs.edit().putString("perAppMode", v.name).apply()

    var perAppPackages: Set<String>
        get() = prefs.getStringSet("perAppPackages", emptySet())?.toSet() ?: emptySet()
        set(v) = prefs.edit().putStringSet("perAppPackages", v).apply()

    /** Set while the VPN should be up (for always-on / process restarts). */
    var wantRunning: Boolean
        get() = prefs.getBoolean("wantRunning", false)
        set(v) = prefs.edit().putBoolean("wantRunning", v).apply()

    var lastIpInfo: String?
        get() = prefs.getString("lastIpInfo", null)
        set(v) = prefs.edit().putString("lastIpInfo", v).apply()
}
