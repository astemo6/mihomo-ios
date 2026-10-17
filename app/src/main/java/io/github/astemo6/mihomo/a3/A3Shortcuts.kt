package io.github.astemo6.mihomo.a3

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Toast
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.MainActivity
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * App Shortcuts. Static ones (res/xml/shortcuts.xml, one copy per build type because the debug build has
 * the ".debug" application id suffix): 连接/断开, 切换模式, 配置. Dynamic ones: the first profiles other than
 * the active one ("使用 X" = switch profile and connect). All go through [ShortcutActivity].
 */
object A3Shortcuts {
    const val ACTION_TOGGLE = "io.github.astemo6.mihomo.SHORTCUT_TOGGLE"
    const val ACTION_CONNECT = "io.github.astemo6.mihomo.SHORTCUT_CONNECT"
    const val ACTION_DISCONNECT = "io.github.astemo6.mihomo.SHORTCUT_DISCONNECT"
    const val ACTION_MODE = "io.github.astemo6.mihomo.SHORTCUT_MODE"
    const val ACTION_PROFILES = "io.github.astemo6.mihomo.SHORTCUT_PROFILES"
    const val ACTION_USE_PROFILE = "io.github.astemo6.mihomo.SHORTCUT_USE_PROFILE"
    const val EXTRA_PROFILE = "profile"
    const val EXTRA_MODE = "mode"

    /** MainActivity: open this route once (from the 配置 shortcut). */
    const val ACTION_OPEN_ROUTE = "io.github.astemo6.mihomo.OPEN_ROUTE"
    const val EXTRA_ROUTE = "route"
    val pendingRoute = MutableStateFlow<String?>(null)

    private const val DYNAMIC_PROFILES = 2

    fun publishDynamic(context: Context) {
        val active = ProfileStore.active?.id
        val list = ProfileStore.profiles.value.filter { it.id != active }.take(DYNAMIC_PROFILES)
        val shortcuts = list.mapIndexed { i, p ->
            ShortcutInfoCompat.Builder(context, "profile-${p.id}")
                .setShortLabel(p.name.take(24))
                .setLongLabel(context.getString(R.string.a3_sc_use_profile, p.name))
                .setIcon(IconCompat.createWithResource(context, R.drawable.ic_sc_profile))
                .setRank(10 + i)
                .setIntent(Intent(context, ShortcutActivity::class.java)
                    .setAction(ACTION_USE_PROFILE).putExtra(EXTRA_PROFILE, p.id))
                .build()
        }
        ShortcutManagerCompat.setDynamicShortcuts(context, shortcuts)
    }

    fun nextMode(m: String): String = when (m) {
        "rule" -> "global"
        "global" -> "direct"
        else -> "rule"
    }
}

/** Invisible trampoline: performs the shortcut action and finishes (falls back to the app when it needs UI). */
class ShortcutActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
        finish()
    }

    private fun handle(intent: Intent?) {
        val action = intent?.action ?: return
        val running = VpnState.info.value.status.let { it == VpnStatus.RUNNING || it == VpnStatus.CONNECTING }
        when (action) {
            A3Shortcuts.ACTION_TOGGLE -> if (running) VpnController.stop(this) else connect()
            A3Shortcuts.ACTION_CONNECT -> if (!running) connect()
            A3Shortcuts.ACTION_DISCONNECT -> if (running) VpnController.stop(this)
            A3Shortcuts.ACTION_MODE -> {
                val cur = VpnState.info.value.mode ?: Overrides.load().mode
                val m = intent.getStringExtra(A3Shortcuts.EXTRA_MODE) ?: A3Shortcuts.nextMode(cur)
                A3Runtime.scope.launch { NetworkModeSwitcher.applyMode(m) }
                Toast.makeText(this, getString(R.string.a3_mode_switched, getString(when (m) {
                    "global" -> R.string.mode_global
                    "direct" -> R.string.mode_direct
                    else -> R.string.mode_rule
                })), Toast.LENGTH_SHORT).show()
            }
            A3Shortcuts.ACTION_PROFILES -> startActivity(Intent(this, MainActivity::class.java)
                .setAction(A3Shortcuts.ACTION_OPEN_ROUTE)
                .putExtra(A3Shortcuts.EXTRA_ROUTE, io.github.astemo6.mihomo.ui.Routes.PROFILES)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            A3Shortcuts.ACTION_USE_PROFILE -> {
                val id = intent.getStringExtra(A3Shortcuts.EXTRA_PROFILE)
                val p = ProfileStore.profiles.value.firstOrNull { it.id == id }
                if (p == null) {
                    Toast.makeText(this, R.string.err_profile_missing, Toast.LENGTH_SHORT).show(); return
                }
                ProfileStore.setActive(p) // reloads a running core
                if (!running) connect()
            }
        }
    }

    private fun connect() {
        if (ProfileStore.active == null || VpnService.prepare(this) != null) {
            startActivity(Intent(this, MainActivity::class.java).setAction(MainActivity.ACTION_CONNECT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } else {
            VpnController.start(this)
        }
    }
}
