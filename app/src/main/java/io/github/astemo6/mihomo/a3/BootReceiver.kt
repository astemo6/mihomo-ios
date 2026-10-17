package io.github.astemo6.mihomo.a3

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState

/**
 * 开机自启. BOOT_COMPLETED (and LOCKED_BOOT_COMPLETED where the platform delivers it to a non direct-boot
 * component, i.e. devices without file-based encryption): profiles live in credential-encrypted storage,
 * so the VPN can only start once the user unlocked; the receiver is intentionally not directBootAware.
 * MY_PACKAGE_REPLACED: reconnect after an app update when the VPN was running before it.
 *
 * When the system always-on VPN is set to this app, the system starts the service itself (action
 * android.net.VpnService); starting it here as well is harmless (startVpn is idempotent).
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        A3Prefs.init(context)
        val action = intent.action ?: return
        val wanted = when (action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_LOCKED_BOOT_COMPLETED, "android.intent.action.QUICKBOOT_POWERON" -> A3Prefs.bootStart
            Intent.ACTION_MY_PACKAGE_REPLACED -> A3Prefs.bootStart && AppSettings.wantRunning
            else -> false
        }
        if (!wanted || VpnState.info.value.status != io.github.astemo6.mihomo.vpn.VpnStatus.STOPPED) return
        if (ProfileStore.active == null) {
            Log.i("A3Boot", "no active profile, not starting")
            return
        }
        if (VpnService.prepare(context) != null) {
            // Permission never granted (or revoked by another VPN app): needs the UI.
            A3Runtime.notifyBackgroundFailure(context, null)
            return
        }
        A3Runtime.markBackgroundStart()
        // BOOT_COMPLETED is an allowed foreground-service start (specialUse is not in the Android 15 list).
        runCatching { VpnController.start(context) }.onFailure { Log.w("A3Boot", "start", it) }
    }
}
