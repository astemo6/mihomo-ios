package io.github.astemo6.mihomo.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat

/** UI / tile / widget side entry points for the VPN service. */
object VpnController {
    fun needsPermission(context: Context): Boolean = VpnService.prepare(context) != null

    fun start(context: Context) = send(context, MihomoVpnService.ACTION_START)
    fun stop(context: Context) = send(context, MihomoVpnService.ACTION_STOP)
    fun reload(context: Context) {
        if (VpnState.info.value.isRunning) send(context, MihomoVpnService.ACTION_RELOAD)
    }

    fun toggle(context: Context) {
        val s = VpnState.info.value.status
        if (s == VpnStatus.RUNNING || s == VpnStatus.CONNECTING) stop(context) else start(context)
    }

    private fun send(context: Context, action: String) {
        val i = Intent(context, MihomoVpnService::class.java).setAction(action)
        if (action == MihomoVpnService.ACTION_START) {
            ContextCompat.startForegroundService(context, i)
        } else if (VpnState.info.value.status != VpnStatus.STOPPED) {
            // Service is in the foreground already: a plain start is allowed.
            runCatching { context.startService(i) }.onFailure { ContextCompat.startForegroundService(context, i) }
        }
    }
}
