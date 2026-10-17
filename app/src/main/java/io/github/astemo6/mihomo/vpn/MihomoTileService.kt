package io.github.astemo6.mihomo.vpn

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.MainActivity

/** Quick Settings tile: toggles the VPN; opens the app when the VPN permission is still missing. */
class MihomoTileService : TileService() {
    companion object {
        fun requestUpdate(context: Context) {
            runCatching { TileService.requestListeningState(context, ComponentName(context, MihomoTileService::class.java)) }
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        refresh()
    }

    override fun onTileAdded() {
        super.onTileAdded()
        refresh()
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    override fun onClick() {
        super.onClick()
        if (VpnController.needsPermission(this) || ProfileStore.active == null) {
            val intent = Intent(this, MainActivity::class.java)
                .setAction(MainActivity.ACTION_CONNECT)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(PendingIntent.getActivity(this, 2, intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
            return
        }
        VpnController.toggle(this)
        qsTile?.let {
            it.state = Tile.STATE_UNAVAILABLE
            it.updateTile()
        }
    }

    private fun refresh() {
        val tile = qsTile ?: return
        val info = VpnState.info.value
        tile.state = when (info.status) {
            VpnStatus.RUNNING -> Tile.STATE_ACTIVE
            VpnStatus.STOPPED -> Tile.STATE_INACTIVE
            else -> Tile.STATE_UNAVAILABLE
        }
        tile.label = getString(R.string.app_name)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = when (info.status) {
                VpnStatus.RUNNING -> ProfileStore.active?.name ?: getString(R.string.status_on)
                VpnStatus.CONNECTING -> getString(R.string.status_connecting)
                VpnStatus.STOPPING -> getString(R.string.status_stopping)
                VpnStatus.STOPPED -> getString(R.string.status_off)
            }
        }
        tile.updateTile()
    }
}
