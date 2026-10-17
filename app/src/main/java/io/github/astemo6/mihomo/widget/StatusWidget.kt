package io.github.astemo6.mihomo.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.MainActivity
import io.github.astemo6.mihomo.vpn.MihomoVpnService
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus

/** Home-screen widget: status, switch, current node and mode (RemoteViews; no extra dependency). */
class StatusWidget : AppWidgetProvider() {
    companion object {
        fun updateAll(context: Context) {
            val mgr = AppWidgetManager.getInstance(context)
            val ids = mgr.getAppWidgetIds(ComponentName(context, StatusWidget::class.java))
            if (ids.isNotEmpty()) ids.forEach { mgr.updateAppWidget(it, build(context)) }
        }

        private fun build(context: Context): RemoteViews {
            val info = VpnState.info.value
            val v = RemoteViews(context.packageName, R.layout.widget_status)
            val on = info.status == VpnStatus.RUNNING
            v.setTextViewText(R.id.widget_status, context.getString(when (info.status) {
                VpnStatus.RUNNING -> R.string.status_on
                VpnStatus.CONNECTING -> R.string.status_connecting
                VpnStatus.STOPPING -> R.string.status_stopping
                VpnStatus.STOPPED -> R.string.status_off
            }))
            v.setTextViewText(R.id.widget_profile, ProfileStore.active?.name ?: context.getString(R.string.no_profile_short))
            v.setTextViewText(R.id.widget_node, if (on) info.nodeText ?: "—" else "—")
            val mode = info.mode ?: Overrides.load().mode
            v.setTextViewText(R.id.widget_mode, context.getString(when (mode) {
                "global" -> R.string.mode_global
                "direct" -> R.string.mode_direct
                else -> R.string.mode_rule
            }))
            v.setImageViewResource(R.id.widget_toggle, if (on) R.drawable.ic_widget_on else R.drawable.ic_widget_off)

            val open = PendingIntent.getActivity(context, 10, Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            v.setOnClickPendingIntent(R.id.widget_root, open)
            val toggle = if (VpnController.needsPermission(context) || ProfileStore.active == null) {
                PendingIntent.getActivity(context, 11,
                    Intent(context, MainActivity::class.java).setAction(MainActivity.ACTION_CONNECT),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            } else {
                // Widget interaction is an allowed foreground-service start from the background.
                PendingIntent.getForegroundService(context, 12,
                    Intent(context, MihomoVpnService::class.java).setAction(MihomoVpnService.ACTION_TOGGLE),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            v.setOnClickPendingIntent(R.id.widget_toggle, toggle)
            return v
        }
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        appWidgetIds.forEach { appWidgetManager.updateAppWidget(it, build(context)) }
    }
}
