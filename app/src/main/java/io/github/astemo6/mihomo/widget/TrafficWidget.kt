package io.github.astemo6.mihomo.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.a3.A3Runtime
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainActivity
import io.github.astemo6.mihomo.vpn.MihomoVpnService
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus

/** 流量 widget: current ↑ / ↓ speed and this session's totals (fed by A3Runtime every ~3 s, screen on). */
class TrafficWidget : AppWidgetProvider() {
    companion object {
        private fun ids(context: Context): IntArray =
            AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, TrafficWidget::class.java))

        fun hasWidgets(context: Context): Boolean = ids(context).isNotEmpty()

        fun updateAll(context: Context) {
            val ids = ids(context)
            if (ids.isEmpty()) return
            val mgr = AppWidgetManager.getInstance(context)
            val v = build(context)
            ids.forEach { mgr.updateAppWidget(it, v) }
        }

        private fun build(context: Context): RemoteViews {
            val info = VpnState.info.value
            val on = info.status == VpnStatus.RUNNING
            val t = A3Runtime.traffic
            val v = RemoteViews(context.packageName, R.layout.widget_traffic)
            v.setTextViewText(R.id.wt_status, context.getString(when (info.status) {
                VpnStatus.RUNNING -> R.string.status_on
                VpnStatus.CONNECTING -> R.string.status_connecting
                VpnStatus.STOPPING -> R.string.status_stopping
                VpnStatus.STOPPED -> R.string.status_off
            }))
            v.setTextViewText(R.id.wt_up, if (on) Fmt.speed(t.up) else "—")
            v.setTextViewText(R.id.wt_down, if (on) Fmt.speed(t.down) else "—")
            v.setTextViewText(R.id.wt_total, if (on)
                context.getString(R.string.a3_widget_session_total, Fmt.bytes(t.upTotal), Fmt.bytes(t.downTotal)) else "")
            v.setImageViewResource(R.id.wt_toggle, if (on) R.drawable.ic_widget_on else R.drawable.ic_widget_off)

            v.setOnClickPendingIntent(R.id.wt_root, PendingIntent.getActivity(context, 25,
                Intent(context, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
            val toggle = if (VpnController.needsPermission(context) || ProfileStore.active == null) {
                PendingIntent.getActivity(context, 26,
                    Intent(context, MainActivity::class.java).setAction(MainActivity.ACTION_CONNECT),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            } else {
                PendingIntent.getForegroundService(context, 27,
                    Intent(context, MihomoVpnService::class.java).setAction(MihomoVpnService.ACTION_TOGGLE),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            }
            v.setOnClickPendingIntent(R.id.wt_toggle, toggle)
            return v
        }
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        updateAll(context)
    }
}
