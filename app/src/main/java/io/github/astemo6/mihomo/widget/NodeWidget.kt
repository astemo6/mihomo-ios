package io.github.astemo6.mihomo.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.RemoteViews
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.a3.A3Prefs
import io.github.astemo6.mihomo.a3.A3Runtime
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.api.ProxyItem
import io.github.astemo6.mihomo.ui.MainActivity
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * 节点切换 widget: one select group (cycled with the swap button), its current member and ◀ / ▶ to pick
 * the previous / next member (PUT /proxies/{group} through the controller). Works while connected.
 */
class NodeWidget : AppWidgetProvider() {
    private data class State(val group: String = "", val node: String = "", val index: Int = -1, val count: Int = 0)

    companion object {
        private const val ACTION_PREV = "io.github.astemo6.mihomo.widget.NODE_PREV"
        private const val ACTION_NEXT = "io.github.astemo6.mihomo.widget.NODE_NEXT"
        private const val ACTION_GROUP = "io.github.astemo6.mihomo.widget.NODE_GROUP"
        @Volatile private var cache = State()

        private fun ids(context: Context): IntArray =
            AppWidgetManager.getInstance(context).getAppWidgetIds(ComponentName(context, NodeWidget::class.java))

        /** Redraw from the cache now, then refresh the cache from the controller when connected. */
        fun updateAll(context: Context) {
            val ids = ids(context)
            if (ids.isEmpty()) return
            push(context, ids)
            if (VpnState.info.value.isRunning) A3Runtime.scope.launch {
                runCatching { refresh(null) }
                push(context, ids(context))
            } else cache = State()
        }

        private fun push(context: Context, ids: IntArray) {
            val mgr = AppWidgetManager.getInstance(context)
            ids.forEach { mgr.updateAppWidget(it, build(context)) }
        }

        private fun selectable(proxies: Map<String, ProxyItem>): List<ProxyItem> {
            val order = proxies["GLOBAL"]?.all.orEmpty()
            val inOrder = order.mapNotNull { proxies[it] }.filter { it.isSelectable && it.hidden != true }
            val rest = proxies.values.filter { it.isSelectable && it.hidden != true && it.name != "GLOBAL" && it !in inOrder }
            return (inOrder + rest).ifEmpty { listOfNotNull(proxies["GLOBAL"]) }
        }

        /** delta: null = just read; -1 / +1 = select previous / next member; 0 = next group. */
        private suspend fun refresh(delta: Int?) {
            val proxies = withTimeoutOrNull(4000) { ControllerClient.proxies() } ?: return
            val groups = selectable(proxies)
            if (groups.isEmpty()) { cache = State(); return }
            var gi = groups.indexOfFirst { it.name == A3Prefs.widgetGroup }.coerceAtLeast(0)
            if (delta == 0) {
                gi = (gi + 1) % groups.size
                A3Prefs.widgetGroup = groups[gi].name
            }
            val g = groups[gi]
            val members = g.all.orEmpty()
            var now = g.now.orEmpty()
            if ((delta == 1 || delta == -1) && members.isNotEmpty()) {
                val cur = members.indexOf(now).coerceAtLeast(0)
                val next = members[(cur + delta + members.size) % members.size]
                runCatching { ControllerClient.select(g.name, next) }.onSuccess { now = next }
            }
            cache = State(g.name, now, members.indexOf(now), members.size)
        }

        private fun build(context: Context): RemoteViews {
            val v = RemoteViews(context.packageName, R.layout.widget_node)
            val on = VpnState.info.value.isRunning
            val s = cache
            v.setTextViewText(R.id.wn_group, if (on && s.group.isNotEmpty()) s.group else context.getString(R.string.a3_widget_node_name))
            v.setTextViewText(R.id.wn_node, when {
                !on -> context.getString(R.string.status_off)
                s.node.isNotEmpty() -> s.node
                else -> "—"
            })
            v.setTextViewText(R.id.wn_pos, if (on && s.count > 0) "${s.index + 1} / ${s.count}" else "")
            val open = PendingIntent.getActivity(context, 20, Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            v.setOnClickPendingIntent(R.id.wn_root, open)
            v.setOnClickPendingIntent(R.id.wn_prev, self(context, ACTION_PREV, 21))
            v.setOnClickPendingIntent(R.id.wn_next, self(context, ACTION_NEXT, 22))
            v.setOnClickPendingIntent(R.id.wn_group_next, self(context, ACTION_GROUP, 23))
            return v
        }

        private fun self(context: Context, action: String, code: Int): PendingIntent =
            PendingIntent.getBroadcast(context, code, Intent(context, NodeWidget::class.java).setAction(action),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        updateAll(context)
    }

    override fun onReceive(context: Context, intent: Intent) {
        val delta = when (intent.action) {
            ACTION_PREV -> -1
            ACTION_NEXT -> 1
            ACTION_GROUP -> 0
            else -> return super.onReceive(context, intent)
        }
        A3Prefs.init(context)
        if (!VpnState.info.value.isRunning) { updateAll(context); return }
        val pr = goAsync()
        A3Runtime.scope.launch {
            try {
                runCatching { refresh(delta) }
                push(context, ids(context))
            } finally {
                pr.finish()
            }
        }
    }
}
