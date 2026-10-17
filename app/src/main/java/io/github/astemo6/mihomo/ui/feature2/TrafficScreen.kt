package io.github.astemo6.mihomo.ui.feature2

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.RestartAlt
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.feature2.Bytes
import io.github.astemo6.mihomo.data.feature2.RateSample
import io.github.astemo6.mihomo.data.feature2.TrafficStats
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnState

/** 流量统计 (iOS StatsView + AnalyticsView): rate graph, this session per policy / host / rule, daily history. */
@Composable
fun TrafficScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val vpn by VpnState.info.collectAsState()
    val session by TrafficStats.session.collectAsState()
    val rate by TrafficStats.rate.collectAsState()
    val days by TrafficStats.days.collectAsState()
    val analytics by TrafficStats.analytics.collectAsState()
    var range by remember { mutableStateOf(7) }
    var confirmClear by remember { mutableStateOf(false) }
    val upColor = c.accent
    val downColor = c.good

    F2Page(stringResource(R.string.f2_traffic_title), onBack, actions = {
        IconButton(onClick = { TrafficStats.resetSession() }) { Icon(Icons.Default.RestartAlt, stringResource(R.string.f2_traffic_reset)) }
        IconButton(onClick = { confirmClear = true }) { Icon(Icons.Default.Delete, stringResource(R.string.f2_traffic_clear_history)) }
    }) {
        // ---- rate -----------------------------------------------------------------------------
        item { SectionTitle(stringResource(R.string.f2_traffic_rate)) }
        item {
            AppCard {
                val last = rate.lastOrNull()
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Dot(upColor); Text(" ↑ " + Fmt.speed(last?.up ?: 0), fontSize = 14.sp, color = c.text, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.width(16.dp))
                    Dot(downColor); Text(" ↓ " + Fmt.speed(last?.down ?: 0), fontSize = 14.sp, color = c.text, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.weight(1f))
                    Text(stringResource(R.string.f2_traffic_peak, Fmt.speed(rate.maxOfOrNull { maxOf(it.up, it.down) } ?: 0)), fontSize = 11.sp, color = c.secondary)
                }
                Spacer(Modifier.height(8.dp))
                RateGraph(rate, upColor, downColor, c.separator)
                if (!vpn.isRunning) Text(stringResource(R.string.f2_need_connect), fontSize = 12.sp, color = c.secondary)
            }
        }
        // ---- session --------------------------------------------------------------------------
        item { SectionTitle(stringResource(R.string.f2_traffic_session)) }
        item {
            AppCard {
                val total = session.policies.values.fold(Bytes()) { a, b -> a + b }
                Row {
                    Stat(stringResource(R.string.f2_traffic_upload), Fmt.bytes(total.up), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_download), Fmt.bytes(total.down), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_connections), "${session.activeConnections} / ${session.totalConnections}", Modifier.weight(1f))
                }
                Text(stringResource(R.string.f2_traffic_since, Fmt.dateTime(session.since)), fontSize = 11.sp, color = c.secondary)
                Text(stringResource(R.string.f2_traffic_session_note), fontSize = 11.sp, color = c.secondary)
            }
        }
        val pol = session.policies.entries.filter { it.value.total > 0 }.sortedByDescending { it.value.total }
        item { SectionTitle(stringResource(R.string.f2_traffic_by_policy)) }
        item {
            AppCard {
                if (pol.isEmpty()) Text(stringResource(R.string.f2_none), fontSize = 13.sp, color = c.secondary)
                val max = pol.firstOrNull()?.value?.total ?: 1
                pol.take(20).forEach { (k, v) -> UsageBar(k, v, max) }
            }
        }
        val hosts = session.hosts.entries.sortedByDescending { it.value.total }.take(15)
        item { SectionTitle(stringResource(R.string.f2_traffic_top_hosts)) }
        item {
            AppCard {
                if (hosts.isEmpty()) Text(stringResource(R.string.f2_none), fontSize = 13.sp, color = c.secondary)
                val max = hosts.firstOrNull()?.value?.total ?: 1
                hosts.forEach { (k, v) -> UsageBar(k, v, max) }
            }
        }
        val rules = session.rules.values.sortedByDescending { it.hits }.take(15)
        item { SectionTitle(stringResource(R.string.f2_traffic_top_rules)) }
        item {
            AppCard {
                if (rules.isEmpty()) Text(stringResource(R.string.f2_none), fontSize = 13.sp, color = c.secondary)
                rules.forEach { r ->
                    Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(r.rule, fontSize = 12.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(r.policy, fontSize = 11.sp, color = c.secondary, maxLines = 1)
                        }
                        Text(stringResource(R.string.f2_times_n, r.hits), fontSize = 12.sp, color = c.secondary)
                    }
                }
            }
        }
        // ---- history --------------------------------------------------------------------------
        item { SectionTitle(stringResource(R.string.f2_traffic_history)) }
        item {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                listOf(1, 7, 30).forEachIndexed { i, n ->
                    SegmentedButton(selected = range == n, onClick = { range = n }, shape = SegmentedButtonDefaults.itemShape(i, 3)) {
                        Text(if (n == 1) stringResource(R.string.f2_today) else stringResource(R.string.f2_last_days_n, n), fontSize = 12.sp)
                    }
                }
            }
        }
        item {
            val recent = remember(days, range) { TrafficStats.recentDays(range) }
            val sum = recent.fold(0L to 0L) { a, d -> (a.first + d.up) to (a.second + d.down) }
            val wifi = recent.sumOf { it.wifi ?: 0 }
            val cell = recent.sumOf { it.cell ?: 0 }
            AppCard {
                Row {
                    Stat(stringResource(R.string.f2_traffic_upload), Fmt.bytes(sum.first), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_download), Fmt.bytes(sum.second), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_total), Fmt.bytes(sum.first + sum.second), Modifier.weight(1f))
                }
                Row {
                    Stat("Wi-Fi", Fmt.bytes(wifi), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_cellular), Fmt.bytes(cell), Modifier.weight(1f))
                    Stat(stringResource(R.string.f2_traffic_other), Fmt.bytes((sum.first + sum.second - wifi - cell).coerceAtLeast(0)), Modifier.weight(1f))
                }
                if (range > 1) {
                    Spacer(Modifier.height(8.dp))
                    DayBars(recent.map { it.total }, c.accent)
                }
                Text(stringResource(R.string.f2_traffic_history_note), fontSize = 11.sp, color = c.secondary)
            }
        }
        item {
            val a = remember(analytics, range) { TrafficStats.analyticsSummary(range) }
            AppCard(Modifier.padding(top = 8.dp)) {
                Text(stringResource(R.string.f2_traffic_split), fontSize = 13.sp, color = c.text, fontWeight = FontWeight.SemiBold)
                val tot = (a.direct.total + a.proxy.total).coerceAtLeast(1)
                Row(Modifier.fillMaxWidth().padding(vertical = 6.dp).height(10.dp).clip(RoundedCornerShape(5.dp)).background(c.cardAlt)) {
                    if (a.direct.total > 0) Box(Modifier.weight(a.direct.total.toFloat()).fillMaxHeight().background(c.good))
                    if (a.proxy.total > 0) Box(Modifier.weight(a.proxy.total.toFloat()).fillMaxHeight().background(c.accent))
                }
                Row {
                    Dot(c.good); Text(" " + stringResource(R.string.f2_traffic_direct) + " " + Fmt.bytes(a.direct.total) + " (${a.direct.total * 100 / tot}%)", fontSize = 12.sp, color = c.text)
                    Spacer(Modifier.width(12.dp))
                    Dot(c.accent); Text(" " + stringResource(R.string.f2_traffic_proxy) + " " + Fmt.bytes(a.proxy.total) + " (${a.proxy.total * 100 / tot}%)", fontSize = 12.sp, color = c.text)
                }
                val top = a.policies.entries.sortedByDescending { it.value.total }.take(8)
                val max = top.firstOrNull()?.value?.total ?: 1
                top.forEach { (k, v) -> UsageBar(k, v, max) }
                Text(stringResource(R.string.f2_traffic_split_note), fontSize = 11.sp, color = c.secondary)
            }
        }
    }
    if (confirmClear) ConfirmDialog(stringResource(R.string.f2_traffic_clear_history), null, stringResource(R.string.f2_clear),
        onConfirm = { TrafficStats.clearHistory() }, onDismiss = { confirmClear = false })
}

@Composable
private fun Dot(color: Color) = Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(color))

@Composable
private fun Stat(title: String, value: String, modifier: Modifier = Modifier) {
    val c = LocalAppColors.current
    Column(modifier.padding(vertical = 4.dp)) {
        Text(title, fontSize = 11.sp, color = c.secondary)
        Text(value, fontSize = 15.sp, color = c.text, fontWeight = FontWeight.SemiBold, maxLines = 1)
    }
}

@Composable
private fun UsageBar(name: String, b: Bytes, max: Long) {
    val c = LocalAppColors.current
    Column(Modifier.padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(name, fontSize = 12.sp, color = c.text, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text("↑${Fmt.bytes(b.up)}  ↓${Fmt.bytes(b.down)}", fontSize = 11.sp, color = c.secondary)
        }
        Box(Modifier.fillMaxWidth().padding(top = 2.dp).height(4.dp).clip(RoundedCornerShape(2.dp)).background(c.cardAlt)) {
            Box(Modifier.fillMaxWidth((b.total.toFloat() / max.coerceAtLeast(1)).coerceIn(0.02f, 1f)).fillMaxHeight().background(c.accent))
        }
    }
}

@Composable
private fun RateGraph(samples: List<RateSample>, up: Color, down: Color, grid: Color) {
    Canvas(Modifier.fillMaxWidth().height(110.dp)) {
        val w = size.width; val h = size.height
        for (i in 1..3) drawLine(grid, Offset(0f, h * i / 4), Offset(w, h * i / 4), 1f)
        if (samples.size < 2) return@Canvas
        val max = samples.maxOf { maxOf(it.up, it.down) }.coerceAtLeast(1024).toFloat()
        val n = 180
        val step = w / (n - 1)
        val off = n - samples.size
        fun path(sel: (RateSample) -> Long): Path = Path().apply {
            samples.forEachIndexed { i, s ->
                val x = (off + i) * step
                val y = h - (sel(s) / max) * h * 0.95f
                if (i == 0) moveTo(x, y) else lineTo(x, y)
            }
        }
        drawPath(path { it.down }, down, style = Stroke(width = 2.dp.toPx()))
        drawPath(path { it.up }, up, style = Stroke(width = 2.dp.toPx()))
    }
}

@Composable
private fun DayBars(values: List<Long>, color: Color) {
    Canvas(Modifier.fillMaxWidth().height(70.dp)) {
        if (values.isEmpty()) return@Canvas
        val max = values.max().coerceAtLeast(1).toFloat()
        val slot = size.width / values.size
        values.forEachIndexed { i, v ->
            val bh = (v / max) * size.height
            drawRect(color, topLeft = Offset(i * slot + slot * 0.15f, size.height - bh),
                size = androidx.compose.ui.geometry.Size(slot * 0.7f, bh.coerceAtLeast(if (v > 0) 2f else 0f)))
        }
    }
}
