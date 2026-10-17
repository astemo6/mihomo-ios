package io.github.astemo6.mihomo.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ConnectionItem
import io.github.astemo6.mihomo.api.LogLine
import io.github.astemo6.mihomo.api.RuleItem
import io.github.astemo6.mihomo.data.RewriteEntry
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.ui.theme.PanelColors

// ---- 网络活动 -----------------------------------------------------------------------------------

fun LazyListScope.activityPanel(
    vm: MainViewModel,
    connections: List<ConnectionItem>,
    totals: Pair<Long, Long>,
    speed: Pair<Long, Long>,
    running: Boolean,
    query: String,
) {
    item(key = "act-summary") {
        val c = LocalAppColors.current
        val tcp = connections.count { it.metadata.network.equals("tcp", true) }
        val udp = connections.count { it.metadata.network.equals("udp", true) }
        AppCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Counter("TCP", tcp, PanelColors.nodes)
                Spacer(Modifier.width(16.dp))
                Counter("UDP", udp, PanelColors.activity)
                Spacer(Modifier.weight(1f))
                Column(horizontalAlignment = Alignment.End) {
                    Text("↑ ${Fmt.speed(speed.first)}  ↓ ${Fmt.speed(speed.second)}", fontSize = 12.sp, color = c.text)
                    Text("Σ ↑ ${Fmt.bytes(totals.first)}  ↓ ${Fmt.bytes(totals.second)}", fontSize = 11.sp, color = c.secondary)
                }
            }
            if (connections.isNotEmpty()) {
                TextButton(onClick = { vm.closeAllConnections() }, contentPadding = PaddingValues(0.dp)) {
                    Text(stringResource(R.string.close_all), color = c.bad, fontSize = 13.sp)
                }
            }
        }
    }
    val list = if (query.isEmpty()) connections else connections.filter {
        it.metadata.displayHost.contains(query, true) || it.chainText.contains(query, true) || it.ruleText.contains(query, true) ||
            (it.metadata.process ?: "").contains(query, true)
    }
    if (!running) item(key = "act-off") { EmptyHint(stringResource(R.string.need_running)) }
    else if (list.isEmpty()) item(key = "act-empty") { EmptyHint(stringResource(R.string.no_connections)) }
    items(list, key = { "c:" + it.id }) { conn -> ConnectionRow(conn) { vm.closeConnection(conn.id) } }
}

@Composable
private fun Counter(label: String, n: Int, color: Color) {
    val c = LocalAppColors.current
    Column {
        Text(n.toString(), fontSize = 20.sp, fontWeight = FontWeight.Bold, color = color)
        Text(label, fontSize = 11.sp, color = c.secondary)
    }
}

@Composable
private fun ConnectionRow(conn: ConnectionItem, onClose: () -> Unit) {
    val c = LocalAppColors.current
    AppCard(padding = PaddingValues(horizontal = 12.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tag((conn.metadata.network ?: "?").uppercase(), if (conn.metadata.network == "udp") PanelColors.activity else PanelColors.nodes)
                    Spacer(Modifier.width(6.dp))
                    Text(conn.metadata.displayHost, fontSize = 14.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.height(4.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (conn.ruleText.isNotEmpty()) {
                        Tag(conn.ruleText, PanelColors.rules, Modifier.weight(1f, fill = false))
                        Spacer(Modifier.width(6.dp))
                    }
                    Text(conn.chainText, fontSize = 12.sp, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text("↑ ${Fmt.bytes(conn.upload)}  ↓ ${Fmt.bytes(conn.download)}" +
                    (conn.metadata.process?.takeIf { it.isNotEmpty() }?.let { "  ·  $it" } ?: ""),
                    fontSize = 11.sp, color = c.secondary, maxLines = 1)
            }
            IconButton(onClick = onClose, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Filled.Close, stringResource(R.string.close_connection), tint = c.secondary, modifier = Modifier.size(18.dp))
            }
        }
    }
}

// ---- 分流规则 -----------------------------------------------------------------------------------

private fun ruleColor(type: String): Color = when {
    type.startsWith("DOMAIN", true) -> PanelColors.nodes
    type.startsWith("IP", true) || type.startsWith("SRC-IP", true) -> PanelColors.activity
    type.startsWith("GEO", true) -> PanelColors.rewrite
    type.equals("RULE-SET", true) -> PanelColors.rules
    type.equals("MATCH", true) || type.equals("FINAL", true) -> Color(0xFF8E8E93)
    else -> PanelColors.logs
}

fun LazyListScope.rulesPanel(rules: List<RuleItem>, query: String) {
    val list = if (query.isEmpty()) rules else rules.filter {
        it.payload.contains(query, true) || it.proxy.contains(query, true) || it.type.contains(query, true)
    }
    item(key = "rules-head") {
        val c = LocalAppColors.current
        Text(stringResource(R.string.rules_count, list.size), fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(start = 6.dp))
    }
    if (list.isEmpty()) item(key = "rules-empty") { EmptyHint(stringResource(R.string.no_rules)) }
    itemsIndexed(list, key = { i, _ -> "r:$i" }) { _, r ->
        val c = LocalAppColors.current
        AppCard(padding = PaddingValues(horizontal = 12.dp, vertical = 9.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tag(r.type, ruleColor(r.type))
                Spacer(Modifier.width(8.dp))
                Text(r.payload.ifEmpty { "—" }, fontSize = 13.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f))
                Spacer(Modifier.width(8.dp))
                Tag(r.proxy, c.accent)
            }
            r.size?.takeIf { it > 0 }?.let { Text(stringResource(R.string.rule_size, it), fontSize = 11.sp, color = c.secondary) }
        }
    }
}

// ---- 重写规则 -------------------------------------------------------------------------------------

private fun rewriteKindColor(kind: String): Color = when (kind) {
    "script" -> Color(0xFFAF52DE)
    "url" -> Color(0xFFFF3B30)
    "header" -> Color(0xFFFF9500)
    "body", "jq", "json" -> Color(0xFF34C759)
    "maplocal" -> Color(0xFF2F7BF6)
    else -> Color(0xFF5AC8FA)
}

/** Rewrite rules of the user lines and every module (parsed by the Go engine), off ones dimmed. */
fun LazyListScope.rewritePanel(entries: List<RewriteEntry>, engineOn: Boolean, query: String, onManage: () -> Unit) {
    val list = if (query.isEmpty()) entries else entries.filter {
        it.rule.pattern.contains(query, true) || it.rule.desc.contains(query, true) || it.source.contains(query, true) || it.rule.kind.contains(query, true)
    }
    item(key = "rw-head") {
        val c = LocalAppColors.current
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.rules_count, list.size) + if (!engineOn) " · " + stringResource(R.string.rewrite_off) else "",
                fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(start = 6.dp).weight(1f))
            TextButton(onClick = onManage) { Text(stringResource(R.string.manage)) }
        }
    }
    if (list.isEmpty()) item(key = "rw-empty") { EmptyHint(stringResource(R.string.rewrite_empty)) }
    itemsIndexed(list, key = { i, _ -> "rw:$i" }) { _, e ->
        val c = LocalAppColors.current
        val alpha = if (e.enabled) 1f else 0.45f
        AppCard(padding = PaddingValues(horizontal = 12.dp, vertical = 9.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tag(e.rule.kind.ifEmpty { "?" }, rewriteKindColor(e.rule.kind).copy(alpha = alpha))
                if (e.rule.phase.isNotEmpty()) {
                    Spacer(Modifier.width(4.dp))
                    Tag(e.rule.phase, c.secondary.copy(alpha = alpha))
                }
                Spacer(Modifier.width(8.dp))
                Text(e.rule.pattern.ifEmpty { e.rule.line }, fontSize = 13.sp, color = c.text.copy(alpha = alpha), maxLines = 1,
                    overflow = TextOverflow.Ellipsis, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
            }
            val sub = listOf(e.rule.desc, e.source).filter { it.isNotEmpty() }.joinToString(" · ")
            if (sub.isNotEmpty()) Text(sub, fontSize = 11.sp, color = c.secondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

// ---- 日志 ---------------------------------------------------------------------------------------

private fun levelColor(level: String): Color = when (level.lowercase()) {
    "error" -> Color(0xFFFF3B30)
    "warning", "warn" -> Color(0xFFFF9500)
    "debug" -> Color(0xFF8E8E93)
    else -> Color(0xFF34C759)
}

fun LazyListScope.logsPanel(vm: MainViewModel, logs: List<LogLine>, level: String, paused: Boolean, running: Boolean, query: String) {
    item(key = "logs-head") {
        val c = LocalAppColors.current
        AppCard(padding = PaddingValues(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Row(Modifier.weight(1f).horizontalScroll(rememberScrollState())) {
                    listOf("debug", "info", "warning", "error").forEach { l ->
                        val sel = l == level
                        Box(
                            Modifier.padding(2.dp).clip(RoundedCornerShape(8.dp))
                                .background(if (sel) levelColor(l) else Color.Transparent)
                                .clickable { vm.setLogLevel(l) }
                                .padding(horizontal = 10.dp, vertical = 6.dp),
                        ) { Text(l.uppercase(), fontSize = 12.sp, color = if (sel) Color.White else c.text, fontWeight = FontWeight.Medium) }
                    }
                }
                IconButton(onClick = { vm.toggleLogsPaused() }) {
                    Icon(if (paused) Icons.Filled.PlayArrow else Icons.Filled.Pause, stringResource(R.string.pause), tint = c.text)
                }
                IconButton(onClick = { vm.clearLogs() }) {
                    Icon(Icons.Filled.DeleteSweep, stringResource(R.string.clear), tint = c.text)
                }
            }
        }
    }
    val list = if (query.isEmpty()) logs else logs.filter { it.message.contains(query, true) }
    if (!running) item(key = "logs-off") { EmptyHint(stringResource(R.string.need_running)) }
    else if (list.isEmpty()) item(key = "logs-empty") { EmptyHint(stringResource(R.string.no_logs)) }
    items(list, key = { "l:" + it.id }) { line ->
        val c = LocalAppColors.current
        Column(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(c.card).padding(horizontal = 10.dp, vertical = 6.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tag(line.level.uppercase(), levelColor(line.level))
                Spacer(Modifier.width(6.dp))
                Text(Fmt.time(line.time), fontSize = 11.sp, color = c.secondary, fontFamily = FontFamily.Monospace)
            }
            Text(line.message, fontSize = 12.sp, color = c.text, fontFamily = FontFamily.Monospace)
        }
    }
}
