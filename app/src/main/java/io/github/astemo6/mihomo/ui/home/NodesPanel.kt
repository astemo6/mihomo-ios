package io.github.astemo6.mihomo.ui.home

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ProxyTypes
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.GroupCard
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.ResourceCard
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.GroupIcon
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.components.delayColor
import io.github.astemo6.mihomo.ui.components.delayText
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.ui.theme.PanelColors

data class NodesData(
    val groups: List<GroupCard>,
    val resource: ResourceCard,
    val delays: Map<String, Int>,
    val testing: Set<String>,
    val nodeTypes: Map<String, String>,
    val mode: String,
    val running: Boolean,
    val expanded: Set<String>,
)

private const val RESOURCE_KEY = "__resource__"

fun LazyListScope.nodesPanel(vm: MainViewModel, d: NodesData, query: String, toggle: (String) -> Unit) {
    item(key = "mode") { ModeRow(d.mode) { vm.setMode(it) } }
    item(key = "resource") {
        ResourceCardView(d, query, expanded = RESOURCE_KEY in d.expanded, onToggle = { toggle(RESOURCE_KEY) },
            onTestAll = { vm.testNodes(d.resource.nodes, RESOURCE_KEY) }, onTestNode = { vm.testNode(it) })
    }
    val groups = if (query.isEmpty()) d.groups
    else d.groups.filter { g -> g.name.contains(query, true) || g.members.any { it.contains(query, true) } }
    if (groups.isEmpty() && d.resource.profile == null) {
        item(key = "empty") { EmptyHint(stringResource(R.string.no_profile_hint)) }
    }
    items(groups, key = { "g:" + it.name }) { g ->
        GroupCardView(g, d, query, expanded = g.name in d.expanded, onToggle = { toggle(g.name) },
            onTest = { vm.testGroup(g) }, onSelect = { vm.select(g, it) }, onTestNode = { vm.testNode(it) })
    }
}

@Composable
private fun ModeRow(mode: String, onMode: (String) -> Unit) {
    val c = LocalAppColors.current
    AppCard(padding = PaddingValues(4.dp)) {
        Row(Modifier.fillMaxWidth()) {
            listOf("rule" to R.string.mode_rule, "global" to R.string.mode_global, "direct" to R.string.mode_direct).forEach { (m, label) ->
                val sel = mode == m || (mode.isEmpty() && m == "rule")
                Box(
                    Modifier.weight(1f).clip(RoundedCornerShape(10.dp))
                        .background(if (sel) c.accent else Color.Transparent)
                        .clickable { onMode(m) }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(stringResource(label), color = if (sel) Color.White else c.text, fontSize = 14.sp,
                        fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal)
                }
            }
        }
    }
}

@Composable
private fun groupTypeLabel(type: String): String = when (type.lowercase()) {
    "selector", "select" -> stringResource(R.string.gt_select)
    "urltest", "url-test" -> stringResource(R.string.gt_urltest)
    "fallback" -> stringResource(R.string.gt_fallback)
    "loadbalance", "load-balance" -> stringResource(R.string.gt_loadbalance)
    "relay" -> stringResource(R.string.gt_relay)
    "smart" -> stringResource(R.string.gt_smart)
    else -> type
}

@Composable
private fun Avatar(name: String, color: Color) {
    val letter = name.trim().firstOrNull { it.isLetterOrDigit() }?.uppercase() ?: name.take(2)
    Box(Modifier.size(34.dp).clip(RoundedCornerShape(9.dp)).background(color.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
        Text(letter, color = color, fontWeight = FontWeight.Bold, fontSize = 15.sp)
    }
}

@Composable
private fun TestButton(testing: Boolean, onClick: () -> Unit) {
    val c = LocalAppColors.current
    IconButton(onClick = onClick, enabled = !testing, modifier = Modifier.size(36.dp)) {
        if (testing) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
        else Icon(Icons.Filled.Bolt, stringResource(R.string.test_latency), tint = c.warn)
    }
}

@Composable
private fun ResourceCardView(d: NodesData, query: String, expanded: Boolean, onToggle: () -> Unit, onTestAll: () -> Unit, onTestNode: (String) -> Unit) {
    val c = LocalAppColors.current
    val p = d.resource.profile
    AppCard {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable(onClick = onToggle)) {
            Avatar("P", PanelColors.nodes)
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("PROXY", fontWeight = FontWeight.Bold, fontSize = 15.sp, color = c.text)
                    Spacer(Modifier.width(6.dp))
                    Tag(stringResource(R.string.node_count, d.resource.nodes.size), PanelColors.nodes)
                }
                Text(p?.name ?: stringResource(R.string.no_profile_short), fontSize = 12.sp, color = c.secondary,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            TestButton(RESOURCE_KEY in d.testing, onTestAll)
            Icon(if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown, null, tint = c.secondary)
        }
        p?.userInfo?.let { info ->
            Spacer(Modifier.height(10.dp))
            if (info.total > 0) {
                LinearProgressIndicator(progress = { info.fraction }, modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
                    color = if (info.fraction > 0.9f) c.bad else c.accent, trackColor = c.separator)
                Spacer(Modifier.height(4.dp))
            }
            Row {
                Text(stringResource(R.string.sub_used, Fmt.bytes(info.used), if (info.total > 0) Fmt.bytes(info.total) else "∞"),
                    fontSize = 12.sp, color = c.secondary, modifier = Modifier.weight(1f))
                if (info.expire > 0) Text(stringResource(R.string.sub_expire, Fmt.date(info.expire * 1000)), fontSize = 12.sp, color = c.secondary)
            }
        }
        if (expanded) {
            Spacer(Modifier.height(8.dp))
            val nodes = if (query.isEmpty()) d.resource.nodes else d.resource.nodes.filter { it.contains(query, true) }
            NodeGrid(nodes, selected = null, d = d, onClick = null, onLong = onTestNode)
        }
    }
}

@Composable
private fun GroupCardView(
    g: GroupCard, d: NodesData, query: String, expanded: Boolean,
    onToggle: () -> Unit, onTest: () -> Unit, onSelect: (String) -> Unit, onTestNode: (String) -> Unit,
) {
    val c = LocalAppColors.current
    val leaf = g.chain.lastOrNull()
    AppCard {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable(onClick = onToggle)) {
            Box(Modifier.size(34.dp), contentAlignment = Alignment.Center) {
                GroupIcon(g.icon, 30.dp) { Avatar(g.name, PanelColors.rules) }
            }
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(g.name, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = c.text,
                        maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    Spacer(Modifier.width(6.dp))
                    Tag(groupTypeLabel(g.type), c.secondary)
                    if (g.fixed != null) {
                        Spacer(Modifier.width(4.dp))
                        Tag(stringResource(R.string.pinned), c.warn)
                    }
                }
                // Resolved policy chain: Group ➤ Sub-group ➤ Node
                Text(g.chain.drop(1).joinToString(" ➤ ").ifEmpty { "—" }, fontSize = 12.sp, color = c.secondary,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            val ms = leaf?.let { d.delays[it] }
            if (ms != null) Text(delayText(ms), color = delayColor(ms), fontSize = 12.sp, modifier = Modifier.padding(horizontal = 4.dp))
            TestButton(g.name in d.testing, onTest)
            Icon(if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown, null, tint = c.secondary)
        }
        if (expanded) {
            Spacer(Modifier.height(8.dp))
            val members = if (query.isEmpty()) g.members else g.members.filter { it.contains(query, true) }
            val canSelect = g.selectable || (d.running && g.type.lowercase() in setOf("urltest", "fallback"))
            NodeGrid(members, selected = g.now, d = d, onClick = if (canSelect) onSelect else null, onLong = onTestNode)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class, ExperimentalFoundationApi::class)
@Composable
private fun NodeGrid(nodes: List<String>, selected: String?, d: NodesData, onClick: ((String) -> Unit)?, onLong: (String) -> Unit) {
    val c = LocalAppColors.current
    if (nodes.isEmpty()) {
        Text(stringResource(R.string.no_nodes), fontSize = 13.sp, color = c.secondary)
        return
    }
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        maxItemsInEachRow = 2,
    ) {
        nodes.forEach { n ->
            val sel = n == selected
            val ms = d.delays[n]
            Column(
                Modifier.weight(1f)
                    .clip(RoundedCornerShape(10.dp))
                    .background(if (sel) c.accent.copy(alpha = 0.12f) else c.cardAlt)
                    .border(1.dp, if (sel) c.accent else Color.Transparent, RoundedCornerShape(10.dp))
                    .combinedClickable(onClick = { onClick?.invoke(n) }, onLongClick = { onLong(n) })
                    .padding(horizontal = 10.dp, vertical = 8.dp),
            ) {
                Text(n, fontSize = 13.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val t = d.nodeTypes[n]?.let { ProxyTypes.short(it) }.orEmpty()
                    Text(t, fontSize = 11.sp, color = c.secondary, modifier = Modifier.weight(1f), maxLines = 1)
                    if ("node:$n" in d.testing) CircularProgressIndicator(Modifier.size(10.dp), strokeWidth = 1.5.dp)
                    else Text(delayText(ms), fontSize = 11.sp, color = delayColor(ms))
                }
            }
        }
        if (nodes.size % 2 == 1) Spacer(Modifier.weight(1f))
    }
}
