package io.github.astemo6.mihomo.ui.home

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.filled.Toys
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.Panel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.ui.theme.PanelColors
import io.github.astemo6.mihomo.vpn.VpnStatus
import kotlinx.coroutines.delay
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.runtime.produceState
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.RewriteEntry
import io.github.astemo6.mihomo.data.ToolbarItem
import io.github.astemo6.mihomo.data.UiLayout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    vm: MainViewModel,
    onToggle: (Boolean) -> Unit,
    onOpenSettings: () -> Unit,
    onAdd: () -> Unit,
    onOpenProfiles: () -> Unit,
    onOpenDns: () -> Unit,
    onOpenLayout: () -> Unit,
    onOpenRewrite: () -> Unit,
) {
    val c = LocalAppColors.current
    val panel by vm.panel.collectAsState()
    val panelOrder by UiLayout.panelOrder.collectAsState()
    val hiddenPanels by UiLayout.hiddenPanels.collectAsState()
    val visiblePanels = remember(panelOrder, hiddenPanels) {
        UiLayout.orderedPanels(Panel.entries.toList()) { it.name }.filter { it.name !in hiddenPanels }.ifEmpty { listOf(Panel.NODES) }
    }
    val shownPanel = if (panel in visiblePanels) panel else visiblePanels.first()
    val engineCfg by EngineStore.config.collectAsState()
    val moduleInfo by EngineStore.moduleInfo.collectAsState()
    val rewrite by produceState(emptyList<RewriteEntry>(), engineCfg, moduleInfo) {
        value = withContext(Dispatchers.IO) { runCatching { EngineStore.rewriteEntries() }.getOrDefault(emptyList()) }
    }
    var searching by rememberSaveable { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    var showModeSheet by remember { mutableStateOf(false) }
    var showStats by remember { mutableStateOf(false) }
    val listState = rememberLazyListState()
    val groups by vm.groups.collectAsState()
    val resource by vm.resource.collectAsState()
    val delays by vm.delays.collectAsState()
    val testing by vm.testing.collectAsState()
    val nodeTypes by vm.nodeTypes.collectAsState()
    val running by vm.running.collectAsState()
    val connections by vm.connections.collectAsState()
    val totals by vm.totals.collectAsState()
    val speed by vm.speed.collectAsState()
    val rules by vm.rules.collectAsState()
    val logs by vm.logs.collectAsState()
    val logLevel by vm.logLevel.collectAsState()
    val logsPaused by vm.logsPaused.collectAsState()
    val mode by vm.mode.collectAsState()
    var expanded by remember { mutableStateOf(setOf<String>()) }
    val toggleExpanded: (String) -> Unit = { k -> expanded = if (k in expanded) expanded - k else expanded + k }

    Box(Modifier.fillMaxSize().background(c.bg)) {
        LazyColumn(
            state = listState,
            modifier = Modifier.fillMaxSize().statusBarsPadding(),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 120.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            item(key = "header") { Header(vm, onToggle, onOpenProfiles) }
            item(key = "strip") { PanelStrip(visiblePanels, shownPanel) { vm.setPanel(it) } }
            val q = if (searching) query.trim() else ""
            when (shownPanel) {
                Panel.NODES -> nodesPanel(vm, NodesData(groups, resource, delays, testing, nodeTypes, mode, running, expanded), q, toggleExpanded)
                Panel.ACTIVITY -> activityPanel(vm, connections, totals, speed, running, q)
                Panel.RULES -> rulesPanel(rules, q)
                Panel.REWRITE -> rewritePanel(rewrite, engineCfg.enabled, q, onOpenRewrite)
                Panel.LOGS -> logsPanel(vm, logs, logLevel, logsPaused, running, q)
            }
        }

        FloatingToolbar(
            modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().imePadding().padding(bottom = 14.dp),
            searching = searching,
            query = query,
            onQuery = { query = it },
            onCloseSearch = { searching = false; query = "" },
            onAction = { item ->
                when (item) {
                    ToolbarItem.SEARCH -> searching = true
                    ToolbarItem.ADD -> onAdd()
                    ToolbarItem.STATS -> showStats = true
                    ToolbarItem.DNS -> onOpenDns()
                    ToolbarItem.REQUESTS -> vm.setPanel(Panel.ACTIVITY)
                }
            },
            onWindmill = onOpenSettings,
            onWindmillLong = { showModeSheet = true },
            onOpenLayout = onOpenLayout,
        )
    }

    if (showModeSheet) {
        ModalBottomSheet(onDismissRequest = { showModeSheet = false }, containerColor = c.bg) {
            ModeSheet(vm) { showModeSheet = false }
        }
    }
    if (showStats) StatsDialog(vm) { showStats = false }
}

// ---- header -----------------------------------------------------------------------------------

@Composable
private fun Header(vm: MainViewModel, onToggle: (Boolean) -> Unit, onOpenProfiles: () -> Unit) {
    val c = LocalAppColors.current
    val vpn by vm.vpn.collectAsState()
    val ip by vm.ip.collectAsState()
    val loading by vm.ipLoading.collectAsState()
    val profiles by vm.profiles.collectAsState()
    val activeId by vm.activeId.collectAsState()
    val profile = profiles.firstOrNull { it.id == activeId }
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(vpn.status) {
        while (vpn.status == VpnStatus.RUNNING) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }
    Column(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f).clickable { vm.refreshIp() }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(ip?.flag ?: "🌐", fontSize = 28.sp)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        ip?.locationText?.ifEmpty { null } ?: stringResource(if (loading) R.string.ip_loading else R.string.ip_unknown),
                        fontSize = 22.sp, fontWeight = FontWeight.Bold, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    )
                }
                val asn = ip?.asnText.orEmpty()
                if (asn.isNotEmpty()) Text(asn, fontSize = 13.sp, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(ip?.ip ?: "—", fontSize = 13.sp, color = c.secondary, fontFamily = FontFamily.Monospace)
            }
            Switch(
                checked = vpn.status == VpnStatus.RUNNING || vpn.status == VpnStatus.CONNECTING,
                onCheckedChange = { onToggle(it) },
                enabled = !vpn.isBusy || vpn.status == VpnStatus.CONNECTING,
                colors = SwitchDefaults.colors(checkedTrackColor = c.good),
            )
        }
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(7.dp).clip(CircleShape).background(if (vpn.isRunning) c.good else c.secondary.copy(alpha = 0.6f)))
            Spacer(Modifier.width(6.dp))
            val status = when (vpn.status) {
                VpnStatus.RUNNING -> stringResource(R.string.status_running_for, Fmt.duration(now - (vpn.since ?: now)))
                VpnStatus.CONNECTING -> stringResource(R.string.status_connecting)
                VpnStatus.STOPPING -> stringResource(R.string.status_stopping)
                VpnStatus.STOPPED -> stringResource(R.string.status_off)
            }
            Text(status, fontSize = 12.sp, color = c.secondary)
            Spacer(Modifier.weight(1f))
            Text(
                profile?.name ?: stringResource(R.string.no_profile_short),
                fontSize = 12.sp, color = c.accent, maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.clickable(onClick = onOpenProfiles).padding(4.dp),
            )
        }
        vpn.error?.let { err ->
            Spacer(Modifier.height(8.dp))
            AppCard {
                Row(verticalAlignment = Alignment.Top) {
                    Text(err, color = c.bad, fontSize = 13.sp, modifier = Modifier.weight(1f))
                    IconButton(onClick = { vm.clearVpnError() }, modifier = Modifier.size(24.dp)) {
                        Icon(Icons.Filled.Close, null, tint = c.secondary, modifier = Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

// ---- panel strip ------------------------------------------------------------------------------

data class PanelSpec(val panel: Panel, val label: Int, val icon: ImageVector, val color: Color)

fun panelSpec(p: Panel): PanelSpec = when (p) {
    Panel.NODES -> PanelSpec(p, R.string.panel_nodes, Icons.Filled.Public, PanelColors.nodes)
    Panel.ACTIVITY -> PanelSpec(p, R.string.panel_activity, Icons.Filled.Timeline, PanelColors.activity)
    Panel.RULES -> PanelSpec(p, R.string.panel_rules, Icons.AutoMirrored.Filled.AltRoute, PanelColors.rules)
    Panel.REWRITE -> PanelSpec(p, R.string.panel_rewrite, Icons.Filled.AutoFixHigh, PanelColors.rewrite)
    Panel.LOGS -> PanelSpec(p, R.string.panel_logs, Icons.Filled.Description, PanelColors.logs)
}

data class ToolbarSpec(val item: ToolbarItem, val label: Int, val icon: ImageVector)

fun toolbarSpec(t: ToolbarItem): ToolbarSpec = when (t) {
    ToolbarItem.SEARCH -> ToolbarSpec(t, R.string.tb_search, Icons.Filled.Search)
    ToolbarItem.ADD -> ToolbarSpec(t, R.string.tb_add, Icons.Filled.Add)
    ToolbarItem.STATS -> ToolbarSpec(t, R.string.tb_stats, Icons.Filled.BarChart)
    ToolbarItem.DNS -> ToolbarSpec(t, R.string.dns, Icons.Filled.Dns)
    ToolbarItem.REQUESTS -> ToolbarSpec(t, R.string.tb_requests, Icons.Filled.SwapVert)
}

@Composable
private fun PanelStrip(panels: List<Panel>, selected: Panel, onSelect: (Panel) -> Unit) {
    val c = LocalAppColors.current
    AppCard(padding = PaddingValues(horizontal = 6.dp, vertical = 10.dp)) {
        Row(Modifier.fillMaxWidth()) {
            panels.map { panelSpec(it) }.forEach { s ->
                val sel = s.panel == selected
                Column(
                    Modifier.weight(1f).clip(RoundedCornerShape(10.dp)).clickable { onSelect(s.panel) }.padding(vertical = 4.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Box(
                        Modifier.size(40.dp).clip(RoundedCornerShape(11.dp)).background(if (sel) s.color else s.color.copy(alpha = 0.85f)),
                        contentAlignment = Alignment.Center,
                    ) { Icon(s.icon, null, tint = Color.White, modifier = Modifier.size(22.dp)) }
                    Spacer(Modifier.height(5.dp))
                    Text(stringResource(s.label), fontSize = 11.sp, color = if (sel) c.text else c.secondary,
                        fontWeight = if (sel) FontWeight.SemiBold else FontWeight.Normal, maxLines = 1)
                    Spacer(Modifier.height(4.dp))
                    Box(Modifier.width(18.dp).height(3.dp).clip(RoundedCornerShape(2.dp))
                        .background(if (sel) s.color else Color.Transparent))
                }
            }
        }
    }
}

// ---- floating toolbar -------------------------------------------------------------------------

/**
 * QX floating toolbar. Three states:
 *  - normal: the visible buttons in the user's order + the windmill (tap = settings, long = run mode);
 *  - search: the capsule turns into a search field that filters the current panel;
 *  - edit (long-press any button): every button is shown (hidden ones dimmed); tap one to pick it, then
 *    move it left / right or hide / show it from the bar above; ✓ leaves edit mode. The same settings are
 *    in 设置 › 面板 & 工具栏 (also linked from the edit bar).
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FloatingToolbar(
    modifier: Modifier,
    searching: Boolean,
    query: String,
    onQuery: (String) -> Unit,
    onCloseSearch: () -> Unit,
    onAction: (ToolbarItem) -> Unit,
    onWindmill: () -> Unit,
    onWindmillLong: () -> Unit,
    onOpenLayout: () -> Unit,
) {
    val c = LocalAppColors.current
    val order by UiLayout.toolbarOrder.collectAsState()
    val hidden by UiLayout.hiddenToolbar.collectAsState()
    var editing by rememberSaveable { mutableStateOf(false) }
    var picked by remember { mutableStateOf<ToolbarItem?>(null) }
    val focus = remember { FocusRequester() }

    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        if (editing) {
            Surface(Modifier.padding(bottom = 8.dp).shadow(6.dp, RoundedCornerShape(16.dp)), shape = RoundedCornerShape(16.dp), color = c.card) {
                Row(Modifier.padding(horizontal = 6.dp, vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    val p = picked
                    if (p == null) {
                        Text(stringResource(R.string.tb_edit_hint), fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(horizontal = 8.dp))
                    } else {
                        IconButton(onClick = { UiLayout.moveToolbar(p, -1) }, enabled = order.indexOf(p) > 0) {
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowLeft, stringResource(R.string.move_up))
                        }
                        TextButton(onClick = { UiLayout.setToolbarHidden(p, p !in hidden) }) {
                            Text(stringResource(if (p in hidden) R.string.show else R.string.hide))
                        }
                        IconButton(onClick = { UiLayout.moveToolbar(p, 1) }, enabled = order.indexOf(p) < order.lastIndex) {
                            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, stringResource(R.string.move_down))
                        }
                    }
                    TextButton(onClick = { editing = false; picked = null; onOpenLayout() }) {
                        Text(stringResource(R.string.more), fontSize = 13.sp)
                    }
                }
            }
        }
        Surface(
            modifier = Modifier.shadow(10.dp, RoundedCornerShape(26.dp)),
            shape = RoundedCornerShape(26.dp),
            color = c.card,
        ) {
            if (searching) {
                LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }
                Row(Modifier.padding(start = 14.dp, end = 4.dp, top = 2.dp, bottom = 2.dp).width(300.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Search, null, tint = c.secondary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(8.dp))
                    Box(Modifier.weight(1f), contentAlignment = Alignment.CenterStart) {
                        if (query.isEmpty()) Text(stringResource(R.string.search), color = c.secondary, fontSize = 15.sp)
                        BasicTextField(
                            value = query, onValueChange = onQuery, singleLine = true,
                            textStyle = TextStyle(color = c.text, fontSize = 15.sp),
                            cursorBrush = SolidColor(c.accent),
                            modifier = Modifier.fillMaxWidth().focusRequester(focus),
                        )
                    }
                    IconButton(onClick = onCloseSearch, modifier = Modifier.size(44.dp)) {
                        Icon(Icons.Filled.Close, stringResource(R.string.cancel), tint = c.text)
                    }
                }
            } else {
                Row(Modifier.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                    val items = if (editing) order else order.filter { it !in hidden }
                    items.forEach { t ->
                        val spec = toolbarSpec(t)
                        val isHidden = t in hidden
                        val sel = editing && picked == t
                        Box(
                            Modifier.size(44.dp).clip(CircleShape)
                                .background(if (sel) c.accent.copy(alpha = 0.18f) else Color.Transparent)
                                .combinedClickable(
                                    onClick = { if (editing) picked = t else onAction(t) },
                                    onLongClick = { editing = true; picked = t },
                                ),
                            contentAlignment = Alignment.Center,
                        ) {
                            Icon(spec.icon, stringResource(spec.label),
                                tint = if (editing && isHidden) c.secondary.copy(alpha = 0.4f) else c.text)
                        }
                    }
                    if (editing) {
                        IconButton(onClick = { editing = false; picked = null }, modifier = Modifier.size(44.dp)) {
                            Icon(Icons.Filled.Check, stringResource(R.string.done), tint = c.accent)
                        }
                    } else {
                        Box(
                            Modifier.size(44.dp).clip(CircleShape)
                                .combinedClickable(onClick = onWindmill, onLongClick = onWindmillLong),
                            contentAlignment = Alignment.Center,
                        ) { Icon(Icons.Filled.Toys, stringResource(R.string.settings), tint = c.accent) }
                    }
                }
            }
        }
    }
}

// ---- mode sheet / stats -----------------------------------------------------------------------

@Composable
fun ModeSheet(vm: MainViewModel, onDone: () -> Unit) {
    val c = LocalAppColors.current
    val mode by vm.mode.collectAsState()
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 24.dp)) {
        Text(stringResource(R.string.run_mode), fontSize = 17.sp, fontWeight = FontWeight.SemiBold, color = c.text,
            modifier = Modifier.padding(bottom = 12.dp))
        AppCard(padding = PaddingValues(0.dp)) {
            listOf(
                Triple("rule", R.string.mode_rule, R.string.mode_rule_desc),
                Triple("global", R.string.mode_global, R.string.mode_global_desc),
                Triple("direct", R.string.mode_direct, R.string.mode_direct_desc),
            ).forEach { (m, title, desc) ->
                Row(
                    Modifier.fillMaxWidth().clickable { vm.setMode(m); onDone() }.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(title), fontSize = 15.sp, color = c.text, fontWeight = FontWeight.Medium)
                        Text(stringResource(desc), fontSize = 12.sp, color = c.secondary)
                    }
                    if (mode == m) Box(Modifier.size(10.dp).clip(CircleShape).background(c.accent))
                }
            }
        }
    }
}

@Composable
private fun StatsDialog(vm: MainViewModel, onDismiss: () -> Unit) {
    val totals by vm.totals.collectAsState()
    val speed by vm.speed.collectAsState()
    val conns by vm.connections.collectAsState()
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.ok)) } },
        title = { Text(stringResource(R.string.tb_stats)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.stats_upload, Fmt.bytes(totals.first)))
                Text(stringResource(R.string.stats_download, Fmt.bytes(totals.second)))
                Text(stringResource(R.string.stats_speed, Fmt.speed(speed.first), Fmt.speed(speed.second)))
                Text(stringResource(R.string.stats_connections, conns.size))
                // Per-policy totals of the current connections (session statistics: A2).
                val byPolicy = conns.groupBy { it.chains?.lastOrNull() ?: "?" }
                    .mapValues { (_, l) -> l.sumOf { it.upload + it.download } }
                    .entries.sortedByDescending { it.value }.take(6)
                byPolicy.forEach { (k, v) -> Text("$k · ${Fmt.bytes(v)}", fontSize = 13.sp) }
            }
        },
    )
}
