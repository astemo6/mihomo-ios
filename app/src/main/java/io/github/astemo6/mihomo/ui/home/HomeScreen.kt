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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    vm: MainViewModel,
    onToggle: (Boolean) -> Unit,
    onOpenSettings: () -> Unit,
    onAdd: () -> Unit,
    onOpenProfiles: () -> Unit,
) {
    val c = LocalAppColors.current
    val panel by vm.panel.collectAsState()
    var searching by rememberSaveable { mutableStateOf(false) }
    var query by rememberSaveable { mutableStateOf("") }
    var showModeSheet by remember { mutableStateOf(false) }
    var showStats by remember { mutableStateOf(false) }
    var showDns by remember { mutableStateOf(false) }
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
            item(key = "strip") { PanelStrip(panel) { vm.setPanel(it) } }
            if (searching) {
                item(key = "search") {
                    OutlinedTextField(
                        value = query, onValueChange = { query = it },
                        modifier = Modifier.fillMaxWidth(), singleLine = true,
                        placeholder = { Text(stringResource(R.string.search)) },
                        leadingIcon = { Icon(Icons.Filled.Search, null) },
                        trailingIcon = {
                            IconButton(onClick = { query = ""; searching = false }) { Icon(Icons.Filled.Close, null) }
                        },
                        shape = RoundedCornerShape(12.dp),
                    )
                }
            }
            val q = if (searching) query.trim() else ""
            when (panel) {
                Panel.NODES -> nodesPanel(vm, NodesData(groups, resource, delays, testing, nodeTypes, mode, running, expanded), q, toggleExpanded)
                Panel.ACTIVITY -> activityPanel(vm, connections, totals, speed, running, q)
                Panel.RULES -> rulesPanel(rules, q)
                Panel.REWRITE -> rewritePanel()
                Panel.LOGS -> logsPanel(vm, logs, logLevel, logsPaused, running, q)
            }
        }

        FloatingToolbar(
            modifier = Modifier.align(Alignment.BottomCenter).navigationBarsPadding().padding(bottom = 14.dp),
            onSearch = { searching = !searching; if (!searching) query = "" },
            onAdd = onAdd,
            onStats = { showStats = true },
            onDns = { showDns = true },
            onRequests = { vm.setPanel(Panel.ACTIVITY) },
            onWindmill = onOpenSettings,
            onWindmillLong = { showModeSheet = true },
        )
    }

    if (showModeSheet) {
        ModalBottomSheet(onDismissRequest = { showModeSheet = false }, containerColor = c.bg) {
            ModeSheet(vm) { showModeSheet = false }
        }
    }
    if (showStats) StatsDialog(vm) { showStats = false }
    if (showDns) {
        AlertDialog(
            onDismissRequest = { showDns = false },
            confirmButton = { TextButton(onClick = { showDns = false }) { Text(stringResource(R.string.ok)) } },
            title = { Text(stringResource(R.string.dns)) },
            text = { Text(stringResource(R.string.dns_later)) },
        )
    }
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

private data class PanelSpec(val panel: Panel, val label: Int, val icon: ImageVector, val color: Color)

private val panelSpecs = listOf(
    PanelSpec(Panel.NODES, R.string.panel_nodes, Icons.Filled.Public, PanelColors.nodes),
    PanelSpec(Panel.ACTIVITY, R.string.panel_activity, Icons.Filled.Timeline, PanelColors.activity),
    PanelSpec(Panel.RULES, R.string.panel_rules, Icons.AutoMirrored.Filled.AltRoute, PanelColors.rules),
    PanelSpec(Panel.REWRITE, R.string.panel_rewrite, Icons.Filled.AutoFixHigh, PanelColors.rewrite),
    PanelSpec(Panel.LOGS, R.string.panel_logs, Icons.Filled.Description, PanelColors.logs),
)

@Composable
private fun PanelStrip(selected: Panel, onSelect: (Panel) -> Unit) {
    val c = LocalAppColors.current
    AppCard(padding = PaddingValues(horizontal = 6.dp, vertical = 10.dp)) {
        Row(Modifier.fillMaxWidth()) {
            panelSpecs.forEach { s ->
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

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun FloatingToolbar(
    modifier: Modifier,
    onSearch: () -> Unit,
    onAdd: () -> Unit,
    onStats: () -> Unit,
    onDns: () -> Unit,
    onRequests: () -> Unit,
    onWindmill: () -> Unit,
    onWindmillLong: () -> Unit,
) {
    val c = LocalAppColors.current
    Surface(
        modifier = modifier.shadow(10.dp, RoundedCornerShape(26.dp)),
        shape = RoundedCornerShape(26.dp),
        color = c.card,
    ) {
        Row(Modifier.padding(horizontal = 8.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            ToolbarButton(Icons.Filled.Search, stringResource(R.string.tb_search), onSearch)
            ToolbarButton(Icons.Filled.Add, stringResource(R.string.tb_add), onAdd)
            ToolbarButton(Icons.Filled.BarChart, stringResource(R.string.tb_stats), onStats)
            ToolbarButton(Icons.Filled.Dns, stringResource(R.string.dns), onDns)
            ToolbarButton(Icons.Filled.SwapVert, stringResource(R.string.tb_requests), onRequests)
            Box(
                Modifier.size(44.dp).clip(CircleShape)
                    .combinedClickable(onClick = onWindmill, onLongClick = onWindmillLong),
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.Filled.Toys, stringResource(R.string.settings), tint = c.accent) }
        }
    }
}

@Composable
private fun ToolbarButton(icon: ImageVector, label: String, onClick: () -> Unit) {
    IconButton(onClick = onClick, modifier = Modifier.size(44.dp)) {
        Icon(icon, label, tint = LocalAppColors.current.text)
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
