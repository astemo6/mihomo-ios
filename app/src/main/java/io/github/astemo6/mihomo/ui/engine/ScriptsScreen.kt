package io.github.astemo6.mihomo.ui.engine

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer

@Serializable
private data class ScriptLog(val id: Long = 0, val time: Double = 0.0, val script: String = "", val level: String = "", val msg: String = "")

private data class ModuleScript(val module: String, val kind: String, val name: String, val pattern: String, val path: String)

/** 脚本: the user's script lines, scripts / cron / event tasks from modules, and the engine's script console (/mitm/logs). */
@Composable
fun ScriptsScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val cfg by EngineStore.config.collectAsState()
    val info by EngineStore.moduleInfo.collectAsState()
    val running by vm.running.collectAsState()
    var tab by remember { mutableIntStateOf(0) }
    var showAdd by remember { mutableStateOf(false) }
    var logs by remember { mutableStateOf<List<ScriptLog>>(emptyList()) }
    val scope = rememberCoroutineScope()

    val fromModules = remember(cfg, info) {
        cfg.modules.flatMap { m ->
            val p = info[m.id] ?: return@flatMap emptyList()
            p.rules.filter { it.kind == "script" }.map { ModuleScript(m.name, it.phase.ifEmpty { "script" }, it.script ?: it.desc, it.pattern, it.path.orEmpty()) } +
                p.tasks.orEmpty().map { t -> ModuleScript(m.name, t.kind, t.name, t.cron ?: t.event.orEmpty(), t.path) }
        }
    }

    LaunchedEffect(tab, running) {
        if (tab != 1 || !running) return@LaunchedEffect
        var since = 0L
        while (isActive) {
            runCatching {
                val list = AppJson.decodeFromString(ListSerializer(ScriptLog.serializer()), ControllerClient.mitmLogs(since))
                if (list.isNotEmpty()) {
                    since = list.maxOf { it.id }
                    logs = (list.reversed() + logs).take(500)
                }
            }
            delay(2000)
        }
    }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.scripts), onBack) {
            if (tab == 0) TextButton(onClick = { showAdd = true }) { Text(stringResource(R.string.add)) }
            else TextButton(onClick = { scope.launch { runCatching { ControllerClient.mitmClearLogs() }; logs = emptyList() } }) {
                Text(stringResource(R.string.clear))
            }
        }
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            TabRow(selectedTabIndex = tab, containerColor = c.bg) {
                Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.scripts)) })
                Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.script_logs)) })
            }
            LazyColumn(contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 40.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (tab == 0) {
                    item { SectionTitle(stringResource(R.string.scripts_own)) }
                    if (cfg.scripts.isEmpty()) item { AppCard { EmptyHint(stringResource(R.string.scripts_own_empty)) } }
                    items(cfg.scripts, key = { it.id }) { LineRow(it, scripts = true) }
                    item { SectionTitle(stringResource(R.string.scripts_modules)) }
                    if (fromModules.isEmpty()) item { AppCard { EmptyHint(stringResource(R.string.scripts_modules_empty)) } }
                    items(fromModules) { s ->
                        AppCard(padding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Tag(s.kind, c.accent)
                                Spacer(Modifier.width(6.dp))
                                Text(s.name, fontWeight = FontWeight.Medium, fontSize = 13.sp, color = c.text, maxLines = 1,
                                    overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                            }
                            if (s.pattern.isNotEmpty()) Text(s.pattern, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.secondary, maxLines = 1,
                                overflow = TextOverflow.Ellipsis)
                            Text(listOf(s.module, s.path).filter { it.isNotEmpty() }.joinToString(" · "), fontSize = 11.sp, color = c.secondary,
                                maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                } else {
                    if (!running) item { AppCard { EmptyHint(stringResource(R.string.need_running)) } }
                    else if (logs.isEmpty()) item { AppCard { EmptyHint(stringResource(R.string.no_logs)) } }
                    items(logs, key = { "l:${it.id}" }) { l ->
                        AppCard(padding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Tag(l.level.ifEmpty { "info" }, when (l.level) {
                                    "error" -> Color(0xFFFF3B30); "warn", "warning" -> Color(0xFFFF9500); else -> Color(0xFF34C759)
                                })
                                Spacer(Modifier.width(6.dp))
                                Text(l.script, fontSize = 12.sp, color = c.text, fontWeight = FontWeight.Medium, modifier = Modifier.weight(1f),
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                if (l.time > 0) Text(Fmt.time((l.time * 1000).toLong()), fontSize = 11.sp, color = c.secondary)
                            }
                            Text(l.msg, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.text)
                        }
                    }
                }
            }
        }
    }

    if (showAdd) AddLinesDialog(scripts = true, onAdd = { text ->
        scope.launch {
            val n = withContext(Dispatchers.IO) { EngineStore.addLines(text, toScripts = true) }
            vm.toast(ctx.getString(R.string.msg_lines_added, n))
        }
        showAdd = false
    }, onDismiss = { showAdd = false })
}
