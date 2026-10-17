package io.github.astemo6.mihomo.ui.engine

import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.EngineItem
import io.github.astemo6.mihomo.data.ParsedEngineText
import io.github.astemo6.mihomo.data.EngineModule
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.ImportRouter
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.profiles.readDocument
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * 重写 (QX settings › 重写): master switch, modules (import by URL / file / clipboard, enable, update,
 * delete, view), and the user's own rewrite lines. Mirrors the iOS MitMView 模块 / 重写 sections; the
 * Go engine (core/mitm) parses and runs everything.
 */
@Composable
fun RewriteScreen(vm: MainViewModel, onBack: () -> Unit, onMitm: () -> Unit, onScripts: () -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val cfg by EngineStore.config.collectAsState()
    val info by EngineStore.moduleInfo.collectAsState()
    val busy by EngineStore.busy.collectAsState()
    val scope = rememberCoroutineScope()
    var showAdd by remember { mutableStateOf(false) }
    var showAddLines by remember { mutableStateOf(false) }
    var viewing by remember { mutableStateOf<EngineModule?>(null) }
    var deleting by remember { mutableStateOf<EngineModule?>(null) }
    var detailId by remember { mutableStateOf<String?>(null) }

    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            when (val r = readDocument(ctx, uri)) {
                is ImportRouter.Request.Text -> vm.import(ImportRouter.Request.ModuleText(r.text, r.name))
                null -> vm.toast(ctx.getString(R.string.err_read_file))
                else -> vm.import(r)
            }
            showAdd = false
        }
    }

    detailId?.let { id ->
        BackHandler { detailId = null }
        ModuleDetailScreen(vm, id, onBack = { detailId = null })
        return
    }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.sec_rewrite), onBack) {
            IconButton(onClick = {
                scope.launch {
                    val errs = EngineStore.updateAll()
                    vm.toast(if (errs.isEmpty()) ctx.getString(R.string.msg_modules_updated) else errs.joinToString("\n"))
                }
            }) { Icon(Icons.Filled.Refresh, stringResource(R.string.update_all)) }
            IconButton(onClick = { showAdd = true }) { Icon(Icons.Filled.Add, stringResource(R.string.add)) }
        }
    }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.rewrite_master), stringResource(R.string.rewrite_master_desc), cfg.enabled) { EngineStore.setEnabled(it) }
                    SettingsRowLink(stringResource(R.string.sec_mitm), if (cfg.mitm) stringResource(R.string.on) else stringResource(R.string.off), onMitm)
                    SettingsRowLink(stringResource(R.string.scripts), cfg.scripts.size.toString() + " / " +
                        info.values.sumOf { p -> p.rules.count { it.kind == "script" } + (p.tasks?.size ?: 0) }, onScripts, divider = false)
                }
            }
            item { SectionTitle(stringResource(R.string.modules)) }
            if (cfg.modules.isEmpty()) item { AppCard { EmptyHint(stringResource(R.string.modules_empty)) } }
            items(cfg.modules, key = { it.id }) { m ->
                val p = info[m.id]
                AppCard(padding = PaddingValues(start = 14.dp, end = 6.dp, top = 10.dp, bottom = 10.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f).clickable { detailId = m.id }) {
                            Text(m.name, fontWeight = FontWeight.SemiBold, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            val scripts = p?.rules?.count { it.kind == "script" } ?: 0
                            val summary = if (p == null) stringResource(R.string.module_not_downloaded)
                            else stringResource(R.string.module_summary, p.rules.size - scripts, scripts, p.hostnames.size)
                            Text(summary, fontSize = 12.sp, color = c.secondary)
                            val sub = listOfNotNull(
                                p?.format?.takeIf { it.isNotEmpty() },
                                m.updatedAt?.let { stringResource(R.string.updated_at, Fmt.dateTime((it * 1000).toLong())) },
                                if (m.url.isEmpty()) stringResource(R.string.kind_local) else null,
                            ).joinToString(" · ")
                            if (sub.isNotEmpty()) Text(sub, fontSize = 11.sp, color = c.secondary)
                            val nArgs = p?.arguments?.size ?: 0
                            if (nArgs > 0 || !m.policies.isNullOrEmpty()) Text(
                                listOfNotNull(
                                    if (nArgs > 0) stringResource(R.string.e2_module_args_n, nArgs) else null,
                                    if (!m.policies.isNullOrEmpty()) stringResource(R.string.e2_module_policies_n, m.policies.size) else null,
                                ).joinToString(" · "), fontSize = 11.sp, color = c.accent)
                            if (!p?.errors.isNullOrEmpty()) Text(p!!.errors.first(), fontSize = 11.sp, color = c.bad, maxLines = 2)
                        }
                        if (m.id in busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                        Switch(m.enabled, { EngineStore.setModuleEnabled(m, it) }, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
                    }
                    Row {
                        TextButton(onClick = { detailId = m.id }) { Text(stringResource(R.string.e2_details)) }
                        TextButton(onClick = { viewing = m }) { Text(stringResource(R.string.view)) }
                        if (m.url.isNotEmpty()) TextButton(onClick = {
                            scope.launch { EngineStore.updateModule(m)?.let { vm.toast(ctx.getString(R.string.msg_update_failed, it)) } }
                        }) { Text(stringResource(R.string.update)) }
                        Spacer(Modifier.weight(1f))
                        TextButton(onClick = { deleting = m }) { Text(stringResource(R.string.delete), color = c.bad) }
                    }
                }
            }
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SectionTitle(stringResource(R.string.rewrite_own), Modifier.weight(1f))
                    TextButton(onClick = { showAddLines = true }) { Text(stringResource(R.string.add)) }
                }
            }
            if (cfg.rules.isEmpty()) item { AppCard { EmptyHint(stringResource(R.string.rewrite_own_empty)) } }
            items(cfg.rules, key = { it.id }) { r -> LineRow(r, scripts = false) }
        }
    }

    if (showAdd) AddModuleDialog(
        busy = "add" in busy,
        onUrl = { url ->
            vm.import(ImportRouter.Request.ModuleUrl(url.trim()))
            showAdd = false
        },
        onFile = { pickFile.launch(arrayOf("*/*")) },
        onClipboard = {
            val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val t = cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString().orEmpty().trim()
            when {
                t.isEmpty() -> vm.toast(ctx.getString(R.string.clipboard_empty))
                !t.contains('\n') && (t.startsWith("http://") || t.startsWith("https://")) -> vm.import(ImportRouter.Request.ModuleUrl(t))
                else -> vm.import(ImportRouter.Request.ModuleText(t, ctx.getString(R.string.local_module)))
            }
            showAdd = false
        },
        onDismiss = { showAdd = false },
    )
    if (showAddLines) AddLinesDialog(scripts = false, onAdd = { text ->
        scope.launch {
            val n = withContext(Dispatchers.IO) { EngineStore.addLines(text, toScripts = false) }
            vm.toast(ctx.getString(R.string.msg_lines_added, n))
        }
        showAddLines = false
    }, onDismiss = { showAddLines = false })
    viewing?.let { m ->
        AlertDialog(
            onDismissRequest = { viewing = null },
            title = { Text(m.name) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (m.url.isNotEmpty()) Text(m.url, fontSize = 11.sp, color = c.accent)
                    info[m.id]?.unsupported?.takeIf { it.isNotEmpty() }?.let { u ->
                        Text(stringResource(R.string.msg_module_unsupported, u.size), fontSize = 12.sp, color = c.warn)
                    }
                    SelectionContainer {
                        Text(EngineStore.moduleText(m).take(60_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { viewing = null }) { Text(stringResource(R.string.ok)) } },
        )
    }
    deleting?.let { m ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(stringResource(R.string.delete_profile_q, m.name)) },
            confirmButton = { TextButton(onClick = { EngineStore.deleteModule(m); deleting = null }) { Text(stringResource(R.string.delete), color = c.bad) } },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
internal fun SettingsRowLink(title: String, value: String, onClick: () -> Unit, divider: Boolean = true) {
    io.github.astemo6.mihomo.ui.components.SettingsRow(title, value = value, onClick = onClick, showDivider = divider)
}

/** One user rewrite / script line: kind tag, description from the engine, switch and delete. */
@Composable
internal fun LineRow(item: EngineItem, scripts: Boolean, onOpen: ((String) -> Unit)? = null) {
    val c = LocalAppColors.current
    val d = remember(item.line) { runCatching { EngineStore.describe(item.line, if (scripts) "script" else "") }.getOrNull() }
    AppCard(padding = PaddingValues(start = 12.dp, end = 4.dp, top = 8.dp, bottom = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Tag(d?.second?.ifEmpty { "?" } ?: "?", if (d?.third != null) c.bad else c.accent)
                    Spacer(Modifier.width(6.dp))
                    Text(d?.third ?: d?.first.orEmpty(), fontSize = 12.sp, color = if (d?.third != null) c.bad else c.secondary,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text(item.line, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.text, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            if (onOpen != null) {
                val path = remember(item.line) {
                    runCatching { ParsedEngineText.parse(Core.engineParseLine(item.line, "script"))?.rules?.firstOrNull()?.path }.getOrNull()
                }
                if (!path.isNullOrEmpty()) IconButton(onClick = { onOpen(path) }) {
                    Icon(Icons.Filled.Edit, stringResource(R.string.e2_open_script), tint = c.accent)
                }
            }
            Switch(item.enabled, { EngineStore.toggleItem(item.id, scripts) }, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
            IconButton(onClick = { EngineStore.deleteItem(item.id) }) { Icon(Icons.Filled.Close, stringResource(R.string.delete), tint = c.secondary) }
        }
    }
}

@Composable
private fun AddModuleDialog(busy: Boolean, onUrl: (String) -> Unit, onFile: () -> Unit, onClipboard: () -> Unit, onDismiss: () -> Unit) {
    var url by remember { mutableStateOf("") }
    val c = LocalAppColors.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_module)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(stringResource(R.string.module_url)) }, placeholder = { Text("https://…/x.sgmodule") })
                Button(onClick = { onUrl(url) }, enabled = url.isNotBlank() && !busy, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.download_import))
                }
                HorizontalDivider(color = c.separator)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(onClick = onFile, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.from_file)) }
                    OutlinedButton(onClick = onClipboard, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.from_clipboard)) }
                }
                Text(stringResource(R.string.module_formats), fontSize = 11.sp, color = c.secondary)
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
internal fun AddLinesDialog(scripts: Boolean, onAdd: (String) -> Unit, onDismiss: () -> Unit) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(if (scripts) R.string.add_script else R.string.add_rewrite)) },
        text = {
            Column {
                OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().height(180.dp),
                    textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
                    placeholder = { Text(stringResource(if (scripts) R.string.add_script_hint else R.string.add_rewrite_hint), fontSize = 12.sp) })
            }
        },
        confirmButton = { TextButton(onClick = { onAdd(text) }, enabled = text.isNotBlank()) { Text(stringResource(R.string.add)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
