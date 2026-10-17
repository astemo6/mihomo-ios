package io.github.astemo6.mihomo.ui.engine

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
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
import io.github.astemo6.mihomo.data.EngineExtras
import io.github.astemo6.mihomo.data.EngineModule
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.ParsedEngineText
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.launch

/**
 * One module (iOS ModuleDetailView): info, #!arguments editing (Surge text, Loon switch / select, Egern
 * compat_arguments), policy mapping for [Rule] policies the profile lacks, and the parsed content.
 */
@Composable
fun ModuleDetailScreen(vm: MainViewModel, moduleId: String, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val cfg by EngineStore.config.collectAsState()
    val infoMap by EngineStore.moduleInfo.collectAsState()
    val busy by EngineStore.busy.collectAsState()
    val scope = rememberCoroutineScope()
    val m: EngineModule? = cfg.modules.firstOrNull { it.id == moduleId }
    val info: ParsedEngineText? = infoMap[moduleId]
    val edits = remember(moduleId) { mutableStateMapOf<String, String>() }
    var unresolved by remember { mutableStateOf<List<String>>(emptyList()) }
    var groups by remember { mutableStateOf<List<String>>(emptyList()) }
    var reloadKey by remember { mutableStateOf(0) }
    var showText by remember { mutableStateOf(false) }

    LaunchedEffect(moduleId, reloadKey, m?.args) {
        val mm = m ?: return@LaunchedEffect
        unresolved = EngineExtras.moduleUnresolved(mm)
        groups = EngineExtras.profileGroups()
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(m?.name ?: stringResource(R.string.modules), onBack) }) { pad ->
        if (m == null) return@Scaffold
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                AppCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(m.name, fontWeight = FontWeight.SemiBold, color = c.text)
                            if (!info?.desc.isNullOrBlank()) Text(info!!.desc, fontSize = 12.sp, color = c.secondary)
                        }
                        Switch(m.enabled, { EngineStore.setModuleEnabled(m, it) }, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
                    }
                    info?.format?.takeIf { it.isNotEmpty() }?.let { KvLine(stringResource(R.string.e2_format), it) }
                    m.updatedAt?.let { KvLine(stringResource(R.string.e2_updated), Fmt.dateTime((it * 1000).toLong())) }
                    if (m.url.isNotEmpty()) Text(m.url, fontSize = 11.sp, color = c.accent, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    Row(Modifier.padding(top = 6.dp)) {
                        TextButton(onClick = { showText = true }) { Text(stringResource(R.string.e2_view_content)) }
                        if (m.url.isNotEmpty()) TextButton(enabled = m.id !in busy, onClick = {
                            scope.launch {
                                EngineStore.updateModule(m)?.let { vm.toast(ctx.getString(R.string.msg_update_failed, it)) }
                                reloadKey++
                            }
                        }) { Text(stringResource(R.string.update)) }
                    }
                }
            }

            // ---- arguments ----
            val args = info?.arguments.orEmpty()
            if (args.isNotEmpty()) {
                item {
                    SectionTitle(stringResource(when (info?.format) {
                        "loon" -> R.string.e2_args_loon
                        "egern" -> R.string.e2_args_egern
                        else -> R.string.e2_args_surge
                    }))
                }
                item {
                    AppCard {
                        args.forEachIndexed { i, a ->
                            val value = edits[a.key] ?: m.args?.get(a.key) ?: a.default
                            ArgRow(a, value) { edits[a.key] = it }
                            if (i < args.lastIndex) HorizontalDivider(color = c.separator, thickness = 0.5.dp, modifier = Modifier.padding(vertical = 6.dp))
                        }
                        Row(Modifier.fillMaxWidth().padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = {
                                EngineExtras.setModuleArgs(m.id, edits.toMap())
                                edits.clear()
                                vm.toast(ctx.getString(R.string.e2_args_saved))
                            }, enabled = edits.isNotEmpty(), modifier = Modifier.weight(1f)) { Text(stringResource(R.string.e2_args_save)) }
                            OutlinedButton(onClick = { edits.clear(); EngineExtras.resetModuleArgs(m.id) },
                                enabled = !m.args.isNullOrEmpty() || edits.isNotEmpty(), modifier = Modifier.weight(1f)) {
                                Text(stringResource(R.string.e2_args_reset))
                            }
                        }
                    }
                }
            }

            // ---- policy mapping ----
            val names = (unresolved + m.policies.orEmpty().keys.sorted()).distinct()
            if (names.isNotEmpty()) {
                item { SectionTitle(stringResource(R.string.e2_policy_map)) }
                item {
                    AppCard {
                        val auto = stringResource(R.string.e2_policy_auto)
                        names.forEachIndexed { i, name ->
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(vertical = 4.dp)) {
                                if (name in unresolved && m.policies?.get(name) == null) {
                                    Icon(Icons.Filled.Warning, null, tint = c.warn, modifier = Modifier.padding(end = 6.dp))
                                }
                                Text(name, fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Spacer(Modifier.width(8.dp))
                                val cur = m.policies?.get(name).orEmpty()
                                DropdownField(cur.ifEmpty { auto }, listOf("" to auto) + groups.map { it to it },
                                    Modifier.weight(1f)) { g -> EngineExtras.setModulePolicy(m.id, name, g) }
                            }
                            if (i < names.lastIndex) HorizontalDivider(color = c.separator, thickness = 0.5.dp)
                        }
                        Text(stringResource(R.string.e2_policy_map_desc), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(top = 6.dp))
                        if (groups.isEmpty()) Text(stringResource(R.string.e2_policy_no_profile), fontSize = 11.sp, color = c.warn)
                    }
                }
            }

            if (info != null) {
                if (info.hostnames.isNotEmpty()) {
                    item { SectionTitle(stringResource(R.string.e2_hostnames_n, info.hostnames.size)) }
                    item { AppCard { Text(info.hostnames.joinToString(", "), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text) } }
                }
                item { SectionTitle(stringResource(R.string.e2_rules_n, info.rules.size)) }
                item {
                    AppCard {
                        info.rules.take(300).forEach { r ->
                            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
                                Tag(if (r.phase.isNotEmpty()) "${r.kind}·${r.phase}" else r.kind, c.accent)
                                Spacer(Modifier.width(6.dp))
                                Text(r.desc, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            Text(r.pattern, fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = c.secondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
                info.tasks?.takeIf { it.isNotEmpty() }?.let { tasks ->
                    item { SectionTitle(stringResource(R.string.e2_tasks_n, tasks.size)) }
                    item {
                        AppCard {
                            tasks.forEach { t ->
                                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
                                    Tag(t.kind, c.accent); Spacer(Modifier.width(6.dp))
                                    Text(t.name, fontSize = 12.sp, fontWeight = FontWeight.Medium, color = c.text, maxLines = 1)
                                }
                                Text(t.desc, fontSize = 10.sp, fontFamily = FontFamily.Monospace, color = c.secondary)
                            }
                        }
                    }
                }
                if (info.coreRules.isNotEmpty()) {
                    item { SectionTitle(stringResource(R.string.e2_core_rules_n, info.coreRules.size)) }
                    item {
                        AppCard {
                            info.coreRules.take(200).forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = c.text) }
                        }
                    }
                }
                if (info.errors.isNotEmpty() || info.unsupported.isNotEmpty()) {
                    item { SectionTitle(stringResource(R.string.e2_not_imported_n, info.errors.size + info.unsupported.size)) }
                    item {
                        AppCard {
                            info.errors.forEach { Text(it, fontSize = 11.sp, color = c.bad) }
                            info.unsupported.take(100).forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = c.secondary) }
                        }
                    }
                }
            }
        }
    }

    if (showText && m != null) {
        AlertDialog(
            onDismissRequest = { showText = false },
            title = { Text(m.name) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    SelectionContainer { Text(EngineStore.moduleText(m).take(60_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp) }
                }
            },
            confirmButton = { TextButton(onClick = { showText = false }) { Text(stringResource(R.string.ok)) } },
        )
    }
}

/** One argument: Loon switch → switch, select → dropdown, anything else → text field. */
@Composable
private fun ArgRow(a: ParsedEngineText.ModArg, value: String, onChange: (String) -> Unit) {
    val c = LocalAppColors.current
    Column {
        when (a.type.orEmpty()) {
            "switch" -> Row(verticalAlignment = Alignment.CenterVertically) {
                Text(a.key, fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f))
                Switch(value.lowercase() in setOf("true", "1", "on", "yes"), { onChange(if (it) "true" else "false") },
                    colors = SwitchDefaults.colors(checkedTrackColor = c.good))
            }
            "select" -> Row(verticalAlignment = Alignment.CenterVertically) {
                Text(a.key, fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f))
                val opts = (listOf(value) + a.options.orEmpty()).distinct()
                DropdownField(value, opts.map { it to it }, Modifier.weight(1f)) { onChange(it) }
            }
            else -> OutlinedTextField(value, onChange, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text(a.key) }, placeholder = { Text(a.default) },
                textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp))
        }
        if (!a.desc.isNullOrBlank()) Text(a.desc, fontSize = 11.sp, color = c.secondary)
    }
}
