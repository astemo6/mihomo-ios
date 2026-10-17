package io.github.astemo6.mihomo.ui.feature2

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.api.ProviderItem
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.data.feature2.CustomRulesStore
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.data.feature2.NodeSubStore
import io.github.astemo6.mihomo.data.feature2.NodeSubscription
import io.github.astemo6.mihomo.data.feature2.RenameRule
import io.github.astemo6.mihomo.data.feature2.SubPreviewResult
import io.github.astemo6.mihomo.data.feature2.SubRules
import io.github.astemo6.mihomo.data.feature2.SubRulesStore
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private sealed interface SubEditing {
    data class Sub(val sub: NodeSubscription?) : SubEditing
    /** 节点处理 of a node subscription ("nodesub-<id>", preview its cache) or of the active profile (its id). */
    data class Rules(val key: String, val title: String, val previewPath: String) : SubEditing
}

/** 订阅管理 (iOS SubscriptionsView / NodeSubStore / SubscriptionRulesView). */
@Composable
fun NodeSubsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val c = LocalAppColors.current
    val subs by NodeSubStore.subs.collectAsState()
    val updating by NodeSubStore.updating.collectAsState()
    val vpn by VpnState.info.collectAsState()
    val active by ProfileStore.activeId.collectAsState()
    var editing by remember { mutableStateOf<SubEditing?>(null) }
    var confirmDelete by remember { mutableStateOf<NodeSubscription?>(null) }
    var providers by remember { mutableStateOf<List<ProviderItem>>(emptyList()) }
    var message by remember { mutableStateOf<String?>(null) }
    val reloadedMsg = stringResource(R.string.f2_saved_reloaded)

    fun applyChange() {
        if (F2Core.isConnected) { F2Core.reload(context); F2Util.toast(context, reloadedMsg) }
    }

    LaunchedEffect(Unit) { if (NodeSubStore.autoUpdateIfNeeded()) applyChange() }
    LaunchedEffect(vpn.isRunning) {
        providers = if (vpn.isRunning) { delay(500); runCatching { ControllerClient.proxyProviders() }.getOrDefault(emptyList()) } else emptyList()
    }

    when (val e = editing) {
        is SubEditing.Sub -> {
            BackHandler { editing = null }
            NodeSubEditor(e.sub, onBack = { editing = null }) { editing = null; applyChange() }
            return
        }
        is SubEditing.Rules -> {
            BackHandler { editing = null }
            SubRulesEditor(e.key, e.title, e.previewPath, onBack = { editing = null }) { editing = null; applyChange() }
            return
        }
        null -> {}
    }

    F2Page(stringResource(R.string.f2_nodesubs_title), onBack, actions = {
        IconButton(onClick = {
            scope.launch {
                val errs = NodeSubStore.refreshAll()
                applyChange()
                if (errs.isNotEmpty()) message = errs.joinToString("\n")
            }
        }) { Icon(Icons.Default.Refresh, stringResource(R.string.f2_update_all)) }
        IconButton(onClick = { editing = SubEditing.Sub(null) }) { Icon(Icons.Default.Add, stringResource(R.string.f2_nodesubs_add)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_nodesubs_n, subs.size)) }
        if (subs.isEmpty()) item { AppCard { Text(stringResource(R.string.f2_nodesubs_empty), fontSize = 13.sp, color = c.secondary) } }
        items(subs, key = { it.id }) { s ->
            AppCard(Modifier.padding(bottom = 8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(s.name, fontSize = 15.sp, color = c.text, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                            textDecoration = if (s.enabled) null else TextDecoration.LineThrough)
                        Text(listOfNotNull(
                            s.count?.let { stringResource(R.string.f2_n_nodes, it) },
                            s.lastUpdatedMs?.let { stringResource(R.string.f2_updated_at, Fmt.dateTime(it)) },
                            if (SubRulesStore.get(s.rulesKey)?.let { it.enabled && !it.isEmpty } == true) stringResource(R.string.f2_sub_rules_on) else null,
                        ).joinToString(" · "), fontSize = 11.sp, color = c.secondary)
                    }
                    if (s.id in updating) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Switch(checked = s.enabled, onCheckedChange = { on -> NodeSubStore.save(s.copy(enabled = on)); applyChange() })
                }
                s.userInfo?.takeIf { it.total > 0 }?.let { info ->
                    LinearProgressIndicator(progress = { info.fraction }, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp))
                    Text(stringResource(R.string.f2_used_of, Fmt.bytes(info.used), Fmt.bytes(info.total)) +
                        (if (info.expire > 0) " · " + stringResource(R.string.f2_expires, Fmt.date(info.expire * 1000)) else ""),
                        fontSize = 11.sp, color = c.secondary)
                }
                s.lastError?.let { Text(it, fontSize = 11.sp, color = c.bad, maxLines = 2) }
                Row {
                    TextButton(onClick = { scope.launch { NodeSubStore.refresh(s)?.let { message = it } ?: applyChange() } }) { Text(stringResource(R.string.f2_update)) }
                    TextButton(onClick = { editing = SubEditing.Sub(s) }) { Text(stringResource(R.string.f2_edit)) }
                    TextButton(onClick = { editing = SubEditing.Rules(s.rulesKey, s.name, s.cacheFile.absolutePath) }) { Text(stringResource(R.string.f2_sub_rules)) }
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = { confirmDelete = s }) { Text(stringResource(R.string.delete), color = c.bad) }
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_nodesubs_footer)) }

        ProfileStore.active?.takeIf { active != null }?.let { p ->
            item { SectionTitle(stringResource(R.string.f2_sub_rules_profile)) }
            item {
                SettingsGroup {
                    val r = SubRulesStore.get(p.id)
                    SettingsRow(p.name, subtitle = if (r?.enabled == true && !r.isEmpty) stringResource(R.string.f2_sub_rules_on) else stringResource(R.string.f2_off),
                        showDivider = false, onClick = { editing = SubEditing.Rules(p.id, p.name, p.file.absolutePath) })
                }
            }
            item { F2Footer(stringResource(R.string.f2_sub_rules_profile_footer)) }
        }

        if (providers.isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.f2_nodesubs_providers_n, providers.size)) }
            items(providers, key = { "pv-" + it.name }) { pv ->
                AppCard(Modifier.padding(bottom = 8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(pv.name, fontSize = 14.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(listOfNotNull(pv.vehicleType, stringResource(R.string.f2_n_nodes, pv.proxies?.size ?: 0),
                                pv.updatedAt?.take(19)?.replace('T', ' ')).joinToString(" · "), fontSize = 11.sp, color = c.secondary)
                        }
                        if (pv.vehicleType == "HTTP") TextButton(onClick = {
                            scope.launch {
                                runCatching { ControllerClient.updateProxyProvider(pv.name) }.onFailure { message = it.message }
                                providers = runCatching { ControllerClient.proxyProviders() }.getOrDefault(providers)
                            }
                        }) { Text(stringResource(R.string.f2_update)) }
                    }
                }
            }
        }
    }

    confirmDelete?.let { s ->
        ConfirmDialog(stringResource(R.string.f2_delete_q), s.name, stringResource(R.string.delete),
            onConfirm = { NodeSubStore.delete(s); applyChange() }, onDismiss = { confirmDelete = null })
    }
    MessageDialog(message) { message = null }
}

@Composable
private fun uaOptions() = listOf("clash.meta" to "clash.meta", "mihomo" to "mihomo", "clash-verge/v2" to "clash-verge/v2",
    "Quantumult%20X/1.5.2" to "Quantumult X", "Shadowrocket/2070" to "Shadowrocket")

@Composable
private fun updateOptions() = listOf("0" to stringResource(R.string.f2_off), "6" to stringResource(R.string.f2_every_hours_n, 6),
    "12" to stringResource(R.string.f2_every_hours_n, 12), "24" to stringResource(R.string.f2_daily), "168" to stringResource(R.string.f2_weekly))

@Composable
private fun NodeSubEditor(initial: NodeSubscription?, onBack: () -> Unit, onSaved: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val c = LocalAppColors.current
    var url by remember { mutableStateOf(initial?.url.orEmpty()) }
    var name by remember { mutableStateOf(initial?.name.orEmpty()) }
    var ua by remember { mutableStateOf(initial?.userAgent ?: "clash.meta") }
    var hours by remember { mutableStateOf(initial?.updateIntervalHours ?: 24) }
    var groups by remember { mutableStateOf(initial?.groups.orEmpty()) }
    var enabled by remember { mutableStateOf(initial?.enabled ?: true) }
    var candidates by remember { mutableStateOf<List<String>>(emptyList()) }
    var picking by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { candidates = F2Core.io { CustomRulesStore.profileGroups() } }

    F2Page(stringResource(if (initial == null) R.string.f2_nodesubs_add else R.string.f2_nodesubs_edit), onBack, actions = {
        if (busy) CircularProgressIndicator(Modifier.size(20.dp).padding(end = 4.dp), strokeWidth = 2.dp)
        else TextButton(enabled = url.isNotBlank(), onClick = {
            busy = true; error = null
            scope.launch {
                try {
                    if (initial == null) NodeSubStore.add(url, name, ua, hours, groups)
                    else {
                        val changedUrl = url.trim() != initial.url || ua != initial.userAgent
                        val n = initial.copy(url = url.trim(), name = name.trim().ifEmpty { initial.name }, userAgent = ua,
                            updateIntervalHours = hours, groups = groups.ifEmpty { null }, enabled = enabled)
                        NodeSubStore.save(n)
                        if (changedUrl) NodeSubStore.refresh(n)?.let { throw IllegalStateException(it) }
                    }
                    onSaved()
                } catch (e: Exception) {
                    error = e.message ?: e.toString()
                } finally { busy = false }
            }
        }) { Text(stringResource(R.string.f2_save)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_nodesubs_link)) }
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_nodesubs_url), url, { url = it }, placeholder = "https://…")
                TextButton(onClick = { F2Util.paste(context).trim().takeIf { it.startsWith("http") }?.let { url = it } },
                    modifier = Modifier.padding(start = 6.dp)) { Text(stringResource(R.string.f2_paste)) }
                F2Field(stringResource(R.string.f2_name), name, { name = it }, placeholder = stringResource(R.string.f2_name_auto))
                ChoiceRow("User-Agent", uaOptions(), ua) { ua = it }
                ChoiceRow(stringResource(R.string.f2_auto_update), updateOptions(), hours.toString(), showDivider = initial != null) { hours = it.toInt() }
                if (initial != null) SwitchRow(stringResource(R.string.f2_enabled), checked = enabled, showDivider = false) { enabled = it }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_nodesubs_groups)) }
        item {
            SettingsGroup {
                SettingsRow(stringResource(R.string.f2_nodesubs_groups), value = if (groups.isEmpty()) stringResource(R.string.f2_default) else groups.joinToString(", "),
                    showDivider = false, onClick = { picking = true })
            }
        }
        item { F2Footer(stringResource(R.string.f2_nodesubs_groups_footer)) }
        error?.let { e -> item { Text(e, color = c.bad, fontSize = 13.sp, modifier = Modifier.padding(8.dp)) } }
    }
    if (picking) MultiPickDialog(stringResource(R.string.f2_nodesubs_groups), candidates, groups.toSet(), onDismiss = { picking = false }) { groups = it }
}

private val renamePresets = listOf(
    R.string.f2_preset_multiplier to RenameRule("""\s*[|｜\-]\s*(\d+(\.\d+)?\s*[xX倍]|倍率.*)$""", ""),
    R.string.f2_preset_hongkong to RenameRule("""(?i)hong\s?kong""", "香港"),
    R.string.f2_preset_brackets to RenameRule("""\s*[\(（\[【].*?[\)）\]】]\s*""", " "),
    R.string.f2_preset_spaces to RenameRule("""\s{2,}""", " "),
)

/** 节点处理 with live preview (bridge SubPreview). */
@Composable
private fun SubRulesEditor(key: String, title: String, previewPath: String, onBack: () -> Unit, onSaved: () -> Unit) {
    val c = LocalAppColors.current
    var r by remember { mutableStateOf(SubRulesStore.get(key) ?: SubRules()) }
    var preview by remember { mutableStateOf<SubPreviewResult?>(null) }
    var showRemoved by remember { mutableStateOf(true) }
    var newStrip by remember { mutableStateOf("") }
    LaunchedEffect(r) {
        delay(350)
        val json = AppJson.encodeToString(SubRules.serializer(), r)
        preview = F2Core.io { runCatching { AppJson.decodeFromString(SubPreviewResult.serializer(), F2Core.subPreview(previewPath, json)) }.getOrNull() }
    }
    F2Page(stringResource(R.string.f2_sub_rules) + " · " + title, onBack, actions = {
        TextButton(onClick = { SubRulesStore.set(key, if (r.isEmpty && r.enabled) null else r); onSaved() }) { Text(stringResource(R.string.f2_save)) }
    }) {
        item { SettingsGroup { SwitchRow(stringResource(R.string.f2_sub_rules_enable), checked = r.enabled, showDivider = false) { r = r.copy(enabled = it) } } }
        item { F2Footer(stringResource(R.string.f2_sub_rules_note)) }
        item { SectionTitle(stringResource(R.string.f2_sub_filter)) }
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_sub_include), r.include, { r = r.copy(include = it) }, mono = true, placeholder = "香港|HK|日本")
                F2Field(stringResource(R.string.f2_sub_exclude), r.exclude, { r = r.copy(exclude = it) }, mono = true, placeholder = "过期|剩余|官网")
                SwitchRow(stringResource(R.string.f2_sub_regex), checked = r.regex, showDivider = false) { r = r.copy(regex = it) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_sub_renames)) }
        item {
            SettingsGroup {
                r.renames.forEachIndexed { i, rr ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            F2Field(stringResource(R.string.f2_sub_pattern), rr.pattern, { v -> r = r.copy(renames = r.renames.toMutableList().also { it[i] = rr.copy(pattern = v) }) }, mono = true)
                            F2Field(stringResource(R.string.f2_sub_replace), rr.replace, { v -> r = r.copy(renames = r.renames.toMutableList().also { it[i] = rr.copy(replace = v) }) }, mono = true)
                        }
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Switch(checked = rr.enabled, onCheckedChange = { v -> r = r.copy(renames = r.renames.toMutableList().also { it[i] = rr.copy(enabled = v) }) })
                            TextButton(onClick = { r = r.copy(renames = r.renames.toMutableList().also { it.removeAt(i) }) }) { Text(stringResource(R.string.delete), color = c.bad, fontSize = 12.sp) }
                        }
                    }
                    HorizontalDivider(color = c.separator, thickness = 0.5.dp)
                }
                TextButton(onClick = { r = r.copy(renames = r.renames + RenameRule()) }, modifier = Modifier.padding(start = 6.dp)) { Text(stringResource(R.string.f2_sub_add_rename)) }
                renamePresets.forEach { (label, rule) ->
                    TextButton(onClick = { r = r.copy(renames = r.renames + rule) }, modifier = Modifier.padding(start = 6.dp)) {
                        Text("+ " + stringResource(label), fontSize = 12.sp)
                    }
                }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_sub_prefix_flags)) }
        item {
            SettingsGroup {
                if (r.stripPrefixes.isNotEmpty()) Text(r.stripPrefixes.joinToString("  ·  "), fontSize = 12.sp, color = c.text, fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(horizontal = 14.dp, vertical = 6.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    F2Field(stringResource(R.string.f2_sub_strip_prefix), newStrip, { newStrip = it }, modifier = Modifier.weight(1f))
                    TextButton(onClick = { if (newStrip.isNotBlank()) { r = r.copy(stripPrefixes = r.stripPrefixes + newStrip); newStrip = "" } }) { Text(stringResource(R.string.f2_add)) }
                    if (r.stripPrefixes.isNotEmpty()) TextButton(onClick = { r = r.copy(stripPrefixes = emptyList()) }) { Text(stringResource(R.string.f2_clear), color = c.bad) }
                }
                F2Field(stringResource(R.string.f2_sub_prefix), r.prefix, { r = r.copy(prefix = it) })
                SwitchRow(stringResource(R.string.f2_sub_strip_flags), checked = r.stripFlags) { r = r.copy(stripFlags = it) }
                SwitchRow(stringResource(R.string.f2_sub_add_flag), checked = r.addFlag, showDivider = false) { r = r.copy(addFlag = it) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_sub_dedupe_sort)) }
        item {
            SettingsGroup {
                SwitchRow(stringResource(R.string.f2_sub_dedupe), checked = r.dedupe) { r = r.copy(dedupe = it) }
                ChoiceRow(stringResource(R.string.f2_sub_sort), listOf("" to stringResource(R.string.f2_sub_sort_keep), "name" to stringResource(R.string.f2_sub_sort_name),
                    "region" to stringResource(R.string.f2_sub_sort_region)), r.sort, showDivider = false) { r = r.copy(sort = it) }
            }
        }
        item { F2Footer(stringResource(R.string.f2_sub_dedupe_footer)) }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionTitle(stringResource(R.string.f2_live_preview), Modifier.weight(1f))
                Text(stringResource(R.string.f2_show_removed), fontSize = 12.sp, color = c.secondary)
                Switch(checked = showRemoved, onCheckedChange = { showRemoved = it })
            }
        }
        val p = preview
        if (p != null) {
            item { Text(stringResource(R.string.f2_kept_of, p.kept, p.total), fontSize = 13.sp, color = c.text, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(6.dp)) }
            p.errors.forEach { e -> item { Text(e, fontSize = 12.sp, color = c.bad, modifier = Modifier.padding(horizontal = 6.dp)) } }
            if (p.nodes.isEmpty()) item { F2Footer(stringResource(R.string.f2_preview_empty)) }
            item {
                AppCard {
                    p.nodes.filter { showRemoved || it.kept }.take(300).forEach { n ->
                        Row(Modifier.padding(vertical = 3.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(n.name.ifEmpty { n.original }, fontSize = 13.sp, color = if (n.kept) c.text else c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                    textDecoration = if (n.kept) null else TextDecoration.LineThrough)
                                if (n.name != n.original || n.reason != null) Text(listOfNotNull(n.original.takeIf { it != n.name }, n.reason).joinToString(" · "),
                                    fontSize = 10.sp, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            }
                            n.region?.takeIf { it.isNotEmpty() }?.let { Tag(it, c.accent); Spacer(Modifier.width(4.dp)) }
                            Tag(n.type, c.secondary)
                        }
                    }
                }
            }
        }
        item {
            Button(onClick = { r = SubRules() }, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) { Text(stringResource(R.string.f2_sub_clear_rules)) }
        }
    }
}
