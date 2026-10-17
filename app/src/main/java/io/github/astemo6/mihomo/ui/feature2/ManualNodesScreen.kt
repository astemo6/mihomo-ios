package io.github.astemo6.mihomo.ui.feature2

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ProxyTypes
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.data.feature2.ChainCandidates
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.data.feature2.ManualNodes
import io.github.astemo6.mihomo.data.feature2.ProbeStore
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

private fun JsonObject.str(k: String): String = (this[k] as? JsonPrimitive)?.contentOrNull.orEmpty()

/** 手动节点 (iOS ManualNodesView + NodeEditorView): form, paste / share-link import, share-link export, probe. */
@Composable
fun ManualNodesScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val manualName = stringResource(R.string.f2_manual_profile_name)
    var nodes by remember { mutableStateOf<List<JsonObject>>(emptyList()) }
    var version by remember { mutableIntStateOf(0) }
    var editing by remember { mutableStateOf<JsonObject?>(null) }
    var creating by remember { mutableStateOf(false) }
    var importText by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf<String?>(null) }
    var probing by remember { mutableStateOf<String?>(null) }
    var merge by remember { mutableStateOf(Overrides.load().mergeManual) }
    val probeErrors = remember { mutableStateMapOf<String, String>() }
    val activeId by ProfileStore.activeId.collectAsState()
    val addedFmt = stringResource(R.string.f2_manual_added_n)
    val copiedMsg = stringResource(R.string.f2_copied)

    fun changed() {
        version++
        if (F2Core.isConnected && (ManualNodes.isActive || Overrides.load().mergeManual)) F2Core.reload(context)
    }

    LaunchedEffect(version) { nodes = F2Core.io { ManualNodes.list() } }

    if (creating || editing != null) {
        BackHandler { creating = false; editing = null }
        NodeEditor(editing, onBack = { creating = false; editing = null }) { creating = false; editing = null; changed() }
        return
    }
    probing?.let { p ->
        BackHandler { probing = null }
        ProbeDetail(p, onBack = { probing = null })
        return
    }

    F2Page(stringResource(R.string.f2_manual_title), onBack, actions = {
        IconButton(onClick = {
            val sub = ManualNodes.subscription()
            if (sub.isNotBlank()) F2Util.shareText(context, sub, context.getString(R.string.f2_manual_export_all))
        }) { Icon(Icons.Default.Share, stringResource(R.string.f2_manual_export_all)) }
        IconButton(onClick = { creating = true }) { Icon(Icons.Default.Add, stringResource(R.string.f2_manual_add)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_manual_import)) }
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_manual_import_hint), importText, { importText = it }, singleLine = false, mono = true, minLines = 3)
                Row(Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
                    TextButton(onClick = { importText = F2Util.paste(context) }) { Text(stringResource(R.string.f2_paste)) }
                    Spacer(Modifier.weight(1f))
                    Button(enabled = importText.isNotBlank(), onClick = {
                        scope.launch {
                            runCatching { F2Core.io { ManualNodes.addText(manualName, importText) } }
                                .onSuccess { n -> importText = ""; F2Util.toast(context, addedFmt.format(n)); changed() }
                                .onFailure { message = it.message }
                        }
                    }) { Text(stringResource(R.string.f2_import)) }
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_manual_import_footer)) }
        item { SectionTitle(stringResource(R.string.f2_manual_use)) }
        item {
            SettingsGroup {
                SwitchRow(stringResource(R.string.f2_manual_merge), stringResource(R.string.f2_manual_merge_desc), checked = merge) { on ->
                    merge = on
                    Overrides.update { it.copy(mergeManual = on) }
                    if (F2Core.isConnected) F2Core.reload(context)
                }
                val p = ManualNodes.profile
                SettingsRow(stringResource(R.string.f2_manual_use_profile),
                    value = if (activeId == ManualNodes.ID) stringResource(R.string.f2_current) else null, showDivider = false,
                    onClick = if (p != null && activeId != ManualNodes.ID) ({ ProfileStore.setActive(p) }) else null)
            }
        }
        item { SectionTitle(stringResource(R.string.f2_manual_n, nodes.size)) }
        if (nodes.isEmpty()) item { AppCard { Text(stringResource(R.string.f2_manual_empty), fontSize = 13.sp, color = c.secondary) } }
        items(nodes, key = { it.str("name") }) { n ->
            val name = n.str("name")
            val probes by ProbeStore.entries.collectAsState()
            val running by ProbeStore.running.collectAsState()
            AppCard(Modifier.padding(bottom = 8.dp)) {
                Row(Modifier.clickable { editing = n }, verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(name, fontSize = 15.sp, color = c.text, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text("${n.str("server")}:${n.str("port")}", fontSize = 12.sp, color = c.secondary, maxLines = 1)
                        probes[name]?.exit?.let { e -> Text("${e.flag} ${e.ip} · ${e.locationText}", fontSize = 11.sp, color = c.accent, maxLines = 1) }
                        ProbeStore.badge(name)?.let { (ok, total) -> Text(stringResource(R.string.f2_unlock_badge, ok, total), fontSize = 11.sp, color = c.good) }
                        probeErrors[name]?.let { Text(it, fontSize = 11.sp, color = c.bad, maxLines = 2) }
                    }
                    Tag(ProxyTypes.short(n.str("type")), c.accent)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = {
                        val link = ManualNodes.shareLink(n)
                        if (link.isBlank()) message = F2Core.lastError().ifBlank { context.getString(R.string.f2_share_unsupported) }
                        else { F2Util.copy(context, link); F2Util.toast(context, copiedMsg) }
                    }) { Text(stringResource(R.string.f2_copy_link), fontSize = 12.sp) }
                    TextButton(onClick = {
                        val link = ManualNodes.shareLink(n)
                        if (link.isNotBlank()) F2Util.shareText(context, link, name)
                    }) { Text(stringResource(R.string.f2_share), fontSize = 12.sp) }
                    TextButton(onClick = {
                        probeErrors.remove(name)
                        scope.launch { ProbeStore.probeExit(name)?.let { probeErrors[name] = probeMessage(context, it) } }
                    }) {
                        if (name in running) CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.f2_probe_exit), fontSize = 12.sp)
                    }
                    TextButton(onClick = { probing = name }) { Text(stringResource(R.string.f2_probe_unlock), fontSize = 12.sp) }
                    Spacer(Modifier.weight(1f))
                    TextButton(onClick = { confirmDelete = name }) { Text(stringResource(R.string.delete), color = c.bad, fontSize = 12.sp) }
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_manual_probe_footer)) }
    }

    confirmDelete?.let { n ->
        ConfirmDialog(stringResource(R.string.f2_delete_q), n, stringResource(R.string.delete),
            onConfirm = { scope.launch { F2Core.io { ManualNodes.delete(n) }; changed() } }, onDismiss = { confirmDelete = null })
    }
    MessageDialog(message) { message = null }
}

fun probeMessage(context: android.content.Context, code: String): String = when (code) {
    "not_connected" -> context.getString(R.string.f2_probe_not_connected)
    "needs_reconnect" -> context.getString(R.string.f2_probe_needs_reconnect)
    "unknown_policy" -> context.getString(R.string.f2_probe_unknown_policy)
    "no_answer" -> context.getString(R.string.f2_probe_no_answer)
    else -> code
}

@Composable
private fun fieldLabel(code: String): String = when (code) {
    "transport" -> stringResource(R.string.f2_fl_transport)
    "ws_path" -> stringResource(R.string.f2_fl_ws_path)
    "ws_host" -> stringResource(R.string.f2_fl_ws_host)
    "grpc_service" -> stringResource(R.string.f2_fl_grpc_service)
    "skip_cert" -> stringResource(R.string.f2_fl_skip_cert)
    "tls_fp" -> stringResource(R.string.f2_fl_tls_fp)
    "cipher" -> stringResource(R.string.f2_fl_cipher)
    "password" -> stringResource(R.string.f2_fl_password)
    "plugin" -> stringResource(R.string.f2_fl_plugin)
    "plugin_mode" -> stringResource(R.string.f2_fl_plugin_mode)
    "plugin_host" -> stringResource(R.string.f2_fl_plugin_host)
    "plugin_path" -> stringResource(R.string.f2_fl_plugin_path)
    "shadowtls_password" -> stringResource(R.string.f2_fl_shadowtls_password)
    "shadowtls_version" -> stringResource(R.string.f2_fl_shadowtls_version)
    "udp" -> "UDP"
    "obfs" -> stringResource(R.string.f2_fl_obfs)
    "obfs_param" -> stringResource(R.string.f2_fl_obfs_param)
    "obfs_password" -> stringResource(R.string.f2_fl_obfs_password)
    "obfs_host" -> stringResource(R.string.f2_fl_obfs_host)
    "protocol" -> stringResource(R.string.f2_fl_protocol)
    "protocol_param" -> stringResource(R.string.f2_fl_protocol_param)
    "reality_pk" -> stringResource(R.string.f2_fl_reality_pk)
    "reality_sid" -> "Reality Short ID"
    "port_hopping" -> stringResource(R.string.f2_fl_port_hopping)
    "up_bw" -> stringResource(R.string.f2_fl_up_bw)
    "down_bw" -> stringResource(R.string.f2_fl_down_bw)
    "auth" -> stringResource(R.string.f2_fl_auth)
    "congestion" -> stringResource(R.string.f2_fl_congestion)
    "udp_relay" -> stringResource(R.string.f2_fl_udp_relay)
    "private_key" -> stringResource(R.string.f2_fl_private_key)
    "private_key_opt" -> stringResource(R.string.f2_fl_private_key_opt)
    "peer_public_key" -> stringResource(R.string.f2_fl_peer_public_key)
    "psk" -> stringResource(R.string.f2_fl_psk)
    "local_ipv4" -> stringResource(R.string.f2_fl_local_ipv4)
    "local_ipv6" -> stringResource(R.string.f2_fl_local_ipv6)
    "version" -> stringResource(R.string.f2_fl_version)
    "username" -> stringResource(R.string.f2_fl_username)
    "port_range" -> stringResource(R.string.f2_fl_port_range)
    "multiplexing" -> stringResource(R.string.f2_fl_multiplexing)
    "https_tls" -> stringResource(R.string.f2_fl_https_tls)
    "ech_config" -> stringResource(R.string.f2_fl_ech_config)
    "cert_fp" -> stringResource(R.string.f2_fl_cert_fp)
    "smux" -> stringResource(R.string.f2_fl_smux)
    "smux_protocol" -> stringResource(R.string.f2_fl_smux_protocol)
    "smux_max" -> stringResource(R.string.f2_fl_smux_max)
    "smux_padding" -> stringResource(R.string.f2_fl_smux_padding)
    "ip_version" -> stringResource(R.string.f2_fl_ip_version)
    else -> code
}

@Composable
private fun NodeEditor(original: JsonObject?, onBack: () -> Unit, onSaved: () -> Unit) {
    val c = LocalAppColors.current
    val scope = rememberCoroutineScope()
    val manualName = stringResource(R.string.f2_manual_profile_name)
    val origType = original?.str("type")?.ifEmpty { null }
    var type by remember { mutableStateOf(origType ?: "ss") }
    var name by remember { mutableStateOf(original?.str("name").orEmpty()) }
    var server by remember { mutableStateOf(original?.str("server").orEmpty()) }
    var port by remember { mutableStateOf(original?.str("port").orEmpty()) }
    var values by remember { mutableStateOf<Map<String, String>>(original?.let { NodeProtocols.flatten(it) } ?: NodeProtocols.defaults(type)) }
    var dialer by remember { mutableStateOf(original?.str("dialer-proxy").orEmpty()) }
    var showAdvanced by remember { mutableStateOf(NodeProtocols.advanced(type).any { f -> values[f.key].let { !it.isNullOrEmpty() && it != "false" } }) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var dialerCandidates by remember { mutableStateOf<List<String>>(emptyList()) }
    LaunchedEffect(Unit) {
        // 前置代理 resolves in the active profile when manual nodes are merged into it, else in the manual profile.
        val path = if (Overrides.load().mergeManual && F2Core.activePath != null && !ManualNodes.isActive) F2Core.activePath!! else ManualNodes.path
        dialerCandidates = F2Core.io { ChainCandidates.load(path, "node", original?.str("name") ?: name).candidates.map { it.name } }
    }

    @Composable
    fun field(f: FieldSpec) {
        val v = values[f.key].orEmpty()
        val label = fieldLabel(f.label)
        when (f.kind) {
            FieldSpec.Kind.BOOL -> SwitchRow(label, checked = v == "true") { on -> values = values + (f.key to on.toString()) }
            FieldSpec.Kind.CHOICE -> {
                val opts = (f.choices + listOfNotNull(v.takeIf { it.isNotEmpty() && it !in f.choices })).map { it to it.ifEmpty { stringResource(R.string.f2_none) } }
                ChoiceRow(label, opts, v) { values = values + (f.key to it) }
            }
            else -> F2Field(label, v, { values = values + (f.key to it) }, placeholder = f.placeholder,
                secure = f.kind == FieldSpec.Kind.SECURE, number = f.kind == FieldSpec.Kind.INT)
        }
    }

    F2Page(stringResource(if (original == null) R.string.f2_manual_add else R.string.f2_manual_edit), onBack, actions = {
        if (busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        else TextButton(enabled = server.isNotBlank() && port.isNotBlank(), onClick = {
            busy = true; error = null
            val node = NodeProtocols.build(original, type, name, server, port, values, dialer)
            scope.launch {
                runCatching { F2Core.io { ManualNodes.upsert(manualName, node, original?.str("name")) } }
                    .onSuccess { onSaved() }.onFailure { error = it.message }
                busy = false
            }
        }) { Text(stringResource(R.string.f2_save)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_basic)) }
        item {
            SettingsGroup {
                ChoiceRow(stringResource(R.string.f2_fl_protocol), NodeProtocols.all, type) { t ->
                    if (t != origType) values = NodeProtocols.defaults(t)
                    type = t
                }
                F2Field(stringResource(R.string.f2_name), name, { name = it })
                F2Field(stringResource(R.string.f2_server), server, { server = it })
                F2Field(stringResource(R.string.f2_port), port, { port = it.filter(Char::isDigit) }, number = true)
            }
        }
        item { SectionTitle((NodeProtocols.all.firstOrNull { it.first == type }?.second ?: type) + " · " + stringResource(R.string.f2_params)) }
        item { SettingsGroup { NodeProtocols.fields(type).forEach { field(it) } } }
        item {
            SettingsGroup(Modifier.padding(top = 12.dp)) {
                SwitchRow(stringResource(R.string.f2_advanced), checked = showAdvanced, showDivider = showAdvanced) { showAdvanced = it }
                if (showAdvanced) NodeProtocols.advanced(type).forEach { field(it) }
            }
        }
        if (showAdvanced) item { F2Footer(stringResource(R.string.f2_advanced_footer)) }
        item { SectionTitle(stringResource(R.string.f2_groups_via)) }
        item {
            SettingsGroup {
                ChoiceRow(stringResource(R.string.f2_groups_via), listOf("" to stringResource(R.string.f2_none)) +
                    (dialerCandidates + listOfNotNull(dialer.takeIf { it.isNotEmpty() && it !in dialerCandidates })).map { it to it },
                    dialer, showDivider = false) { dialer = it }
            }
        }
        item { F2Footer(stringResource(R.string.f2_manual_via_footer)) }
        error?.let { e -> item { Text(e, color = c.bad, fontSize = 13.sp, modifier = Modifier.padding(8.dp)) } }
        if (original != null) item {
            OutlinedButton(onClick = { values = NodeProtocols.flatten(original); type = origType ?: type }, modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                Text(stringResource(R.string.f2_revert))
            }
        }
    }
}
