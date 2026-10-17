package io.github.astemo6.mihomo.ui.feature2

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.api.ProviderItem
import io.github.astemo6.mihomo.data.feature2.CustomRule
import io.github.astemo6.mihomo.data.feature2.CustomRulesStore
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.data.feature2.RuleCheck
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private sealed interface RulesEditing {
    data class One(val rule: CustomRule?) : RulesEditing
    data object Remote : RulesEditing
    data object Bulk : RulesEditing
}

/**
 * 规则列表 / 自定义规则 (iOS RulesView 自定义 + CustomRuleEditor): <home>/rules.json. Single lines in Surge /
 * QX / Loon / mihomo syntax and remote QX / Surge / Clash rule lists, which the bridge turns into remote
 * rule-providers (downloaded and converted by the core through /rules/convert) with the chosen policy.
 */
@Composable
fun RuleSetsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val c = LocalAppColors.current
    var rules by remember { mutableStateOf(CustomRulesStore.load()) }
    var checks by remember { mutableStateOf<Map<String, RuleCheck>>(emptyMap()) }
    var editing by remember { mutableStateOf<RulesEditing?>(null) }
    var providers by remember { mutableStateOf<List<ProviderItem>>(emptyList()) }
    var confirmDelete by remember { mutableStateOf<CustomRule?>(null) }
    val vpn by VpnState.info.collectAsState()
    val reloadedMsg = stringResource(R.string.f2_saved_reloaded)
    val savedMsg = stringResource(R.string.f2_saved_next_connect)

    suspend fun recheck() { checks = F2Core.io { CustomRulesStore.checks() } }
    suspend fun loadProviders() {
        providers = if (F2Core.isConnected) runCatching { ControllerClient.ruleProviders() }.getOrDefault(emptyList()) else emptyList()
    }

    fun persist(n: List<CustomRule>) {
        rules = n
        scope.launch {
            F2Core.io { CustomRulesStore.save(n) }
            recheck()
            if (F2Core.isConnected) {
                F2Core.reload(context)
                F2Util.toast(context, reloadedMsg)
                delay(2500); loadProviders()
            } else F2Util.toast(context, savedMsg)
        }
    }

    LaunchedEffect(vpn.isRunning) { recheck(); loadProviders() }

    when (val e = editing) {
        is RulesEditing.One -> {
            BackHandler { editing = null }
            RuleLineEditor(e.rule, onBack = { editing = null }) { r ->
                editing = null
                persist(if (rules.any { it.id == r.id }) rules.map { if (it.id == r.id) r else it } else rules + r)
            }
            return
        }
        RulesEditing.Remote -> {
            BackHandler { editing = null }
            RemoteListEditor(onBack = { editing = null }) { r -> editing = null; persist(rules + r) }
            return
        }
        RulesEditing.Bulk -> {
            BackHandler { editing = null }
            BulkRulesEditor(onBack = { editing = null }) { list -> editing = null; persist(rules + list) }
            return
        }
        null -> {}
    }

    F2Page(stringResource(R.string.f2_rulesets_title), onBack, actions = {
        IconButton(onClick = { editing = RulesEditing.Bulk }) { Icon(Icons.Default.ContentPaste, stringResource(R.string.f2_rules_bulk)) }
        IconButton(onClick = { editing = RulesEditing.One(null) }) { Icon(Icons.Default.Add, stringResource(R.string.f2_rules_add)) }
    }) {
        item {
            Row(Modifier.fillMaxWidth().padding(top = 4.dp)) {
                Button(onClick = { editing = RulesEditing.Remote }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.f2_rules_import_remote)) }
                Spacer(Modifier.width(8.dp))
                OutlinedButton(onClick = { editing = RulesEditing.One(null) }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.f2_rules_add)) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_rules_custom_n, rules.size)) }
        if (rules.isEmpty()) item { AppCard { Text(stringResource(R.string.f2_rules_empty), fontSize = 13.sp, color = c.secondary) } }
        else item {
            SettingsGroup {
                rules.forEachIndexed { i, r ->
                    CustomRuleRow(r, checks[r.id],
                        onToggle = { on -> persist(rules.map { if (it.id == r.id) it.copy(enabled = on) else it }) },
                        onEdit = { editing = RulesEditing.One(r) },
                        onUp = if (i > 0) ({ persist(rules.toMutableList().also { l -> l.add(i - 1, l.removeAt(i)) }) }) else null,
                        onDown = if (i < rules.size - 1) ({ persist(rules.toMutableList().also { l -> l.add(i + 1, l.removeAt(i)) }) }) else null,
                        onDelete = { confirmDelete = r })
                    if (i < rules.size - 1) HorizontalDivider(color = c.separator, thickness = 0.5.dp)
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_rules_footer)) }
        if (vpn.isRunning) {
            item {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    SectionTitle(stringResource(R.string.f2_rules_providers_n, providers.size), Modifier.weight(1f))
                    IconButton(onClick = { scope.launch { loadProviders() } }) { Icon(Icons.Default.Refresh, null, tint = c.secondary) }
                }
            }
            if (providers.isEmpty()) item { EmptyHint(stringResource(R.string.f2_none)) }
            items(providers, key = { it.name }) { p ->
                AppCard(Modifier.padding(bottom = 8.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(p.name, fontSize = 14.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(listOfNotNull(p.behavior, p.vehicleType, p.ruleCount?.let { context.getString(R.string.f2_n_rules, it) },
                                p.updatedAt?.take(19)?.replace('T', ' ')).joinToString(" · "), fontSize = 11.sp, color = c.secondary)
                        }
                        TextButton(onClick = {
                            scope.launch {
                                runCatching { ControllerClient.updateRuleProvider(p.name) }
                                    .onFailure { F2Util.toast(context, it.message ?: "") }
                                loadProviders()
                            }
                        }) { Text(stringResource(R.string.f2_update)) }
                    }
                }
            }
        }
    }

    confirmDelete?.let { r ->
        ConfirmDialog(stringResource(R.string.f2_delete_q), r.line, stringResource(R.string.delete),
            onConfirm = { persist(rules.filterNot { it.id == r.id }) }, onDismiss = { confirmDelete = null })
    }
}

@Composable
private fun CustomRuleRow(
    r: CustomRule,
    check: RuleCheck?,
    onToggle: (Boolean) -> Unit,
    onEdit: () -> Unit,
    onUp: (() -> Unit)?,
    onDown: (() -> Unit)?,
    onDelete: () -> Unit,
) {
    val c = LocalAppColors.current
    Row(Modifier.fillMaxWidth().clickable(onClick = onEdit).padding(start = 12.dp, end = 4.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (r.isRemote) { Tag(stringResource(R.string.f2_rules_remote_tag), c.accent); Spacer(Modifier.width(6.dp)) }
                Text(r.line, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = if (r.enabled) c.text else c.secondary,
                    maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            RuleCheckLine(check)
        }
        Column {
            if (onUp != null) Icon(Icons.Default.KeyboardArrowUp, null, tint = c.secondary, modifier = Modifier.clickable(onClick = onUp))
            if (onDown != null) Icon(Icons.Default.KeyboardArrowDown, null, tint = c.secondary, modifier = Modifier.clickable(onClick = onDown))
        }
        Switch(checked = r.enabled, onCheckedChange = onToggle)
        TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = c.bad, fontSize = 12.sp) }
    }
}

@Composable
fun RuleCheckLine(check: RuleCheck?) {
    val c = LocalAppColors.current
    if (check == null) return
    when {
        !check.error.isNullOrEmpty() -> Text(check.error, fontSize = 11.sp, color = c.bad)
        !check.rule.isNullOrEmpty() -> Text("→ ${check.rule}" + (check.policy?.let { "  ($it)" } ?: ""), fontSize = 11.sp,
            color = c.good, fontFamily = FontFamily.Monospace, maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
    if (!check.note.isNullOrEmpty()) Text(check.note, fontSize = 11.sp, color = c.warn)
}

private val examples = listOf(
    "DOMAIN-SUFFIX,google.com,Proxy",
    "DOMAIN-KEYWORD,openai,Proxy",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT",
    "host-suffix, apple.com, direct",
    "RULE-SET,https://example.com/ad.list,REJECT",
    "DOMAIN-SET,https://example.com/cdn.txt,DIRECT",
    "https://example.com/x.list, tag=x, force-policy=Proxy",
)

@Composable
private fun intervalOptions(): List<Pair<String, String>> = listOf(
    "21600" to stringResource(R.string.f2_hours_n, 6), "43200" to stringResource(R.string.f2_hours_n, 12),
    "86400" to stringResource(R.string.f2_days_n, 1), "604800" to stringResource(R.string.f2_days_n, 7),
)

@Composable
private fun RuleLineEditor(initial: CustomRule?, onBack: () -> Unit, onSave: (CustomRule) -> Unit) {
    var line by remember { mutableStateOf(initial?.line.orEmpty()) }
    var interval by remember { mutableStateOf(initial?.interval ?: 86400) }
    var check by remember { mutableStateOf<RuleCheck?>(null) }
    LaunchedEffect(line) {
        val l = line.trim()
        if (l.isEmpty()) { check = null; return@LaunchedEffect }
        delay(300)
        check = F2Core.io { CustomRulesStore.check(l) }
    }
    val canSave = line.isNotBlank() && check?.error.isNullOrEmpty()
    F2Page(stringResource(R.string.f2_rules_edit_title), onBack, actions = {
        TextButton(enabled = canSave, onClick = {
            val l = line.trim()
            onSave((initial ?: CustomRule(line = l)).copy(line = l, interval = if (l.contains("://")) interval else null))
        }) { Text(stringResource(R.string.f2_save)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_rule)) }
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_rule), line, { line = it }, singleLine = false, mono = true, minLines = 2)
                Column(Modifier.padding(horizontal = 14.dp, vertical = 6.dp)) { RuleCheckLine(check) }
            }
        }
        item { F2Footer(stringResource(R.string.f2_rules_live_check)) }
        if (line.contains("://")) {
            item { SectionTitle(stringResource(R.string.f2_rules_interval)) }
            item {
                SettingsGroup {
                    ChoiceRow(stringResource(R.string.f2_rules_interval), intervalOptions(), interval.toString(), showDivider = false) {
                        interval = it.toInt()
                    }
                }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_examples)) }
        item {
            SettingsGroup {
                examples.forEach { ex ->
                    Text(ex, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = LocalAppColors.current.secondary,
                        modifier = Modifier.fillMaxWidth().clickable { line = ex }.padding(horizontal = 14.dp, vertical = 9.dp))
                }
            }
        }
    }
}

/** Remote QX / Surge / Clash list → one remote rule line with the chosen policy. */
@Composable
private fun RemoteListEditor(onBack: () -> Unit, onSave: (CustomRule) -> Unit) {
    var url by remember { mutableStateOf("") }
    var format by remember { mutableStateOf("list") }
    var policy by remember { mutableStateOf("") }
    var tag by remember { mutableStateOf("") }
    var interval by remember { mutableStateOf(86400) }
    var groups by remember { mutableStateOf<List<String>>(emptyList()) }
    var check by remember { mutableStateOf<RuleCheck?>(null) }
    LaunchedEffect(Unit) {
        groups = F2Core.io { CustomRulesStore.profileGroups() }
        if (policy.isEmpty()) policy = groups.firstOrNull() ?: "DIRECT"
    }
    val u = url.trim()
    val line = when (format) {
        "domainset" -> "DOMAIN-SET,$u,$policy"
        "qx" -> listOfNotNull(u, tag.trim().takeIf { it.isNotEmpty() }?.let { "tag=$it" }, "force-policy=$policy",
            "update-interval=$interval", "enabled=true").joinToString(", ")
        else -> "RULE-SET,$u,$policy"
    }
    LaunchedEffect(line) {
        if (!u.startsWith("http")) { check = null; return@LaunchedEffect }
        delay(300)
        check = F2Core.io { CustomRulesStore.check(line) }
    }
    val canSave = (u.startsWith("http://") || u.startsWith("https://")) && policy.isNotEmpty() && check?.error.isNullOrEmpty()
    val clip = LocalContext.current
    F2Page(stringResource(R.string.f2_rules_import_remote), onBack, actions = {
        TextButton(enabled = canSave, onClick = { onSave(CustomRule(line = line, interval = interval)) }) { Text(stringResource(R.string.f2_save)) }
    }) {
        item { SectionTitle(stringResource(R.string.f2_rules_list_url)) }
        item {
            SettingsGroup {
                F2Field("URL", url, { url = it }, placeholder = "https://…/rules.list")
                TextButton(onClick = { F2Util.paste(clip).trim().takeIf { it.startsWith("http") }?.let { url = it } },
                    modifier = Modifier.padding(start = 6.dp)) { Text(stringResource(R.string.f2_paste)) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_rules_format)) }
        item {
            SettingsGroup {
                ChoiceRow(stringResource(R.string.f2_rules_format), listOf(
                    "list" to stringResource(R.string.f2_rules_fmt_list),
                    "domainset" to stringResource(R.string.f2_rules_fmt_domainset),
                    "qx" to stringResource(R.string.f2_rules_fmt_qx),
                ), format) { format = it }
                ChoiceRow(stringResource(R.string.f2_policy), (groups + listOf("DIRECT", "REJECT", "REJECT-DROP")).distinct().map { it to it }, policy) { policy = it }
                if (format == "qx") F2Field(stringResource(R.string.f2_rules_tag), tag, { tag = it })
                ChoiceRow(stringResource(R.string.f2_rules_interval), intervalOptions(), interval.toString(), showDivider = false) { interval = it.toInt() }
            }
        }
        item { F2Footer(stringResource(R.string.f2_rules_remote_footer)) }
        item { SectionTitle(stringResource(R.string.f2_preview)) }
        item {
            AppCard {
                Text(line, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = LocalAppColors.current.text)
                RuleCheckLine(check)
            }
        }
    }
}

/** Paste many lines at once (e.g. a Surge [Rule] section or a QX filter_remote block). */
@Composable
private fun BulkRulesEditor(onBack: () -> Unit, onSave: (List<CustomRule>) -> Unit) {
    var text by remember { mutableStateOf("") }
    val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith(";") && !it.startsWith("//") && !it.startsWith("[") }
    F2Page(stringResource(R.string.f2_rules_bulk), onBack, actions = {
        TextButton(enabled = lines.isNotEmpty(), onClick = { onSave(lines.map { CustomRule(line = it) }) }) {
            Text(stringResource(R.string.f2_add_n, lines.size))
        }
    }) {
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_rules_bulk_hint), text, { text = it }, singleLine = false, mono = true, minLines = 8)
            }
        }
        item { F2Footer(stringResource(R.string.f2_rules_bulk_footer)) }
    }
}
