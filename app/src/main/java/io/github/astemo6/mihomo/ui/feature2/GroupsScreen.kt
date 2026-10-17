package io.github.astemo6.mihomo.ui.feature2

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.mutableIntStateOf
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
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.data.feature2.ChainCandidates
import io.github.astemo6.mihomo.data.feature2.F2Api
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.data.feature2.GroupEdit
import io.github.astemo6.mihomo.data.feature2.GroupEditStore
import io.github.astemo6.mihomo.data.feature2.GroupEdits
import io.github.astemo6.mihomo.data.feature2.GroupSpec
import io.github.astemo6.mihomo.data.feature2.GroupSpecsResult
import io.github.astemo6.mihomo.data.feature2.InspectF2
import io.github.astemo6.mihomo.data.feature2.SmartGroupsStore
import io.github.astemo6.mihomo.data.feature2.SmartStatus
import io.github.astemo6.mihomo.data.feature2.SmartStatusResponse
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.launch

private val builtins = setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE")

@Composable
private fun groupTypes() = listOf(
    "select" to stringResource(R.string.f2_gt_select), "url-test" to stringResource(R.string.f2_gt_urltest),
    "fallback" to stringResource(R.string.f2_gt_fallback), "load-balance" to stringResource(R.string.f2_gt_lb),
)

private fun normType(t: String): String = when (t.lowercase()) {
    "selector", "select" -> "select"; "urltest", "url-test" -> "url-test"; "fallback" -> "fallback"
    "loadbalance", "load-balance" -> "load-balance"; "relay" -> "relay"; else -> t.lowercase()
}

/** 策略组编辑 (iOS GroupEditorView + SmartGroups). Edits go to <home>/group-edits.json per profile. */
@Composable
fun GroupsScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val active by ProfileStore.activeId.collectAsState()
    val vpn by VpnState.info.collectAsState()
    var inspect by remember { mutableStateOf(InspectF2()) }
    var edits by remember { mutableStateOf(GroupEdits()) }
    var smart by remember { mutableStateOf<Map<String, SmartStatus>>(emptyMap()) }
    var editing by remember { mutableStateOf<String?>(null) } // group name, "" = new
    var version by remember { mutableIntStateOf(0) }
    var loading by remember { mutableStateOf(true) }
    val reloadedMsg = stringResource(R.string.f2_saved_reloaded)

    LaunchedEffect(active, version, vpn.isRunning) {
        loading = true
        val p = ProfileStore.active
        if (p != null) {
            inspect = F2Core.io { InspectF2.load(p.file.absolutePath) }
            edits = F2Core.io { GroupEditStore.get(p.id) }
        }
        smart = if (vpn.isRunning) runCatching {
            AppJson.decodeFromString(SmartStatusResponse.serializer(), F2Api.get(listOf("smart"))).groups.associateBy { it.name }
        }.getOrDefault(emptyMap()) else emptyMap()
        loading = false
    }

    editing?.let { g ->
        BackHandler { editing = null }
        GroupEditor(if (g.isEmpty()) null else g, inspect, onBack = { editing = null }) {
            editing = null; version++
            if (F2Core.isConnected) { F2Core.reload(context); F2Util.toast(context, reloadedMsg) }
        }
        return
    }

    val profile = ProfileStore.active
    F2Page(stringResource(R.string.f2_groups_title), onBack, actions = {
        if (profile != null) IconButton(onClick = { editing = "" }) { Icon(Icons.Default.Add, stringResource(R.string.f2_groups_new)) }
    }) {
        if (profile == null) { item { EmptyHint(stringResource(R.string.f2_no_profile)) }; return@F2Page }
        item { SectionTitle(stringResource(R.string.f2_groups_n, inspect.groups.count { it.name != F2Core.PROBE_GROUP }) + " · " + profile.name) }
        if (loading && inspect.groups.isEmpty()) item { CircularProgressIndicator(Modifier.padding(16.dp)) }
        val renamed = edits.edits.orEmpty().mapNotNull { (orig, e) -> e.spec?.name?.let { it to orig } }.toMap()
        items(inspect.groups.filter { it.name != F2Core.PROBE_GROUP }, key = { it.name }) { g ->
            val t = normType(g.type)
            val orig = renamed[g.name] ?: g.name
            val isAdded = edits.added.orEmpty().any { it.name == g.name }
            val isEdited = edits.edits?.containsKey(orig) == true
            AppCard(Modifier.padding(bottom = 8.dp).clickable { editing = g.name }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(g.name, fontSize = 15.sp, color = c.text, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f, fill = false))
                            Spacer(Modifier.width(6.dp))
                            if (isAdded) Tag(stringResource(R.string.f2_groups_added), c.good)
                            else if (isEdited) Tag(stringResource(R.string.f2_groups_edited), c.warn)
                            if (g.hidden) { Spacer(Modifier.width(4.dp)); Tag(stringResource(R.string.f2_hidden), c.secondary) }
                        }
                        Text(listOfNotNull(groupTypes().firstOrNull { it.first == t }?.second ?: g.type,
                            stringResource(R.string.f2_members_n, g.proxies.orEmpty().size),
                            g.use?.takeIf { it.isNotEmpty() }?.let { stringResource(R.string.f2_providers_n, it.size) }).joinToString(" · "),
                            fontSize = 11.sp, color = c.secondary)
                        if (SmartGroupsStore.isSmart(profile.id, g.name)) {
                            val st = smart[g.name]
                            val cur = st?.pinned ?: st?.now
                            val m = st?.members?.firstOrNull { it.name == cur }
                            Text(when {
                                st?.members.isNullOrEmpty() -> stringResource(R.string.f2_smart_waiting)
                                m != null && m.score >= 0 -> stringResource(R.string.f2_smart_summary, cur ?: "", m.avg, m.fails, m.count)
                                else -> stringResource(R.string.f2_smart_nodata, st?.now ?: "—")
                            }, fontSize = 11.sp, color = c.accent)
                        }
                    }
                    if (t == "url-test" || t == "fallback") {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(stringResource(R.string.f2_smart), fontSize = 10.sp, color = c.secondary)
                            Switch(checked = SmartGroupsStore.isSmart(profile.id, g.name), onCheckedChange = { on ->
                                scope.launch {
                                    F2Core.io { SmartGroupsStore.setSmart(profile.id, g.name, on) }
                                    if (F2Core.isConnected) F2Core.reload(context)
                                    version++
                                }
                            })
                        }
                    }
                }
            }
        }
        val deleted = edits.edits.orEmpty().filter { it.value.deleted == true }.keys
        if (deleted.isNotEmpty()) {
            item { SectionTitle(stringResource(R.string.f2_groups_deleted)) }
            item {
                SettingsGroup {
                    deleted.forEachIndexed { i, n ->
                        SettingsRow(n, showDivider = i < deleted.size - 1, trailing = {
                            TextButton(onClick = {
                                scope.launch {
                                    val e = edits.copy(edits = edits.edits.orEmpty() - n)
                                    F2Core.io { GroupEditStore.set(profile.id, e) }
                                    version++
                                    if (F2Core.isConnected) F2Core.reload(context)
                                }
                            }) { Text(stringResource(R.string.f2_restore)) }
                        })
                    }
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_groups_footer)) }
    }
}

@Composable
private fun GroupEditor(groupName: String?, inspect: InspectF2, onBack: () -> Unit, onSaved: () -> Unit) {
    val c = LocalAppColors.current
    val scope = rememberCoroutineScope()
    val profile = ProfileStore.active
    if (profile == null) { LaunchedEffect(Unit) { onBack() }; return }
    var specs by remember { mutableStateOf(GroupSpecsResult()) }
    var edits by remember { mutableStateOf(GroupEdits()) }
    var originalName by remember { mutableStateOf<String?>(null) }
    var addedIndex by remember { mutableStateOf<Int?>(null) }
    var spec by remember { mutableStateOf(GroupSpec(name = "")) }
    var loaded by remember { mutableStateOf(false) }
    var picking by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var saving by remember { mutableStateOf(false) }
    var via by remember { mutableStateOf<String?>(null) }
    var viaCandidates by remember { mutableStateOf<List<String>>(emptyList()) }
    val context = LocalContext.current
    val newName = stringResource(R.string.f2_groups_new_name)
    val copySuffix = stringResource(R.string.f2_copy_suffix)
    val errEmptyName = stringResource(R.string.f2_err_empty_name)
    val errClash = stringResource(R.string.f2_err_name_clash)

    LaunchedEffect(groupName) {
        specs = F2Core.io { GroupEditStore.specs(profile.file.absolutePath) }
        edits = F2Core.io { GroupEditStore.get(profile.id) }
        if (groupName != null) {
            val ai = edits.added.orEmpty().indexOfFirst { it.name == groupName }
            val hit = edits.edits.orEmpty().entries.firstOrNull { it.value.spec?.name == groupName }
            when {
                ai >= 0 -> { addedIndex = ai; spec = edits.added!![ai] }
                hit?.value?.spec != null -> { originalName = hit.key; spec = hit.value.spec!! }
                else -> {
                    originalName = groupName
                    spec = specs.groups.firstOrNull { it.name == groupName } ?: GroupSpec(name = groupName)
                }
            }
            via = SmartGroupsStore.via(profile.id, originalName ?: groupName)
            viaCandidates = F2Core.io { ChainCandidates.load(profile.file.absolutePath, "group", groupName).candidates.map { it.name } }
        } else spec = GroupSpec(name = newName)
        loaded = true
    }

    val candidates = (listOf("DIRECT", "REJECT") + specs.groups.map { it.name }.filter { it != spec.name && it != groupName } +
        edits.added.orEmpty().map { it.name }.filter { it != spec.name } + specs.proxies).distinct()
    fun memberKind(m: String): Int = when {
        m.uppercase() in builtins -> R.string.f2_kind_builtin
        specs.groups.any { it.name == m } || edits.added.orEmpty().any { it.name == m } -> R.string.f2_kind_group
        else -> R.string.f2_kind_node
    }

    fun candidate(): GroupEdits {
        val s = spec.copy(name = spec.name.trim())
        val ai = addedIndex
        val o = originalName
        return when {
            ai != null -> edits.copy(added = edits.added.orEmpty().toMutableList().also { it[ai] = s })
            o != null -> edits.copy(edits = edits.edits.orEmpty() + (o to GroupEdit(spec = s)))
            else -> edits.copy(added = edits.added.orEmpty() + s)
        }
    }

    fun persist(e: GroupEdits) {
        saving = true
        scope.launch {
            val err = F2Core.io { F2Core.groupEditCheck(profile.file.absolutePath, GroupEditStore.json(e)) }
            if (err.isNotEmpty()) { message = err; saving = false; return@launch }
            F2Core.io { GroupEditStore.set(profile.id, e) }
            saving = false
            onSaved()
        }
    }

    val previewNodes: List<String> = run {
        val pool = mutableListOf<String>()
        if (spec.includeAll == true) pool += inspect.proxies.map { it.name }
        inspect.proxyProviders.filter { spec.includeAll == true || spec.use.orEmpty().contains(it.name) }
            .forEach { pv -> pool += pv.proxies.orEmpty().map { it.name } }
        fun matches(p: String?, s: String): Boolean? {
            if (p.isNullOrEmpty()) return null
            return p.split('`').any { part -> runCatching { Regex(part).containsMatchIn(s) }.getOrDefault(false) }
        }
        pool.distinct().filter { n -> matches(spec.filter, n) != false && matches(spec.excludeFilter, n) != true }
    }
    val routed = inspect.rules.filter { it.proxy == (groupName ?: spec.name) }

    F2Page(stringResource(if (groupName == null) R.string.f2_groups_new else R.string.f2_groups_edit), onBack, actions = {
        if (saving) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
        else TextButton(enabled = loaded, onClick = {
            val name = spec.name.trim()
            if (name.isEmpty()) { message = errEmptyName; return@TextButton }
            val clash = name != groupName && ((specs.groups.any { it.name == name } && name != originalName) ||
                edits.added.orEmpty().withIndex().any { it.value.name == name && it.index != addedIndex } || specs.proxies.contains(name))
            if (clash) { message = errClash; return@TextButton }
            persist(candidate())
        }) { Text(stringResource(R.string.f2_save)) }
    }) {
        if (!loaded) { item { CircularProgressIndicator(Modifier.padding(16.dp)) }; return@F2Page }
        item { SectionTitle(stringResource(R.string.f2_basic)) }
        item {
            SettingsGroup {
                F2Field(stringResource(R.string.f2_name), spec.name, { spec = spec.copy(name = it) })
                ChoiceRow(stringResource(R.string.f2_type), groupTypes(), spec.type) { spec = spec.copy(type = it) }
                F2Field(stringResource(R.string.f2_groups_icon), spec.icon.orEmpty(), { spec = spec.copy(icon = it.ifEmpty { null }) })
                SwitchRow(stringResource(R.string.f2_hidden), checked = spec.hidden == true, showDivider = false) { spec = spec.copy(hidden = if (it) true else null) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_members_n, spec.proxies.size)) }
        item {
            SettingsGroup {
                spec.proxies.forEachIndexed { i, m ->
                    Row(Modifier.padding(start = 14.dp, end = 4.dp, top = 4.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(m, fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(stringResource(memberKind(m)), fontSize = 10.sp, color = c.secondary)
                        IconButton(enabled = i > 0, onClick = { spec = spec.copy(proxies = spec.proxies.toMutableList().also { it.add(i - 1, it.removeAt(i)) }) }) {
                            Icon(Icons.Default.KeyboardArrowUp, null)
                        }
                        IconButton(enabled = i < spec.proxies.size - 1, onClick = { spec = spec.copy(proxies = spec.proxies.toMutableList().also { it.add(i + 1, it.removeAt(i)) }) }) {
                            Icon(Icons.Default.KeyboardArrowDown, null)
                        }
                        IconButton(onClick = { spec = spec.copy(proxies = spec.proxies.filterIndexed { j, _ -> j != i }) }) { Icon(Icons.Default.Close, null, tint = c.bad) }
                    }
                    HorizontalDivider(color = c.separator, thickness = 0.5.dp)
                }
                TextButton(onClick = { picking = true }, modifier = Modifier.padding(start = 6.dp)) { Text("+ " + stringResource(R.string.f2_groups_add_member)) }
            }
        }
        item { F2Footer(stringResource(R.string.f2_groups_members_footer)) }
        item { SectionTitle(stringResource(R.string.f2_groups_providers_filter)) }
        item {
            SettingsGroup {
                if (specs.providers.isEmpty()) Text(stringResource(R.string.f2_groups_no_providers), fontSize = 12.sp, color = c.secondary,
                    modifier = Modifier.padding(14.dp))
                specs.providers.sorted().forEach { p ->
                    SwitchRow(p, checked = spec.use.orEmpty().contains(p)) { on ->
                        val u = spec.use.orEmpty().filter { it != p } + if (on) listOf(p) else emptyList()
                        spec = spec.copy(use = u.ifEmpty { null })
                    }
                }
                SwitchRow(stringResource(R.string.f2_groups_include_all), checked = spec.includeAll == true) { spec = spec.copy(includeAll = if (it) true else null) }
                F2Field(stringResource(R.string.f2_groups_filter), spec.filter.orEmpty(), { spec = spec.copy(filter = it.ifEmpty { null }) }, mono = true)
                F2Field(stringResource(R.string.f2_groups_exclude), spec.excludeFilter.orEmpty(), { spec = spec.copy(excludeFilter = it.ifEmpty { null }) }, mono = true)
                Column(Modifier.padding(horizontal = 14.dp, vertical = 8.dp)) {
                    Text(stringResource(R.string.f2_groups_matches_n, previewNodes.size), fontSize = 12.sp, color = c.text, fontWeight = FontWeight.SemiBold)
                    if (previewNodes.isNotEmpty()) Text(previewNodes.take(12).joinToString(" · "), fontSize = 11.sp, color = c.secondary, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_groups_filter_footer)) }
        if (spec.type != "select") {
            item { SectionTitle(stringResource(R.string.f2_groups_test)) }
            item {
                SettingsGroup {
                    F2Field(stringResource(R.string.f2_groups_test_url), spec.url.orEmpty(), { spec = spec.copy(url = it.ifEmpty { null }) },
                        placeholder = stringResource(R.string.f2_default))
                    F2Field(stringResource(R.string.f2_groups_interval), (spec.interval ?: 300).toString(),
                        { v -> spec = spec.copy(interval = v.filter(Char::isDigit).toIntOrNull()?.coerceIn(30, 86400)) }, number = true)
                    if (spec.type == "url-test") F2Field(stringResource(R.string.f2_groups_tolerance), (spec.tolerance ?: 0).toString(),
                        { v -> spec = spec.copy(tolerance = v.filter(Char::isDigit).toIntOrNull()?.takeIf { it > 0 }) }, number = true)
                    SwitchRow(stringResource(R.string.f2_groups_lazy), checked = spec.lazy ?: true) { spec = spec.copy(lazy = it) }
                    if (spec.type == "load-balance") ChoiceRow(stringResource(R.string.f2_groups_strategy), listOf(
                        "consistent-hashing" to stringResource(R.string.f2_lb_hash), "round-robin" to stringResource(R.string.f2_lb_rr),
                        "sticky-sessions" to stringResource(R.string.f2_lb_sticky)), spec.strategy ?: "consistent-hashing", showDivider = false) {
                        spec = spec.copy(strategy = it)
                    }
                }
            }
        }
        if (groupName != null) {
            item { SectionTitle(stringResource(R.string.f2_groups_via)) }
            item {
                SettingsGroup {
                    ChoiceRow(stringResource(R.string.f2_groups_via), listOf("" to stringResource(R.string.f2_none)) + viaCandidates.map { it to it },
                        via.orEmpty(), showDivider = false) { v ->
                        scope.launch {
                            val err = F2Core.io { F2Core.setGroupChain(profile.file.absolutePath, groupName, v) }
                            if (err.isNotEmpty()) message = err else {
                                via = v.ifEmpty { null }
                                if (F2Core.isConnected) F2Core.reload(context)
                            }
                        }
                    }
                }
            }
            item { F2Footer(stringResource(R.string.f2_groups_via_footer)) }
            item { SectionTitle(stringResource(R.string.f2_groups_routed_n, routed.size)) }
            item {
                AppCard {
                    if (routed.isEmpty()) Text(stringResource(R.string.f2_groups_no_routed), fontSize = 12.sp, color = c.secondary)
                    routed.take(30).forEach { r -> Text("${r.type},${r.payload}", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = c.text, maxLines = 1) }
                    if (routed.size > 30) Text(stringResource(R.string.f2_more_n, routed.size - 30), fontSize = 11.sp, color = c.secondary)
                }
            }
            item {
                Column(Modifier.padding(top = 12.dp)) {
                    OutlinedButton(onClick = {
                        val taken = (candidates + spec.name).toSet()
                        var n = spec.name + " " + copySuffix
                        var k = 2
                        while (n in taken) { n = spec.name + " " + copySuffix + " " + k; k++ }
                        val s = spec.copy(name = n)
                        edits = edits.copy(added = edits.added.orEmpty() + s)
                        addedIndex = edits.added!!.size - 1
                        originalName = null
                        spec = s
                    }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.f2_groups_duplicate)) }
                    originalName?.takeIf { edits.edits?.containsKey(it) == true }?.let { o ->
                        OutlinedButton(onClick = { persist(edits.copy(edits = edits.edits.orEmpty() - o)) }, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.f2_groups_restore))
                        }
                    }
                    OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.f2_groups_delete), color = c.bad)
                    }
                }
            }
        }
    }

    if (picking) MultiPickDialog(stringResource(R.string.f2_groups_add_member), candidates.filter { it !in spec.proxies }, emptySet(),
        onDismiss = { picking = false }) { picked -> spec = spec.copy(proxies = spec.proxies + picked.filter { it !in spec.proxies }) }
    if (confirmDelete) ConfirmDialog(stringResource(R.string.f2_groups_delete_q, spec.name),
        if (routed.isEmpty()) stringResource(R.string.f2_groups_delete_refs) else stringResource(R.string.f2_groups_delete_rules, routed.size),
        stringResource(R.string.delete), onConfirm = {
            val ai = addedIndex
            val o = originalName
            val e = when {
                ai != null -> edits.copy(added = edits.added.orEmpty().filterIndexed { i, _ -> i != ai })
                o != null -> edits.copy(edits = edits.edits.orEmpty() + (o to GroupEdit(deleted = true)))
                else -> edits
            }
            persist(e)
        }, onDismiss = { confirmDelete = false })
    MessageDialog(message) { message = null }
}
