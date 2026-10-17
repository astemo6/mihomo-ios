package io.github.astemo6.mihomo.ui.feature2

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
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
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.feature2.CustomRule
import io.github.astemo6.mihomo.data.feature2.CustomRulesStore
import io.github.astemo6.mihomo.data.feature2.DnsAnswer
import io.github.astemo6.mihomo.data.feature2.DnsLog
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnState
import kotlinx.coroutines.launch

/** DNS 查询日志 / 被拦截的域名 / DNS 查询工具 (core /logs at debug level + /dns/query). */
@Composable
fun DnsLogScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val vpn by VpnState.info.collectAsState()
    val queries by DnsLog.queries.collectAsState()
    val blocked by DnsLog.blocked.collectAsState()
    val paused by DnsLog.paused.collectAsState()
    var tab by remember { mutableStateOf(0) }
    var filter by remember { mutableStateOf("") }
    var lookupName by remember { mutableStateOf("") }
    var lookupType by remember { mutableStateOf("A") }
    var answers by remember { mutableStateOf<List<DnsAnswer>?>(null) }
    var lookupErr by remember { mutableStateOf<String?>(null) }
    val fakeIp = remember { Overrides.load().dnsMode == "fake-ip" }
    val addedMsg = stringResource(R.string.f2_dns_rule_added)

    F2Page(stringResource(R.string.f2_dns_title), onBack, actions = {
        IconButton(onClick = { DnsLog.setPaused(!paused) }) {
            Icon(if (paused) Icons.Default.PlayArrow else Icons.Default.Pause, stringResource(R.string.f2_pause))
        }
        IconButton(onClick = { DnsLog.clear() }) { Icon(Icons.Default.Delete, stringResource(R.string.f2_clear)) }
    }) {
        item {
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
                listOf(stringResource(R.string.f2_dns_tab_queries, queries.size), stringResource(R.string.f2_dns_tab_blocked, blocked.size),
                    stringResource(R.string.f2_dns_tab_lookup)).forEachIndexed { i, t ->
                    SegmentedButton(selected = tab == i, onClick = { tab = i }, shape = SegmentedButtonDefaults.itemShape(i, 3)) {
                        Text(t, fontSize = 12.sp, maxLines = 1)
                    }
                }
            }
        }
        if (!vpn.isRunning && tab != 2) item { AppCard { Text(stringResource(R.string.f2_need_connect), fontSize = 13.sp, color = c.secondary) } }
        if (tab != 2) item { F2Field(stringResource(R.string.f2_filter), filter, { filter = it }) }
        when (tab) {
            0 -> {
                if (fakeIp) item { F2Footer(stringResource(R.string.f2_dns_fakeip_note)) }
                val list = queries.asReversed().filter { filter.isBlank() || it.domain.contains(filter, true) || it.answers.any { a -> a.contains(filter) } }
                if (list.isEmpty()) item { EmptyHint(stringResource(R.string.f2_dns_no_queries)) }
                items(list.take(400), key = { it.id }) { q ->
                    AppCard(Modifier.padding(top = 6.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(q.domain, fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (q.qtype.isNotEmpty()) Tag(q.qtype, c.accent)
                            if (q.cached) { Spacer(Modifier.width(4.dp)); Tag(stringResource(R.string.f2_dns_cached), c.good) }
                        }
                        if (q.error != null) Text(q.error, fontSize = 11.sp, color = c.bad)
                        else Text(q.answers.joinToString(", ").ifEmpty { "—" }, fontSize = 12.sp, color = c.secondary, fontFamily = FontFamily.Monospace,
                            maxLines = 3, overflow = TextOverflow.Ellipsis)
                        Text(listOfNotNull(Fmt.time(q.time), q.server).joinToString(" · "), fontSize = 10.sp, color = c.secondary)
                    }
                }
            }
            1 -> {
                item { F2Footer(stringResource(R.string.f2_dns_blocked_note)) }
                val list = blocked.values.sortedByDescending { it.last }.filter { filter.isBlank() || it.domain.contains(filter, true) }
                if (list.isEmpty()) item { EmptyHint(stringResource(R.string.f2_dns_no_blocked)) }
                items(list, key = { it.domain }) { b ->
                    AppCard(Modifier.padding(top = 6.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(b.domain, fontSize = 14.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(listOf(b.rule.ifEmpty { "—" }, b.policy, stringResource(R.string.f2_times_n, b.count), Fmt.time(b.last))
                                    .joinToString(" · "), fontSize = 11.sp, color = c.secondary, maxLines = 2)
                            }
                            TextButton(onClick = {
                                // 放行: a DIRECT rule for the exact domain, placed before the profile's rules.
                                scope.launch {
                                    val l = CustomRulesStore.load()
                                    F2Core.io { CustomRulesStore.save(listOf(CustomRule(line = "DOMAIN,${b.domain},DIRECT")) + l) }
                                    F2Core.reload(context)
                                    F2Util.toast(context, addedMsg)
                                }
                            }) { Text(stringResource(R.string.f2_dns_allow), fontSize = 12.sp) }
                        }
                    }
                }
            }
            else -> {
                item { SectionTitle(stringResource(R.string.f2_dns_tab_lookup)) }
                item {
                    SettingsGroup {
                        F2Field(stringResource(R.string.f2_domain), lookupName, { lookupName = it }, placeholder = "example.com")
                        ChoiceRow(stringResource(R.string.f2_dns_type), listOf("A", "AAAA", "CNAME", "TXT", "MX", "HTTPS").map { it to it }, lookupType,
                            showDivider = false) { lookupType = it }
                    }
                }
                item {
                    Button(enabled = vpn.isRunning && lookupName.isNotBlank(), modifier = Modifier.fillMaxWidth().padding(top = 8.dp), onClick = {
                        scope.launch {
                            lookupErr = null
                            runCatching { DnsLog.lookup(lookupName.trim(), lookupType) }
                                .onSuccess { answers = it }.onFailure { answers = null; lookupErr = it.message }
                        }
                    }) { Text(stringResource(R.string.f2_dns_query)) }
                }
                item { F2Footer(stringResource(R.string.f2_dns_lookup_note)) }
                lookupErr?.let { e -> item { Text(e, color = c.bad, fontSize = 12.sp, modifier = Modifier.padding(6.dp)) } }
                answers?.let { a ->
                    if (a.isEmpty()) item { EmptyHint(stringResource(R.string.f2_none)) }
                    items(a) { r ->
                        AppCard(Modifier.padding(top = 6.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Tag(r.type, c.accent)
                                Spacer(Modifier.width(8.dp))
                                Text(r.data, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.text, modifier = Modifier.weight(1f))
                                r.ttl?.let { Text("TTL $it", fontSize = 10.sp, color = c.secondary) }
                            }
                        }
                    }
                }
            }
        }
    }
}
