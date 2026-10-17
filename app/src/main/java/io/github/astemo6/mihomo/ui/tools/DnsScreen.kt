package io.github.astemo6.mihomo.ui.tools

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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.DnsOverride
import io.github.astemo6.mihomo.data.LocalDns
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.Inet6Address
import java.net.InetAddress

private data class DnsAnswer(val type: String, val data: String, val ttl: Int?)

private fun rrType(v: Int?): String = when (v) {
    1 -> "A"; 5 -> "CNAME"; 28 -> "AAAA"; 65 -> "HTTPS"; 16 -> "TXT"; 15 -> "MX"; else -> v?.toString() ?: "?"
}

/**
 * DNS tool (toolbar DNS button): a query test through the core's resolver (/dns/query, so the answer
 * follows the profile's DNS, fake-ip and hosts) or the system resolver when disconnected, plus the DNS
 * settings of the iOS DNSView (dns.json override, DNS mode, hosts, 真实 IP 域名).
 */
@Composable
fun DnsScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val running by vm.running.collectAsState()
    val scope = rememberCoroutineScope()

    var name by remember { mutableStateOf("") }
    var type by remember { mutableStateOf("A") }
    var busy by remember { mutableStateOf(false) }
    var answers by remember { mutableStateOf<List<DnsAnswer>>(emptyList()) }
    var via by remember { mutableStateOf<String?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    var s by remember { mutableStateOf(DnsOverride.load()) }
    var dnsMode by remember { mutableStateOf(Overrides.load().dnsMode) }
    var local by remember { mutableStateOf(LocalDns.load()) }
    var newHost by remember { mutableStateOf("") }
    var newHostValue by remember { mutableStateOf("") }
    var hostError by remember { mutableStateOf<String?>(null) }
    var newMatch by remember { mutableStateOf("") }
    var newServers by remember { mutableStateOf("") }

    val strSystem = stringResource(R.string.dns_via_system)
    val strCore = stringResource(R.string.dns_via_core)
    val strNoRecord = stringResource(R.string.dns_no_record)
    val strSaved = stringResource(R.string.saved_next_connect)
    val strSavedReload = stringResource(R.string.saved_reloaded)

    fun query() {
        val n = name.trim()
        if (n.isEmpty() || busy) return
        busy = true; answers = emptyList(); error = null; via = null
        scope.launch {
            val t0 = System.currentTimeMillis()
            try {
                if (running) {
                    val o = ControllerClient.dnsQuery(n, type)
                    answers = (o["Answer"] as? JsonArray).orEmpty().map { a ->
                        val x = a.jsonObject
                        DnsAnswer(rrType(x["type"]?.jsonPrimitive?.intOrNull), x["data"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                            x["TTL"]?.jsonPrimitive?.intOrNull)
                    }
                    if (answers.isEmpty()) error = strNoRecord + " (Status ${o["Status"]?.jsonPrimitive?.intOrNull ?: -1})"
                    via = strCore
                } else {
                    val ips = withContext(Dispatchers.IO) { InetAddress.getAllByName(n).toList() }
                        .filter { if (type == "AAAA") it is Inet6Address else it !is Inet6Address }
                    answers = ips.map { DnsAnswer(if (it is Inet6Address) "AAAA" else "A", it.hostAddress.orEmpty(), null) }
                    if (answers.isEmpty()) error = strNoRecord
                    via = strSystem
                }
            } catch (e: Exception) {
                error = e.message ?: e.toString()
            } finally {
                via = (via ?: (if (running) strCore else strSystem)) + " · ${System.currentTimeMillis() - t0} ms"
                busy = false
            }
        }
    }

    fun save() {
        local.save(); s.save()
        Overrides.update { it.copy(dnsMode = dnsMode) }
        if (running) { vm.applySettings(); vm.toast(strSavedReload) } else vm.toast(strSaved)
    }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.dns), onBack) {
            TextButton(onClick = { save() }) { Text(stringResource(R.string.save)) }
        }
    }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // ---- query test ----
            item { SectionTitle(stringResource(R.string.dns_query)) }
            item {
                AppCard {
                    OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth(), singleLine = true,
                        placeholder = { Text("www.google.com") },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Search),
                        keyboardActions = KeyboardActions(onSearch = { query() }))
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                        listOf("A", "AAAA", "CNAME", "HTTPS", "TXT").forEach { t ->
                            if (running || t == "A" || t == "AAAA") {
                                FilterChip(selected = type == t, onClick = { type = t }, label = { Text(t, fontSize = 12.sp) })
                            }
                        }
                        Spacer(Modifier.weight(1f))
                        if (busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                        else Button(onClick = { query() }) { Text(stringResource(R.string.dns_lookup)) }
                    }
                    via?.let { Text(it, fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(top = 8.dp)) }
                    error?.let { Text(it, fontSize = 13.sp, color = c.bad, modifier = Modifier.padding(top = 4.dp)) }
                    answers.forEach { a ->
                        Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                            Tag(a.type, c.accent)
                            Spacer(Modifier.width(8.dp))
                            Text(a.data, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = c.text, modifier = Modifier.weight(1f))
                            a.ttl?.let { Text("TTL $it", fontSize = 11.sp, color = c.secondary) }
                        }
                    }
                    if (!running) Text(stringResource(R.string.dns_query_offline), fontSize = 12.sp, color = c.secondary,
                        modifier = Modifier.padding(top = 8.dp))
                }
            }

            // ---- settings ----
            item { SectionTitle(stringResource(R.string.dns_settings)) }
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.dns_custom), stringResource(if (s.enabled) R.string.dns_custom_on else R.string.dns_custom_off),
                        checked = s.enabled) { s = s.copy(enabled = it) }
                    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.dns_mode), fontSize = 15.sp, color = c.text, modifier = Modifier.weight(1f))
                        FilterChip(dnsMode == "fake-ip", { dnsMode = "fake-ip" }, { Text("Fake-IP") })
                        Spacer(Modifier.width(6.dp))
                        FilterChip(dnsMode == "redir-host", { dnsMode = "redir-host" }, { Text("Redir-Host") })
                    }
                }
            }
            if (s.enabled) {
                item {
                    AppCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.dns_split), color = c.text, modifier = Modifier.weight(1f))
                            Switch(s.split, { s = s.copy(split = it) })
                        }
                        LinesField(stringResource(R.string.dns_domestic), "https://223.5.5.5/dns-query", s.nameserver) { s = s.copy(nameserver = it) }
                        if (s.split) LinesField(stringResource(R.string.dns_foreign), "https://1.1.1.1/dns-query", s.foreign) { s = s.copy(foreign = it) }
                        Text(stringResource(if (s.split) R.string.dns_split_desc else R.string.dns_nosplit_desc), fontSize = 12.sp, color = c.secondary)
                    }
                }
                item {
                    AppCard {
                        Text(stringResource(R.string.advanced), fontWeight = FontWeight.SemiBold, color = c.text)
                        LinesField(stringResource(R.string.dns_bootstrap), "223.5.5.5", s.defaultNameserver) { s = s.copy(defaultNameserver = it) }
                        LinesField(stringResource(R.string.dns_proxy_ns), "", s.proxyNameserver) { s = s.copy(proxyNameserver = it) }
                        LinesField(stringResource(R.string.dns_direct_ns), "", s.directNameserver) { s = s.copy(directNameserver = it) }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.dns_prefer_h3), color = c.text, modifier = Modifier.weight(1f))
                            Switch(s.preferH3, { s = s.copy(preferH3 = it) })
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(stringResource(R.string.dns_respect_rules), color = c.text, modifier = Modifier.weight(1f))
                            Switch(s.respectRules, { s = s.copy(respectRules = it) })
                        }
                        Text(stringResource(R.string.dns_bootstrap_desc), fontSize = 12.sp, color = c.secondary)
                    }
                }
                item {
                    AppCard {
                        Text(stringResource(R.string.dns_policy), fontWeight = FontWeight.SemiBold, color = c.text)
                        s.policy.forEachIndexed { i, p ->
                            Row(Modifier.fillMaxWidth().padding(top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                                Column(Modifier.weight(1f)) {
                                    Text(p.match, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.text)
                                    Text(p.servers.joinToString(", "), fontSize = 11.sp, color = c.secondary)
                                }
                                IconButton(onClick = { s = s.copy(policy = s.policy.filterIndexed { j, _ -> j != i }) }) {
                                    Icon(Icons.Filled.Close, stringResource(R.string.delete), tint = c.secondary)
                                }
                            }
                        }
                        OutlinedTextField(newMatch, { newMatch = it }, Modifier.fillMaxWidth(), singleLine = true,
                            placeholder = { Text(stringResource(R.string.dns_policy_match)) })
                        OutlinedTextField(newServers, { newServers = it }, Modifier.fillMaxWidth(), singleLine = true,
                            placeholder = { Text(stringResource(R.string.dns_policy_servers)) })
                        TextButton(onClick = {
                            val servers = newServers.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                            val m = newMatch.trim()
                            if (m.isNotEmpty() && servers.isNotEmpty()) {
                                s = s.copy(policy = s.policy + DnsOverride.Policy(m, servers)); newMatch = ""; newServers = ""
                            }
                        }, modifier = Modifier.align(Alignment.End)) { Text(stringResource(R.string.add)) }
                    }
                }
                if (dnsMode == "fake-ip") item {
                    AppCard {
                        Text("Fake-IP", fontWeight = FontWeight.SemiBold, color = c.text)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            FilterChip(s.fakeIPFilterMode == "blacklist", { s = s.copy(fakeIPFilterMode = "blacklist") },
                                { Text(stringResource(R.string.dns_fakeip_blacklist), fontSize = 12.sp) })
                            FilterChip(s.fakeIPFilterMode == "whitelist", { s = s.copy(fakeIPFilterMode = "whitelist") },
                                { Text(stringResource(R.string.dns_fakeip_whitelist), fontSize = 12.sp) })
                        }
                        LinesField(stringResource(R.string.dns_fakeip_filter), "+.lan", s.fakeIPFilter) { s = s.copy(fakeIPFilter = it) }
                    }
                }
                item {
                    TextButton(onClick = { s = DnsOverride(enabled = true, policy = s.policy) }) { Text(stringResource(R.string.dns_restore)) }
                }
            }

            // ---- hosts ----
            item { SectionTitle(stringResource(R.string.dns_hosts)) }
            item {
                AppCard {
                    local.hosts.forEachIndexed { i, h ->
                        Row(Modifier.fillMaxWidth().padding(bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(h.domain, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = if (h.disabled) c.secondary else c.text)
                                Text(h.value, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.secondary)
                            }
                            Switch(!h.disabled, { on -> local = local.copy(hosts = local.hosts.mapIndexed { j, x -> if (j == i) x.copy(disabled = !on) else x }) })
                            IconButton(onClick = { local = local.copy(hosts = local.hosts.filterIndexed { j, _ -> j != i }) }) {
                                Icon(Icons.Filled.Close, stringResource(R.string.delete), tint = c.secondary)
                            }
                        }
                    }
                    OutlinedTextField(newHost, { newHost = it }, Modifier.fillMaxWidth(), singleLine = true,
                        placeholder = { Text(stringResource(R.string.dns_host_domain)) })
                    OutlinedTextField(newHostValue, { newHostValue = it }, Modifier.fillMaxWidth(), singleLine = true,
                        placeholder = { Text(stringResource(R.string.dns_host_value)) })
                    hostError?.let { Text(it, color = c.warn, fontSize = 12.sp) }
                    TextButton(onClick = {
                        val d = newHost.trim(); val v = newHostValue.trim()
                        val err = runCatching { Core.validateHostEntry(d, v) }.getOrElse { it.message ?: "" }
                        if (err.isNotEmpty()) { hostError = err; return@TextButton }
                        hostError = null
                        val i = local.hosts.indexOfFirst { it.domain.equals(d, true) }
                        local = if (i >= 0) local.copy(hosts = local.hosts.mapIndexed { j, x -> if (j == i) x.copy(value = v, disabled = false) else x })
                        else local.copy(hosts = local.hosts + LocalDns.Host(d, v))
                        newHost = ""; newHostValue = ""
                    }, modifier = Modifier.align(Alignment.End)) { Text(stringResource(R.string.add)) }
                    Text(stringResource(R.string.dns_hosts_desc), fontSize = 12.sp, color = c.secondary)
                }
            }
            if (dnsMode == "fake-ip") {
                item { SectionTitle(stringResource(R.string.dns_realip)) }
                item {
                    AppCard {
                        LinesField(stringResource(R.string.dns_realip), "+.stun.example.com", local.realIP) { local = local.copy(realIP = it) }
                        Text(stringResource(R.string.dns_realip_desc), fontSize = 12.sp, color = c.secondary)
                    }
                }
            }
            item {
                Button(onClick = { save() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp), shape = RoundedCornerShape(12.dp)) {
                    Text(stringResource(if (running) R.string.save_reload else R.string.save))
                }
            }
        }
    }
}

/** Edits a list of strings as one-per-line text (iOS LinesField). */
@Composable
fun LinesField(title: String, placeholder: String, lines: List<String>, onChange: (List<String>) -> Unit) {
    val c = LocalAppColors.current
    var text by remember { mutableStateOf(lines.joinToString("\n")) }
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(title, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = c.secondary)
        OutlinedTextField(
            text, { t -> text = t; onChange(t.split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }) },
            Modifier.fillMaxWidth(), placeholder = { if (placeholder.isNotEmpty()) Text(placeholder, fontSize = 12.sp) },
            textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.text),
            minLines = 1, maxLines = 8,
        )
    }
}
