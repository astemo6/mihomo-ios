package io.github.astemo6.mihomo.ui.settings

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

private enum class Editing { LOG, IPV6, DNS, QUIC, TESTURL, STACK, IPPREF, MIXED, CTRL, TIMEOUT }

/** 连接方式 / 内核设置: writes overrides.json (same fields as iOS) and reloads the core when running. */
@Composable
fun ConnectionScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    var o by remember { mutableStateOf(Overrides.load()) }
    var stack by remember { mutableStateOf(AppSettings.tunStack) }
    var dirty by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<Editing?>(null) }
    val running by vm.running.collectAsState()

    fun save(n: Overrides) {
        o = n
        Overrides.save(n)
        dirty = true
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.connection), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            if (dirty && running) item {
                Button(onClick = { vm.applySettings(); dirty = false }, modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)) {
                    Text(stringResource(R.string.apply_reload))
                }
            }
            item { SectionTitle(stringResource(R.string.sec_core)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.log_level), value = o.logLevel, onClick = { editing = Editing.LOG })
                    SettingsRow(stringResource(R.string.dns_mode), value = o.dnsMode, onClick = { editing = Editing.DNS })
                    SwitchRow(stringResource(R.string.sniffer), checked = o.sniffer) { save(o.copy(sniffer = it)) }
                    SettingsRow(stringResource(R.string.ipv6), value = ipv6Label(o.ipv6Mode), onClick = { editing = Editing.IPV6 })
                    SettingsRow(stringResource(R.string.ip_preference), value = o.ipPreference, onClick = { editing = Editing.IPPREF })
                    SettingsRow(stringResource(R.string.block_quic), value = quicLabel(o.blockQUIC), onClick = { editing = Editing.QUIC })
                    SettingsRow(stringResource(R.string.tun_stack), value = stack, showDivider = false, onClick = { editing = Editing.STACK })
                }
            }
            item { SectionTitle(stringResource(R.string.sec_latency)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.test_url), subtitle = o.testUrlOrDefault, onClick = { editing = Editing.TESTURL })
                    SettingsRow(stringResource(R.string.test_timeout), value = "${o.testTimeout} ms", onClick = { editing = Editing.TIMEOUT })
                    SwitchRow(stringResource(R.string.override_health), stringResource(R.string.override_health_desc),
                        checked = o.overrideHealthCheck, showDivider = false) { save(o.copy(overrideHealthCheck = it)) }
                }
            }
            item { SectionTitle(stringResource(R.string.sec_lan)) }
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.allow_lan), stringResource(R.string.allow_lan_desc), checked = o.allowLan) {
                        save(o.copy(allowLan = it))
                    }
                    SettingsRow(stringResource(R.string.mixed_port), value = o.mixedPort.toString(), onClick = { editing = Editing.MIXED })
                    SettingsRow(stringResource(R.string.controller_port), value = o.port.toString(), showDivider = false,
                        onClick = { editing = Editing.CTRL })
                }
            }
        }
    }

    when (editing) {
        Editing.LOG -> ChoiceDialog(stringResource(R.string.log_level), Overrides.logLevels.map { it to it }, o.logLevel,
            { save(o.copy(logLevel = it)); editing = null }, { editing = null })
        Editing.DNS -> ChoiceDialog(stringResource(R.string.dns_mode), listOf("fake-ip" to "fake-ip", "redir-host" to "redir-host"), o.dnsMode,
            { save(o.copy(dnsMode = it)); editing = null }, { editing = null })
        Editing.IPV6 -> ChoiceDialog(stringResource(R.string.ipv6), listOf("off", "auto", "always").map { it to ipv6Label(it) }, o.ipv6Mode,
            { save(o.copy(ipv6Mode = it, ipv6 = it == "always")); editing = null }, { editing = null })
        Editing.IPPREF -> ChoiceDialog(stringResource(R.string.ip_preference),
            listOf("dual", "ipv4-prefer", "ipv6-prefer", "ipv4", "ipv6").map { it to it }, o.ipPreference,
            { save(o.copy(ipPreference = it)); editing = null }, { editing = null })
        Editing.QUIC -> ChoiceDialog(stringResource(R.string.block_quic), listOf("off", "nondirect", "always").map { it to quicLabel(it) }, o.blockQUIC,
            { save(o.copy(blockQUIC = it)); editing = null }, { editing = null })
        Editing.STACK -> ChoiceDialog(stringResource(R.string.tun_stack), listOf("gvisor", "system", "mixed").map { it to it }, stack,
            { AppSettings.tunStack = it; stack = it; dirty = true; editing = null }, { editing = null })
        Editing.TESTURL -> {
            var custom by remember { mutableStateOf(o.testURL) }
            AlertDialog(
                onDismissRequest = { editing = null },
                title = { Text(stringResource(R.string.test_url)) },
                text = {
                    androidx.compose.foundation.layout.Column {
                        Overrides.testURLPresets.forEach { u ->
                            SettingsRow(u, showDivider = false, onClick = { save(o.copy(testURL = u)); editing = null })
                        }
                        OutlinedTextField(custom, { custom = it }, singleLine = true, label = { Text(stringResource(R.string.custom)) })
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        if (Overrides.isValidTestURL(custom)) { save(o.copy(testURL = custom.trim())); editing = null }
                        else vm.toast(vm.getApplication<android.app.Application>().getString(R.string.err_bad_url))
                    }) { Text(stringResource(R.string.ok)) }
                },
                dismissButton = { TextButton(onClick = { editing = null }) { Text(stringResource(R.string.cancel)) } },
            )
        }
        Editing.MIXED, Editing.CTRL, Editing.TIMEOUT -> {
            val e = editing!!
            val initial = when (e) { Editing.MIXED -> o.mixedPort; Editing.CTRL -> o.port; else -> o.testTimeout }
            var text by remember(e) { mutableStateOf(initial.toString()) }
            val title = stringResource(when (e) { Editing.MIXED -> R.string.mixed_port; Editing.CTRL -> R.string.controller_port; else -> R.string.test_timeout })
            AlertDialog(
                onDismissRequest = { editing = null },
                title = { Text(title) },
                text = {
                    OutlinedTextField(text, { text = it.filter { ch -> ch.isDigit() }.take(5) }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                },
                confirmButton = {
                    TextButton(onClick = {
                        val v = text.toIntOrNull()
                        when {
                            v == null -> Unit
                            e == Editing.TIMEOUT -> save(o.copy(testTimeoutMs = v.coerceIn(1000, 30000)))
                            v !in 1024..65535 -> Unit
                            e == Editing.MIXED -> save(o.copy(mixedPort = v))
                            else -> save(o.copy(controllerPort = v))
                        }
                        editing = null
                    }) { Text(stringResource(R.string.ok)) }
                },
                dismissButton = { TextButton(onClick = { editing = null }) { Text(stringResource(R.string.cancel)) } },
            )
        }
        null -> Unit
    }
}

@Composable
private fun ipv6Label(m: String): String = stringResource(when (m) {
    "auto" -> R.string.ipv6_auto
    "always" -> R.string.ipv6_always
    else -> R.string.off
})

@Composable
private fun quicLabel(m: String): String = stringResource(when (m) {
    "off" -> R.string.off
    "always" -> R.string.quic_always
    else -> R.string.quic_nondirect
})
