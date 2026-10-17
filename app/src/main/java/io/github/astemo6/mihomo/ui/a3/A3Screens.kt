package io.github.astemo6.mihomo.ui.a3

import android.Manifest
import android.appwidget.AppWidgetManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.pm.ShortcutInfoCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.graphics.drawable.IconCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.a3.A3Prefs
import io.github.astemo6.mihomo.a3.A3Shortcuts
import io.github.astemo6.mihomo.a3.NetRule
import io.github.astemo6.mihomo.a3.NetSnapshot
import io.github.astemo6.mihomo.a3.NetworkModeSwitcher
import io.github.astemo6.mihomo.a3.ShortcutActivity
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.settings.ChoiceDialog
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.widget.NodeWidget
import io.github.astemo6.mihomo.widget.TrafficWidget
import java.net.Inet4Address
import java.net.NetworkInterface

/** A3 routes (plain strings, like Feature2Routes). */
object A3Routes {
    const val SYSTEM = "a3_system"
    const val NETWORK = "a3_network"
    const val LAN = "a3_lan"
    val all = setOf(SYSTEM, NETWORK, LAN)
}

@Composable
fun A3Screen(route: String, vm: MainViewModel, onBack: () -> Unit) {
    when (route) {
        A3Routes.SYSTEM -> SystemScreen(onBack)
        A3Routes.NETWORK -> NetworkRulesScreen(onBack)
        A3Routes.LAN -> LanShareScreen(vm, onBack)
    }
}

/** Re-runs [block] every time the screen resumes (permissions / system settings changed elsewhere). */
@Composable
private fun OnResume(block: () -> Unit) {
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val obs = LifecycleEventObserver { _, e -> if (e == Lifecycle.Event.ON_RESUME) block() }
        owner.lifecycle.addObserver(obs)
        onDispose { owner.lifecycle.removeObserver(obs) }
    }
}

private fun Context.openSafely(intent: Intent) {
    runCatching { startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
        .onFailure { runCatching { startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) } }
}

// ==== 系统集成: always-on, boot, battery, widgets, shortcuts ===========================================

@Composable
private fun SystemScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = LocalAppColors.current
    var tick by remember { mutableIntStateOf(0) }
    OnResume { tick++ }
    var boot by remember { mutableStateOf(A3Prefs.bootStart) }
    val pm = ctx.getSystemService(PowerManager::class.java)
    val ignoringBattery = remember(tick) { pm?.isIgnoringBatteryOptimizations(ctx.packageName) == true }
    val alwaysOn = remember(tick) { A3Prefs.lastAlwaysOn }
    val lockdown = remember(tick) { A3Prefs.lastLockdown }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.a3_system), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            item { SectionTitle(stringResource(R.string.a3_sec_autostart)) }
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.a3_boot_start), stringResource(R.string.a3_boot_start_desc), checked = boot) {
                        A3Prefs.bootStart = it; boot = it
                    }
                    SettingsRow(
                        stringResource(R.string.a3_always_on),
                        subtitle = stringResource(R.string.a3_always_on_desc),
                        value = when {
                            Build.VERSION.SDK_INT < Build.VERSION_CODES.Q -> null
                            lockdown -> stringResource(R.string.a3_always_on_lockdown)
                            alwaysOn -> stringResource(R.string.on)
                            else -> stringResource(R.string.off)
                        },
                        onClick = { ctx.openSafely(Intent(Settings.ACTION_VPN_SETTINGS)) },
                    )
                    SettingsRow(
                        stringResource(R.string.a3_battery),
                        subtitle = stringResource(R.string.a3_battery_desc),
                        value = stringResource(if (ignoringBattery) R.string.a3_battery_unrestricted else R.string.a3_battery_optimized),
                        showDivider = false,
                        onClick = { ctx.openSafely(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) },
                    )
                }
            }
            if (lockdown) item {
                Text(stringResource(R.string.a3_lockdown_note), fontSize = 12.sp, color = c.secondary,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
            item { SectionTitle(stringResource(R.string.a3_sec_widgets)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.widget_name), subtitle = stringResource(R.string.widget_desc),
                        onClick = { pinWidget(ctx, io.github.astemo6.mihomo.widget.StatusWidget::class.java) })
                    SettingsRow(stringResource(R.string.a3_widget_node_name), subtitle = stringResource(R.string.a3_widget_node_desc),
                        onClick = { pinWidget(ctx, NodeWidget::class.java) })
                    SettingsRow(stringResource(R.string.a3_widget_traffic_name), subtitle = stringResource(R.string.a3_widget_traffic_desc),
                        showDivider = false, onClick = { pinWidget(ctx, TrafficWidget::class.java) })
                }
            }
            item { SectionTitle(stringResource(R.string.a3_sec_shortcuts)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.a3_sc_toggle_long), subtitle = stringResource(R.string.a3_pin_shortcut),
                        onClick = { pinShortcut(ctx, "pin-toggle", R.string.a3_sc_toggle, R.drawable.ic_sc_power, A3Shortcuts.ACTION_TOGGLE) })
                    SettingsRow(stringResource(R.string.a3_sc_mode_long), subtitle = stringResource(R.string.a3_pin_shortcut),
                        showDivider = false,
                        onClick = { pinShortcut(ctx, "pin-mode", R.string.a3_sc_mode, R.drawable.ic_sc_mode, A3Shortcuts.ACTION_MODE) })
                }
            }
            item {
                Text(stringResource(R.string.a3_shortcuts_hint), fontSize = 12.sp, color = c.secondary,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
        }
    }
}

private fun pinWidget(ctx: Context, cls: Class<*>) {
    val mgr = AppWidgetManager.getInstance(ctx)
    val ok = mgr.isRequestPinAppWidgetSupported && runCatching { mgr.requestPinAppWidget(ComponentName(ctx, cls), null, null) }.getOrDefault(false)
    if (!ok) Toast.makeText(ctx, R.string.a3_pin_unsupported, Toast.LENGTH_LONG).show()
}

private fun pinShortcut(ctx: Context, id: String, label: Int, icon: Int, action: String) {
    if (!ShortcutManagerCompat.isRequestPinShortcutSupported(ctx)) {
        Toast.makeText(ctx, R.string.a3_pin_unsupported, Toast.LENGTH_LONG).show(); return
    }
    val info = ShortcutInfoCompat.Builder(ctx, id)
        .setShortLabel(ctx.getString(label))
        .setIcon(IconCompat.createWithResource(ctx, icon))
        .setIntent(Intent(ctx, ShortcutActivity::class.java).setAction(action))
        .build()
    runCatching { ShortcutManagerCompat.requestPinShortcut(ctx, info, null) }
}

// ==== 按网络切换模式 ====================================================================================

@Composable
private fun targetLabel(target: String): String = when {
    target == "keep" -> stringResource(R.string.a3_net_keep)
    target == "mode:global" -> stringResource(R.string.mode_global)
    target == "mode:direct" -> stringResource(R.string.mode_direct)
    target == "mode:rule" -> stringResource(R.string.mode_rule)
    target.startsWith("profile:") -> {
        val id = target.removePrefix("profile:")
        val name = ProfileStore.profiles.collectAsState().value.firstOrNull { it.id == id }?.name
        stringResource(R.string.a3_net_profile, name ?: stringResource(R.string.a3_net_profile_missing))
    }
    else -> target
}

@Composable
private fun kindLabel(kind: String): String = stringResource(when (kind) {
    NetRule.KIND_SSID -> R.string.a3_net_kind_ssid
    NetRule.KIND_CELLULAR -> R.string.a3_net_kind_cellular
    NetRule.KIND_ETHERNET -> R.string.a3_net_kind_ethernet
    else -> R.string.a3_net_kind_wifi
})

@Composable
private fun snapshotLabel(s: NetSnapshot?): String = when (s?.type) {
    null, "other" -> stringResource(R.string.a3_net_none)
    "wifi" -> stringResource(R.string.a3_net_kind_wifi) + " · " + (s.ssid ?: stringResource(R.string.a3_net_ssid_unknown))
    "cellular" -> stringResource(R.string.a3_net_kind_cellular)
    "wired" -> stringResource(R.string.a3_net_kind_ethernet)
    else -> s.type
}

@Composable
private fun NetworkRulesScreen(onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = LocalAppColors.current
    val enabled by A3Prefs.netEnabled.collectAsState()
    val rules by A3Prefs.rules.collectAsState()
    val current by NetworkModeSwitcher.current.collectAsState()
    var tick by remember { mutableIntStateOf(0) }
    OnResume { tick++; NetworkModeSwitcher.refreshNow(ctx) }
    val hasLoc = remember(tick) { NetworkModeSwitcher.hasLocationPermission(ctx) }
    val hasBg = remember(tick) { NetworkModeSwitcher.hasBackgroundLocation(ctx) }
    val locOn = remember(tick) { NetworkModeSwitcher.locationEnabled(ctx) }
    var editing by remember { mutableStateOf<NetRule?>(null) }
    var pickDefault by remember { mutableStateOf(false) }
    var netDefault by remember { mutableStateOf(A3Prefs.netDefault) }
    val usesSsid = rules.any { it.kind == NetRule.KIND_SSID && it.enabled }

    val fineLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        tick++; NetworkModeSwitcher.refreshNow(ctx)
    }
    val bgLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        tick++
        if (!it) ctx.openSafely(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName)))
    }

    fun saveRules(list: List<NetRule>) {
        A3Prefs.setRules(list)
        NetworkModeSwitcher.reapply()
    }

    Scaffold(
        containerColor = c.bg,
        topBar = {
            BackTopBar(stringResource(R.string.a3_net_title), onBack) {
                IconButton(onClick = {
                    editing = NetRule(kind = if (current?.ssid != null) NetRule.KIND_SSID else NetRule.KIND_WIFI,
                        ssid = current?.ssid.orEmpty(), target = "mode:direct")
                }) { Icon(Icons.Filled.Add, stringResource(R.string.add)) }
            }
        },
    ) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.a3_net_title), stringResource(R.string.a3_net_desc), checked = enabled) {
                        A3Prefs.setNetEnabled(it)
                        if (it) NetworkModeSwitcher.reapply()
                    }
                    SettingsRow(stringResource(R.string.a3_net_current), value = snapshotLabel(current))
                    SettingsRow(stringResource(R.string.a3_net_default), subtitle = stringResource(R.string.a3_net_default_desc),
                        value = targetLabel(netDefault), showDivider = false, onClick = { pickDefault = true })
                }
            }
            item { SectionTitle(stringResource(R.string.a3_net_ssid_access)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.a3_perm_location),
                        subtitle = stringResource(R.string.a3_perm_location_desc),
                        value = stringResource(if (hasLoc) R.string.a3_granted else R.string.a3_not_granted),
                        onClick = {
                            if (!hasLoc) fineLauncher.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
                            else ctx.openSafely(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName)))
                        })
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        SettingsRow(stringResource(R.string.a3_perm_bg_location),
                            subtitle = stringResource(R.string.a3_perm_bg_location_desc),
                            value = stringResource(if (hasBg) R.string.a3_granted else R.string.a3_not_granted),
                            onClick = {
                                when {
                                    !hasLoc -> Toast.makeText(ctx, R.string.a3_perm_location_first, Toast.LENGTH_SHORT).show()
                                    !hasBg -> bgLauncher.launch(Manifest.permission.ACCESS_BACKGROUND_LOCATION)
                                    else -> ctx.openSafely(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName)))
                                }
                            })
                    }
                    SettingsRow(stringResource(R.string.a3_location_service),
                        value = stringResource(if (locOn) R.string.on else R.string.off), showDivider = false,
                        onClick = { ctx.openSafely(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)) })
                }
            }
            if (usesSsid && (!hasLoc || !locOn)) item {
                Text(stringResource(R.string.a3_net_ssid_warning), fontSize = 12.sp, color = c.warn,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
            item { SectionTitle(stringResource(R.string.a3_net_rules)) }
            if (rules.isEmpty()) item { EmptyHint(stringResource(R.string.a3_net_empty)) }
            else item {
                SettingsGroup {
                    rules.forEachIndexed { i, r ->
                        val cond = if (r.kind == NetRule.KIND_SSID) kindLabel(r.kind) + " · " + r.ssid else kindLabel(r.kind)
                        SettingsRow(
                            cond,
                            subtitle = "→ " + targetLabel(r.target) + if (r.enabled) "" else " (" + stringResource(R.string.off) + ")",
                            showDivider = i < rules.lastIndex,
                            onClick = { editing = r },
                        )
                    }
                }
            }
            item {
                Text(stringResource(R.string.a3_net_order_note), fontSize = 12.sp, color = c.secondary,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
        }
    }

    if (pickDefault) {
        val opts = listOf("keep", "mode:rule", "mode:global", "mode:direct")
        ChoiceDialog(stringResource(R.string.a3_net_default), opts.map { it to targetLabel(it) }, netDefault,
            { A3Prefs.netDefault = it; netDefault = it; pickDefault = false; NetworkModeSwitcher.reapply() }, { pickDefault = false })
    }
    editing?.let { r ->
        RuleDialog(
            rule = r,
            currentSsid = current?.ssid,
            isNew = rules.none { it.id == r.id },
            onSave = { n ->
                val list = rules.toMutableList()
                val i = list.indexOfFirst { it.id == n.id }
                if (i >= 0) list[i] = n else list += n
                saveRules(list); editing = null
            },
            onDelete = { saveRules(rules.filter { it.id != r.id }); editing = null },
            onDismiss = { editing = null },
        )
    }
}

@Composable
private fun RuleDialog(rule: NetRule, currentSsid: String?, isNew: Boolean, onSave: (NetRule) -> Unit, onDelete: () -> Unit, onDismiss: () -> Unit) {
    var kind by remember { mutableStateOf(rule.kind) }
    var ssid by remember { mutableStateOf(rule.ssid) }
    var target by remember { mutableStateOf(rule.target) }
    var on by remember { mutableStateOf(rule.enabled) }
    val profiles by ProfileStore.profiles.collectAsState()
    val targets = listOf("mode:rule", "mode:global", "mode:direct") + profiles.map { "profile:" + it.id }
    val valid = kind != NetRule.KIND_SSID || ssid.isNotBlank()

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(if (isNew) R.string.a3_net_add else R.string.a3_net_edit)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(stringResource(R.string.a3_net_when), fontSize = 13.sp, color = LocalAppColors.current.secondary)
                NetRule.kinds.forEach { k -> RadioLine(kindLabel(k), kind == k) { kind = k } }
                if (kind == NetRule.KIND_SSID) {
                    OutlinedTextField(ssid, { ssid = it }, singleLine = true, label = { Text("SSID") }, modifier = Modifier.fillMaxWidth())
                    if (currentSsid != null && currentSsid != ssid) {
                        TextButton(onClick = { ssid = currentSsid }) { Text(stringResource(R.string.a3_net_use_current, currentSsid)) }
                    }
                }
                Text(stringResource(R.string.a3_net_then), fontSize = 13.sp, color = LocalAppColors.current.secondary,
                    modifier = Modifier.padding(top = 10.dp))
                targets.forEach { t -> RadioLine(targetLabel(t), target == t) { target = t } }
                Row(Modifier.fillMaxWidth().clickable { on = !on }.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.a3_net_rule_enabled), modifier = Modifier.weight(1f))
                    Switch(checked = on, onCheckedChange = { on = it })
                }
            }
        },
        confirmButton = {
            TextButton(enabled = valid, onClick = { onSave(rule.copy(kind = kind, ssid = ssid.trim(), target = target, enabled = on)) }) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            Row {
                if (!isNew) TextButton(onClick = onDelete) { Text(stringResource(R.string.delete), color = LocalAppColors.current.bad) }
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) }
            }
        },
    )
}

@Composable
private fun RadioLine(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick), verticalAlignment = Alignment.CenterVertically) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label, maxLines = 1)
    }
}

// ==== 局域网共享 ========================================================================================

private data class LanAddr(val iface: String, val ip: String)

private fun lanAddresses(): List<LanAddr> = runCatching {
    NetworkInterface.getNetworkInterfaces().toList()
        .filter { it.isUp && !it.isLoopback && !it.name.startsWith("tun") && !it.name.startsWith("dummy") }
        .flatMap { ni ->
            ni.inetAddresses.toList().filterIsInstance<Inet4Address>()
                .filter { it.isSiteLocalAddress && !it.hostAddress.orEmpty().startsWith("198.18.") }
                .map { LanAddr(ni.name, it.hostAddress.orEmpty()) }
        }
        .distinctBy { it.ip }
}.getOrDefault(emptyList())

@Composable
private fun LanShareScreen(vm: MainViewModel, onBack: () -> Unit) {
    val ctx = LocalContext.current
    val c = LocalAppColors.current
    var o by remember { mutableStateOf(Overrides.load()) }
    var tick by remember { mutableIntStateOf(0) }
    OnResume { tick++; o = Overrides.load() }
    val addrs = remember(tick) { lanAddresses() }
    val running = VpnState.info.collectAsState().value.isRunning
    var editPort by remember { mutableStateOf(false) }
    var editAuth by remember { mutableStateOf(false) }

    fun save(n: Overrides) {
        Overrides.save(n)
        o = n
        VpnController.reload(ctx) // listeners are rebuilt by the core reload
    }

    fun copy(text: String) {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("proxy", text))
        vm.toast(ctx.getString(R.string.a3_copied, text))
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.a3_lan_title), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.allow_lan), stringResource(R.string.a3_lan_desc), checked = o.allowLan) {
                        save(o.copy(allowLan = it))
                    }
                    SettingsRow(stringResource(R.string.mixed_port), value = o.mixedPort.toString(), onClick = { editPort = true })
                    SettingsRow(stringResource(R.string.a3_lan_auth),
                        value = if (o.lanAuth.username.isNotEmpty() && o.lanAuth.password.isNotEmpty()) o.lanAuth.username
                        else stringResource(R.string.a3_lan_auth_none),
                        onClick = { editAuth = true })
                    SwitchRow(stringResource(R.string.a3_lan_local_only), stringResource(R.string.a3_lan_local_only_desc),
                        checked = o.lanLocalOnly, showDivider = false) { save(o.copy(lanLocalOnly = it)) }
                }
            }
            if (o.allowLan && !running) item {
                Text(stringResource(R.string.a3_lan_needs_vpn), fontSize = 12.sp, color = c.warn,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
            item { SectionTitle(stringResource(R.string.a3_lan_addresses)) }
            if (addrs.isEmpty()) item { EmptyHint(stringResource(R.string.a3_lan_no_ip)) }
            else items(addrs, key = { it.ip }) { a ->
                val http = "http://${a.ip}:${o.mixedPort}"
                val socks = "socks5://${a.ip}:${o.mixedPort}"
                SettingsGroup(Modifier.padding(bottom = 8.dp)) {
                    SettingsRow("${a.ip}:${o.mixedPort}", subtitle = a.iface, onClick = { copy("${a.ip}:${o.mixedPort}") })
                    SettingsRow("HTTP", subtitle = http, onClick = { copy(http) })
                    SettingsRow("SOCKS5", subtitle = socks, showDivider = false, onClick = { copy(socks) })
                }
            }
            item {
                Text(stringResource(R.string.a3_lan_hint), fontSize = 12.sp, color = c.secondary,
                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 6.dp))
            }
        }
    }

    if (editPort) {
        var text by remember { mutableStateOf(o.mixedPort.toString()) }
        val v = text.toIntOrNull()
        val ok = v != null && v in 1024..65535 && v != o.port
        AlertDialog(
            onDismissRequest = { editPort = false },
            title = { Text(stringResource(R.string.mixed_port)) },
            text = {
                OutlinedTextField(text, { text = it.filter { ch -> ch.isDigit() }.take(5) }, singleLine = true,
                    isError = !ok, supportingText = { Text(stringResource(R.string.a3_lan_port_range)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
            },
            confirmButton = { TextButton(enabled = ok, onClick = { save(o.copy(mixedPort = v!!)); editPort = false }) { Text(stringResource(R.string.ok)) } },
            dismissButton = { TextButton(onClick = { editPort = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    if (editAuth) {
        var user by remember { mutableStateOf(o.lanAuth.username) }
        var pass by remember { mutableStateOf(o.lanAuth.password) }
        AlertDialog(
            onDismissRequest = { editAuth = false },
            title = { Text(stringResource(R.string.a3_lan_auth)) },
            text = {
                Column {
                    OutlinedTextField(user, { user = it.trim() }, singleLine = true, label = { Text(stringResource(R.string.a3_username)) })
                    OutlinedTextField(pass, { pass = it }, singleLine = true, label = { Text(stringResource(R.string.a3_password)) },
                        visualTransformation = PasswordVisualTransformation())
                    Text(stringResource(R.string.a3_lan_auth_desc), fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(top = 6.dp))
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val auth = if (user.isEmpty() || pass.isEmpty()) Overrides.LanAuth() else Overrides.LanAuth(user, pass)
                    save(o.copy(lanAuth = auth)); editAuth = false
                }) { Text(stringResource(R.string.save)) }
            },
            dismissButton = { TextButton(onClick = { editAuth = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}
