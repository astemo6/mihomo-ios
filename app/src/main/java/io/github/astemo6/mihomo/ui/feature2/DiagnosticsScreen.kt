package io.github.astemo6.mihomo.ui.feature2

import android.app.Activity
import android.content.Context
import android.net.VpnService
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.feature2.Diagnostics
import io.github.astemo6.mihomo.data.feature2.F2Core
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

/** Stops a running core (if any), writes overrides.safeMode, and connects again (iOS VPNManager.restart(safeMode:)). */
private suspend fun restartWith(context: Context, safe: Boolean) {
    Overrides.update { it.copy(safeMode = safe) }
    if (VpnState.info.value.status != VpnStatus.STOPPED) {
        VpnController.stop(context)
        withTimeoutOrNull(10_000) { while (VpnState.info.value.status != VpnStatus.STOPPED) delay(150) }
    }
    VpnController.start(context, safeMode = safe)
}

/** 诊断: redacted diagnostics bundle (bridge WriteDiagnosticBundle / DiagnosticSummary), safe-mode connect, 节点探测. */
@Composable
fun DiagnosticsScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val vpn by VpnState.info.collectAsState()
    var safe by remember { mutableStateOf(Overrides.load().safeMode) }
    var busy by remember { mutableStateOf(false) }
    var bundle by remember { mutableStateOf<File?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var policies by remember { mutableStateOf<List<String>>(emptyList()) }
    var probePolicy by remember { mutableStateOf<String?>(null) }
    var probePort by remember { mutableStateOf("") }
    var pendingSafe by remember { mutableStateOf<Boolean?>(null) }
    val copiedMsg = stringResource(R.string.f2_copied)
    val savedMsg = stringResource(R.string.f2_diag_saved)

    val saveLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        val f = bundle ?: return@rememberLauncherForActivityResult
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            runCatching { F2Core.io { context.contentResolver.openOutputStream(uri)?.use { out -> f.inputStream().use { it.copyTo(out) } } } }
                .onSuccess { F2Util.toast(context, savedMsg) }.onFailure { message = it.message }
        }
    }
    val permLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        val s = pendingSafe
        pendingSafe = null
        if (r.resultCode == Activity.RESULT_OK && s != null) scope.launch { restartWith(context, s); safe = s }
    }

    fun connect(safeMode: Boolean) {
        val prep = VpnService.prepare(context)
        if (prep != null) { pendingSafe = safeMode; permLauncher.launch(prep); return }
        scope.launch { restartWith(context, safeMode); safe = safeMode }
    }

    LaunchedEffect(vpn.isRunning) {
        probePort = F2Core.io { F2Core.probePort().toString() }
        policies = if (vpn.isRunning) runCatching {
            val p = ControllerClient.proxies()
            val groups = p.values.filter { it.isGroup && it.hidden != true }.map { it.name }.sorted()
            val nodes = p.values.filter { !it.isGroup && it.name !in setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE") }.map { it.name }.sorted()
            groups + nodes
        }.getOrDefault(emptyList()) else emptyList()
    }

    probePolicy?.let { p ->
        BackHandler { probePolicy = null }
        ProbeDetail(p, onBack = { probePolicy = null })
        return
    }

    F2Page(stringResource(R.string.f2_diag_title), onBack) {
        item { SectionTitle(stringResource(R.string.f2_diag_status)) }
        item {
            SettingsGroup {
                SettingsRow(stringResource(R.string.f2_diag_vpn), value = vpn.status.name.lowercase())
                SettingsRow(stringResource(R.string.f2_diag_core), value = Core.version.ifEmpty { "?" })
                SettingsRow(stringResource(R.string.f2_diag_probe_port), value = "127.0.0.1:$probePort")
                SettingsRow(stringResource(R.string.f2_diag_safe_mode), value = stringResource(if (safe) R.string.f2_on else R.string.f2_off), showDivider = vpn.error != null)
                vpn.error?.let { SettingsRow(stringResource(R.string.f2_diag_last_error), subtitle = it, showDivider = false) }
            }
        }
        item { SectionTitle(stringResource(R.string.f2_diag_bundle)) }
        item {
            Column {
                Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                    busy = true
                    scope.launch {
                        runCatching { F2Core.io { Diagnostics.export(context) } }
                            .onSuccess { f -> bundle = f; saveLauncher.launch(f.name) }
                            .onFailure { message = it.message }
                        busy = false
                    }
                }) {
                    if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text(stringResource(R.string.f2_diag_export))
                }
                OutlinedButton(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                    scope.launch {
                        val t = F2Core.io { Diagnostics.summary(context) }
                        F2Util.copy(context, t); F2Util.toast(context, copiedMsg)
                    }
                }) { Text(stringResource(R.string.f2_diag_copy_text)) }
                OutlinedButton(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                    scope.launch {
                        val t = F2Core.io { Diagnostics.summary(context) }
                        F2Util.shareText(context, t, context.getString(R.string.f2_diag_bundle))
                    }
                }) { Text(stringResource(R.string.f2_diag_share_text)) }
            }
        }
        item { F2Footer(stringResource(R.string.f2_diag_bundle_footer)) }
        item { SectionTitle(stringResource(R.string.f2_diag_safe_mode)) }
        item {
            Column {
                if (!safe) Button(modifier = Modifier.fillMaxWidth(), enabled = !vpn.isBusy, onClick = { connect(true) }) {
                    Text(stringResource(R.string.f2_diag_connect_safe))
                } else {
                    AppCard { Text(stringResource(R.string.f2_diag_safe_active), fontSize = 13.sp, color = c.warn) }
                    Button(modifier = Modifier.fillMaxWidth().padding(top = 8.dp), enabled = !vpn.isBusy, onClick = { connect(false) }) {
                        Text(stringResource(R.string.f2_diag_connect_normal))
                    }
                }
            }
        }
        item { F2Footer(stringResource(R.string.f2_diag_safe_footer)) }
        item { SectionTitle(stringResource(R.string.f2_diag_probe)) }
        if (!vpn.isRunning) item { AppCard { Text(stringResource(R.string.f2_probe_not_connected), fontSize = 13.sp, color = c.secondary) } }
        else item {
            SettingsGroup {
                ChoiceRow(stringResource(R.string.f2_diag_probe_policy), policies.map { it to it }, "", showDivider = false) { probePolicy = it }
            }
        }
        item { F2Footer(stringResource(R.string.f2_probe_footer)) }
    }
    MessageDialog(message) { message = null }
}
