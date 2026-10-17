package io.github.astemo6.mihomo.ui.engine

import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SwitchRow
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val CERT_NAME = "Mihomo-CA.crt"

/**
 * MitM (QX settings › MitM): HTTPS decryption switch, the root CA (generate, export to Downloads,
 * manual-install explainer), hostnames (own + read-only from enabled modules), skip cert verify, QUIC.
 * Android cannot install a CA silently (KeyChain.createInstallIntent refuses CA certs since Android 11),
 * so the cert is saved to Downloads and the user installs it in system settings.
 */
@Composable
fun MitmScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val cfg by EngineStore.config.collectAsState()
    val ca by EngineStore.ca.collectAsState()
    val info by EngineStore.moduleInfo.collectAsState()
    val scope = rememberCoroutineScope()
    var confirmRegen by remember { mutableStateOf(false) }
    var newHost by remember { mutableStateOf("") }
    val moduleHosts = remember(cfg, info) { EngineStore.moduleHostnames() }

    val strExported = stringResource(R.string.ca_exported)
    // Android 8–9: no MediaStore.Downloads, let the user pick where to save (no storage permission needed).
    val createDoc = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-x509-ca-cert")) { uri ->
        if (uri != null) scope.launch {
            val ok = runCatching {
                val der = EngineStore.certDer()
                withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri)?.use { it.write(der) } }
            }.isSuccess
            vm.toast(if (ok) strExported else ctx.getString(R.string.ca_export_failed))
        }
    }

    fun export() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) { createDoc.launch(CERT_NAME); return }
        scope.launch {
            val r = runCatching { saveToDownloads(ctx, EngineStore.certDer()) }
            vm.toast(r.fold({ strExported }, { ctx.getString(R.string.ca_export_failed) + ": " + (it.message ?: "") }))
        }
    }

    fun generate() {
        scope.launch {
            runCatching { EngineStore.generateCA() }
                .onSuccess { vm.toast(ctx.getString(R.string.ca_generated)) }
                .onFailure { vm.toast(ctx.getString(R.string.ca_generate_failed, it.message ?: "")) }
        }
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.sec_mitm), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                SettingsGroup {
                    SwitchRow(stringResource(R.string.mitm_switch), stringResource(R.string.mitm_switch_desc), cfg.mitm) { on ->
                        if (on && !ca.exists) vm.toast(ctx.getString(R.string.mitm_need_ca))
                        EngineStore.setMitm(on)
                    }
                    SwitchRow(stringResource(R.string.mitm_skip_verify), stringResource(R.string.mitm_skip_verify_desc), cfg.skipCertVerify) {
                        EngineStore.setSkipCertVerify(it)
                    }
                    SwitchRow(stringResource(R.string.mitm_quic_all), stringResource(R.string.mitm_quic_all_desc), cfg.quic == "all",
                        showDivider = false) { EngineStore.setQuicAll(it) }
                }
            }

            item { SectionTitle(stringResource(R.string.ca_cert)) }
            item {
                AppCard {
                    if (ca.exists) {
                        Text(ca.subject ?: "Mihomo CA", fontWeight = FontWeight.SemiBold, color = c.text)
                        ca.notAfter?.let { Text(stringResource(R.string.ca_valid_until, it), fontSize = 12.sp, color = c.secondary) }
                        ca.algorithm?.let { Text(it, fontSize = 12.sp, color = c.secondary) }
                        (ca.sha1 ?: ca.fingerprint)?.let {
                            Text("SHA-1 $it", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = c.secondary)
                        }
                        Row(Modifier.fillMaxWidth().padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = { export() }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.ca_export)) }
                            OutlinedButton(onClick = { confirmRegen = true }, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.ca_regenerate)) }
                        }
                    } else {
                        Text(stringResource(R.string.ca_none), color = c.secondary, fontSize = 13.sp)
                        Button(onClick = { generate() }, modifier = Modifier.fillMaxWidth().padding(top = 8.dp)) {
                            Text(stringResource(R.string.ca_generate))
                        }
                    }
                }
            }
            item {
                AppCard {
                    Text(stringResource(R.string.ca_install_title), fontWeight = FontWeight.SemiBold, color = c.text)
                    Text(stringResource(R.string.ca_install_steps, CERT_NAME), fontSize = 13.sp, color = c.text, modifier = Modifier.padding(top = 6.dp))
                    Text(stringResource(R.string.ca_install_note), fontSize = 12.sp, color = c.warn, modifier = Modifier.padding(top = 6.dp))
                    TextButton(onClick = { openSecuritySettings(ctx) }, modifier = Modifier.align(Alignment.End)) {
                        Text(stringResource(R.string.ca_open_settings))
                    }
                }
            }

            item { SectionTitle(stringResource(R.string.mitm_hostnames)) }
            item {
                AppCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(newHost, { newHost = it }, Modifier.weight(1f), singleLine = true,
                            placeholder = { Text("*.example.com / -skip.example.com", fontSize = 12.sp) })
                        TextButton(onClick = {
                            newHost.split(',', ' ', '\n').map { it.trim() }.filter { it.isNotEmpty() }.forEach { EngineStore.addHostname(it) }
                            newHost = ""
                        }, enabled = newHost.isNotBlank()) { Text(stringResource(R.string.add)) }
                    }
                    Text(stringResource(R.string.mitm_hostnames_desc), fontSize = 11.sp, color = c.secondary)
                }
            }
            items(cfg.hostnames, key = { "h:$it" }) { h ->
                AppCard(padding = PaddingValues(start = 14.dp, end = 4.dp, top = 2.dp, bottom = 2.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(h, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = c.text, modifier = Modifier.weight(1f))
                        IconButton(onClick = { EngineStore.removeHostname(h) }) { Icon(Icons.Filled.Close, stringResource(R.string.delete), tint = c.secondary) }
                    }
                }
            }
            if (moduleHosts.isNotEmpty()) {
                item { SectionTitle(stringResource(R.string.mitm_module_hostnames)) }
                item {
                    AppCard {
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            moduleHosts.forEach { Text(it, fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = c.secondary) }
                        }
                    }
                }
            }
        }
    }

    if (confirmRegen) {
        AlertDialog(
            onDismissRequest = { confirmRegen = false },
            title = { Text(stringResource(R.string.ca_regenerate)) },
            text = { Text(stringResource(R.string.ca_regenerate_warn)) },
            confirmButton = { TextButton(onClick = { confirmRegen = false; generate() }) { Text(stringResource(R.string.ca_regenerate), color = c.bad) } },
            dismissButton = { TextButton(onClick = { confirmRegen = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/** Android 10+: writes the DER certificate to Download/ via MediaStore (no permission). */
private suspend fun saveToDownloads(ctx: Context, der: ByteArray): Uri = withContext(Dispatchers.IO) {
    val resolver = ctx.contentResolver
    val values = ContentValues().apply {
        put(MediaStore.MediaColumns.DISPLAY_NAME, CERT_NAME)
        put(MediaStore.MediaColumns.MIME_TYPE, "application/x-x509-ca-cert")
        put(MediaStore.MediaColumns.IS_PENDING, 1)
    }
    val collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY)
    val uri = resolver.insert(collection, values) ?: error("MediaStore insert failed")
    try {
        resolver.openOutputStream(uri)?.use { it.write(der) } ?: error("open failed")
        values.clear(); values.put(MediaStore.MediaColumns.IS_PENDING, 0)
        resolver.update(uri, values, null, null)
        uri
    } catch (e: Exception) {
        resolver.delete(uri, null, null); throw e
    }
}

private fun openSecuritySettings(ctx: Context) {
    // There is no public intent for "Install a certificate"; the security page is the closest stable entry.
    val intents = listOf(Intent("android.settings.SECURITY_ADVANCED_SETTINGS"), Intent(Settings.ACTION_SECURITY_SETTINGS), Intent(Settings.ACTION_SETTINGS))
    for (i in intents) {
        if (runCatching { ctx.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }.isSuccess) return
    }
}
