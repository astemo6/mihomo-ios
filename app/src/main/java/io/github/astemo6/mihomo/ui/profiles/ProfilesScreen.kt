package io.github.astemo6.mihomo.ui.profiles

import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.TextSnippet
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.ImportRouter
import io.github.astemo6.mihomo.data.Profile
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.QrCodeDialog
import io.github.astemo6.mihomo.ui.components.rememberQrScanner
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

@Composable
fun ProfilesScreen(vm: MainViewModel, onBack: () -> Unit, onAdd: () -> Unit) {
    val c = LocalAppColors.current
    val profiles by vm.profiles.collectAsState()
    val activeId by vm.activeId.collectAsState()
    val updating by vm.updating.collectAsState()
    var renaming by remember { mutableStateOf<Profile?>(null) }
    var deleting by remember { mutableStateOf<Profile?>(null) }
    var intervalFor by remember { mutableStateOf<Profile?>(null) }
    var qrFor by remember { mutableStateOf<Profile?>(null) }

    Scaffold(
        containerColor = c.bg,
        topBar = {
            BackTopBar(stringResource(R.string.profiles), onBack) {
                if (profiles.any { it.isRemote }) IconButton(onClick = { vm.refreshAll() }) {
                    Icon(Icons.Filled.Refresh, stringResource(R.string.update_all))
                }
            }
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAdd, containerColor = c.accent, contentColor = Color.White) {
                Icon(Icons.Filled.Add, stringResource(R.string.add_profile))
            }
        },
    ) { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(16.dp, 8.dp, 16.dp, 96.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            if (profiles.isEmpty()) item { EmptyHint(stringResource(R.string.no_profile_hint)) }
            items(profiles, key = { it.id }) { p ->
                ProfileRow(
                    p, active = p.id == activeId, updating = p.id in updating,
                    onSelect = { vm.setActive(p) },
                    onUpdate = { vm.refreshProfile(p) },
                    onRename = { renaming = p },
                    onInterval = { intervalFor = p },
                    onDelete = { deleting = p },
                    onQr = { qrFor = p },
                )
            }
        }
    }

    qrFor?.let { p ->
        p.url?.let { QrCodeDialog(it, p.name.ifBlank { stringResource(R.string.qr_sub_title) }, onDismiss = { qrFor = null }) }
    }
    renaming?.let { p ->
        var name by remember(p.id) { mutableStateOf(p.name) }
        AlertDialog(
            onDismissRequest = { renaming = null },
            title = { Text(stringResource(R.string.rename)) },
            text = { OutlinedTextField(name, { name = it }, singleLine = true) },
            confirmButton = { TextButton(onClick = { vm.renameProfile(p, name); renaming = null }) { Text(stringResource(R.string.ok)) } },
            dismissButton = { TextButton(onClick = { renaming = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    deleting?.let { p ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text(stringResource(R.string.delete_profile_q, p.name)) },
            confirmButton = { TextButton(onClick = { vm.deleteProfile(p); deleting = null }) { Text(stringResource(R.string.delete), color = c.bad) } },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    intervalFor?.let { p ->
        AlertDialog(
            onDismissRequest = { intervalFor = null },
            title = { Text(stringResource(R.string.auto_update)) },
            text = {
                Column {
                    listOf(0, 6, 12, 24, 48, 72).forEach { h ->
                        Row(
                            Modifier.fillMaxWidth().clickable { vm.setInterval(p, h); intervalFor = null }.padding(vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(if (h == 0) stringResource(R.string.never) else stringResource(R.string.every_hours, h), modifier = Modifier.weight(1f))
                            if (p.updateIntervalHours == h) Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(c.accent))
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { intervalFor = null }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

@Composable
private fun ProfileRow(
    p: Profile, active: Boolean, updating: Boolean,
    onSelect: () -> Unit, onUpdate: () -> Unit, onRename: () -> Unit, onInterval: () -> Unit, onDelete: () -> Unit,
    onQr: () -> Unit,
) {
    val c = LocalAppColors.current
    var menu by remember { mutableStateOf(false) }
    AppCard(
        Modifier
            .border(1.5.dp, if (active) c.accent else Color.Transparent, RoundedCornerShape(14.dp))
            .clickable(onClick = onSelect),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(p.name, fontWeight = FontWeight.SemiBold, fontSize = 15.sp, color = c.text, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    Spacer(Modifier.width(6.dp))
                    Tag(stringResource(if (p.isRemote) R.string.kind_remote else R.string.kind_local), if (p.isRemote) c.accent else c.secondary)
                    if (active) {
                        Spacer(Modifier.width(4.dp))
                        Tag(stringResource(R.string.in_use), c.good)
                    }
                }
                val sub = buildList {
                    p.lastUpdated?.let { add(stringResource(R.string.updated_at, Fmt.dateTime(it))) }
                    if (p.isRemote) add(if (p.updateIntervalHours > 0) stringResource(R.string.every_hours, p.updateIntervalHours) else stringResource(R.string.never))
                }.joinToString(" · ")
                if (sub.isNotEmpty()) Text(sub, fontSize = 12.sp, color = c.secondary)
            }
            if (updating) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
            Box {
                IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, null, tint = c.secondary) }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    if (p.isRemote) {
                        DropdownMenuItem(text = { Text(stringResource(R.string.update)) }, onClick = { menu = false; onUpdate() })
                        DropdownMenuItem(text = { Text(stringResource(R.string.auto_update)) }, onClick = { menu = false; onInterval() })
                        if (!p.url.isNullOrBlank()) {
                            DropdownMenuItem(text = { Text(stringResource(R.string.qr_show)) }, onClick = { menu = false; onQr() })
                        }
                    }
                    DropdownMenuItem(text = { Text(stringResource(R.string.rename)) }, onClick = { menu = false; onRename() })
                    DropdownMenuItem(text = { Text(stringResource(R.string.delete), color = c.bad) }, onClick = { menu = false; onDelete() })
                }
            }
        }
        p.userInfo?.let { info ->
            Spacer(Modifier.height(8.dp))
            if (info.total > 0) {
                LinearProgressIndicator(progress = { info.fraction }, modifier = Modifier.fillMaxWidth().height(4.dp).clip(RoundedCornerShape(2.dp)),
                    color = if (info.fraction > 0.9f) c.bad else c.accent, trackColor = c.separator)
                Spacer(Modifier.height(4.dp))
            }
            Row {
                Text(stringResource(R.string.sub_used, Fmt.bytes(info.used), if (info.total > 0) Fmt.bytes(info.total) else "∞"),
                    fontSize = 12.sp, color = c.secondary, modifier = Modifier.weight(1f))
                if (info.expire > 0) Text(stringResource(R.string.sub_expire, Fmt.date(info.expire * 1000)), fontSize = 12.sp, color = c.secondary)
            }
        }
    }
}

// ---- add sheet --------------------------------------------------------------------------------

private fun displayName(context: Context, uri: Uri): String? = runCatching {
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cur ->
        if (cur.moveToFirst()) cur.getString(0) else null
    }
}.getOrNull()

/** Reads an opened / shared document (SAF) as text. */
fun readDocument(context: Context, uri: Uri): ImportRouter.Request? {
    val text = runCatching {
        context.contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
    }.getOrNull() ?: return null
    val file = displayName(context, uri).orEmpty()
    val name = file.substringBeforeLast('.')
    // .sgmodule / .plugin / .stoverride / .snippet … are modules; other text is routed by ClassifyText on import.
    if (file.substringAfterLast('.', "").lowercase() in ImportRouter.moduleExtensions) return ImportRouter.Request.ModuleText(text, name)
    return ImportRouter.Request.Text(text, name)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddProfileSheet(vm: MainViewModel, onDismiss: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val importing by vm.importing.collectAsState()
    var url by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var text by remember { mutableStateOf("") }
    var showText by remember { mutableStateOf(false) }
    val scanQr = rememberQrScanner { scanned ->
        // Same routing as the clipboard: subscription URL, install-config link, share links, module URL …
        val req = ImportRouter.fromText(scanned)
        if (req == null) vm.toast(context.getString(R.string.err_bad_url)) else { vm.import(req); onDismiss() }
    }

    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            val req = readDocument(context, uri)
            if (req == null) vm.toast(context.getString(R.string.err_read_file)) else { vm.import(req); onDismiss() }
        }
    }

    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = c.bg) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp).padding(bottom = 28.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.add_profile), fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = c.text)
            AppCard {
                OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(stringResource(R.string.sub_url)) }, leadingIcon = { Icon(Icons.Filled.Link, null) })
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth(), singleLine = true,
                    label = { Text(stringResource(R.string.name_optional)) })
                Spacer(Modifier.height(10.dp))
                Button(
                    onClick = {
                        val req = ImportRouter.fromText(url)
                        when (req) {
                            is ImportRouter.Request.Remote -> { vm.import(req.copy(name = name.ifBlank { req.name })); onDismiss() }
                            is ImportRouter.Request.Text -> { vm.import(req.copy(name = name)); onDismiss() }
                            null -> vm.toast(context.getString(R.string.err_bad_url))
                            else -> { vm.import(req); onDismiss() }
                        }
                    },
                    enabled = url.isNotBlank() && !importing,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(stringResource(R.string.download_import)) }
                Text(stringResource(R.string.ua_hint), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(top = 6.dp))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                SourceTile(Icons.Filled.ContentPaste, stringResource(R.string.from_clipboard), Modifier.weight(1f)) {
                    val cm = context.getSystemService(ClipboardManager::class.java)
                    val clip = cm?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
                    val req = ImportRouter.fromText(clip)
                    if (req == null) vm.toast(context.getString(R.string.clipboard_empty))
                    else { vm.import(req); onDismiss() }
                }
                SourceTile(Icons.Filled.FolderOpen, stringResource(R.string.from_file), Modifier.weight(1f)) {
                    pickFile.launch(arrayOf("*/*"))
                }
                SourceTile(Icons.Filled.QrCodeScanner, stringResource(R.string.qr_scan), Modifier.weight(1f)) { scanQr() }
                @Suppress("DEPRECATION")
                SourceTile(Icons.Filled.TextSnippet, stringResource(R.string.from_text), Modifier.weight(1f)) { showText = !showText }
            }
            if (showText) {
                AppCard {
                    OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth().heightIn(min = 140.dp),
                        placeholder = { Text(stringResource(R.string.paste_hint)) })
                    Spacer(Modifier.height(8.dp))
                    Button(onClick = {
                        ImportRouter.fromText(text)?.let { vm.import(it); onDismiss() }
                    }, enabled = text.isNotBlank() && !importing, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.import_)) }
                }
            }
            Text(stringResource(R.string.formats_hint), fontSize = 11.sp, color = c.secondary)
        }
    }
}

@Composable
private fun SourceTile(icon: ImageVector, label: String, modifier: Modifier, onClick: () -> Unit) {
    val c = LocalAppColors.current
    Column(
        modifier.clip(RoundedCornerShape(14.dp)).background(c.card).clickable(onClick = onClick).padding(vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(icon, null, tint = c.accent)
        Spacer(Modifier.height(6.dp))
        Text(label, fontSize = 12.sp, color = c.text)
    }
}
