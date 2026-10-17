package io.github.astemo6.mihomo.ui.settings

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private data class AppEntry(val pkg: String, val label: String, val system: Boolean, val icon: ImageBitmap?)

/** 分应用代理 (Android only): allow-list (only these apps use the VPN) or deny-list (these bypass it). */
@Composable
fun PerAppScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    var mode by remember { mutableStateOf(AppSettings.perAppMode) }
    var selected by remember { mutableStateOf(AppSettings.perAppPackages) }
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    var changed by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            @Suppress("DEPRECATION")
            pm.getInstalledApplications(PackageManager.GET_META_DATA)
                .filter { it.packageName != context.packageName }
                .map { ai ->
                    AppEntry(
                        ai.packageName,
                        ai.loadLabel(pm).toString(),
                        (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0,
                        runCatching { ai.loadIcon(pm).toBitmap(72, 72).asImageBitmap() }.getOrNull(),
                    )
                }
                .sortedWith(compareBy({ it.pkg !in AppSettings.perAppPackages }, { it.label.lowercase() }))
        }
    }

    fun persist(m: AppSettings.PerAppMode = mode, s: Set<String> = selected) {
        AppSettings.perAppMode = m
        AppSettings.perAppPackages = s
        changed = true
    }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.per_app), onBack) {
            TextButton(onClick = { showSystem = !showSystem }) {
                Text(stringResource(if (showSystem) R.string.hide_system else R.string.show_system), fontSize = 13.sp)
            }
        }
    }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                AppCard(padding = PaddingValues(4.dp)) {
                    Row(Modifier.fillMaxWidth()) {
                        listOf(
                            AppSettings.PerAppMode.OFF to R.string.off,
                            AppSettings.PerAppMode.ALLOW to R.string.per_app_allow,
                            AppSettings.PerAppMode.DENY to R.string.per_app_deny,
                        ).forEach { (m, label) ->
                            val sel = m == mode
                            Box(
                                Modifier.weight(1f).clip(RoundedCornerShape(10.dp))
                                    .background(if (sel) c.accent else androidx.compose.ui.graphics.Color.Transparent)
                                    .clickable { mode = m; persist(m = m) }
                                    .padding(vertical = 8.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(stringResource(label), color = if (sel) androidx.compose.ui.graphics.Color.White else c.text, fontSize = 14.sp)
                            }
                        }
                    }
                }
            }
            item {
                Text(stringResource(when (mode) {
                    AppSettings.PerAppMode.OFF -> R.string.per_app_off_desc
                    AppSettings.PerAppMode.ALLOW -> R.string.per_app_allow_desc
                    AppSettings.PerAppMode.DENY -> R.string.per_app_deny_desc
                }) + if (changed) "\n" + stringResource(R.string.reconnect_to_apply) else "",
                    fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(horizontal = 6.dp))
            }
            item {
                OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, null) }, placeholder = { Text(stringResource(R.string.search)) },
                    shape = RoundedCornerShape(12.dp))
            }
            val list = apps
            if (list == null) {
                item { Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() } }
            } else {
                val shown = list.filter { (showSystem || !it.system || it.pkg in selected) &&
                    (query.isBlank() || it.label.contains(query, true) || it.pkg.contains(query, true)) }
                items(shown, key = { it.pkg }) { a ->
                    val checked = a.pkg in selected
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(c.card)
                            .clickable(enabled = mode != AppSettings.PerAppMode.OFF) {
                                selected = if (checked) selected - a.pkg else selected + a.pkg
                                persist(s = selected)
                            }
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (a.icon != null) Image(a.icon, null, Modifier.size(36.dp)) else Spacer(Modifier.size(36.dp))
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(a.label, fontSize = 14.sp, color = c.text, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(a.pkg, fontSize = 11.sp, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                        Checkbox(checked = checked, enabled = mode != AppSettings.PerAppMode.OFF, onCheckedChange = {
                            selected = if (checked) selected - a.pkg else selected + a.pkg
                            persist(s = selected)
                        })
                    }
                }
            }
        }
    }
}
