package io.github.astemo6.mihomo.ui.components

import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Image
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.GroupIconStore
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.util.concurrent.TimeUnit

/** Popular QX-style icon galleries (JSON {name, icons:[{name,url}]}), same list as iOS. */
private data class IconSetSource(val name: String, val author: String, val index: String)

private val iconSets = listOf(
    IconSetSource("Qure Color", "Koolson/Qure", "https://raw.githubusercontent.com/Koolson/Qure/master/Other/QureColor.json"),
    IconSetSource("mini", "Orz-3/mini", "https://raw.githubusercontent.com/Orz-3/mini/master/mini.json"),
    IconSetSource("Hand Painted", "Semporia/Hand-Painted-icon", "https://raw.githubusercontent.com/Semporia/Hand-Painted-icon/master/Semporia.json"),
)

@Serializable
private data class IconGallery(val name: String? = null, val icons: List<Icon> = emptyList()) {
    @Serializable
    data class Icon(val name: String = "", val url: String = "")
}

/** The group's icon with the user's override applied (group-icons.json), else the profile `icon:`, else [fallback]. */
@Composable
fun UserGroupIcon(group: String, profileIcon: String?, size: androidx.compose.ui.unit.Dp, fallback: @Composable () -> Unit) {
    val custom by GroupIconStore.custom.collectAsState()
    LaunchedEffect(Unit) { GroupIconStore.ensureLoaded() }
    GroupIcon(GroupIconStore.iconUrl(group, profileIcon, custom), size, fallback)
}

/** Full-screen picker (iOS GroupIconPicker): image URL, icon galleries, follow profile / default, clear cache. */
@Composable
fun GroupIconPicker(group: String, profileIcon: String?, onDismiss: () -> Unit) {
    val c = LocalAppColors.current
    val custom by GroupIconStore.custom.collectAsState()
    val scope = rememberCoroutineScope()
    var urlText by remember { mutableStateOf(custom[group].orEmpty()) }
    var urlError by remember { mutableStateOf<String?>(null) }
    var checking by remember { mutableStateOf(false) }
    var gallery by remember { mutableStateOf<IconSetSource?>(null) }
    val errUrl = stringResource(R.string.e2_icon_bad_url)
    val errLoad = stringResource(R.string.e2_icon_load_failed)
    val hasProfileIcon = IconCache.isImageUrl(profileIcon)

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        gallery?.let { set ->
            BackHandler { gallery = null }
            IconSetGrid(set, onBack = { gallery = null }) { url -> GroupIconStore.set(group, url); onDismiss() }
            return@Dialog
        }
        Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.e2_group_icon), onDismiss) }) { pad ->
            LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    AppCard {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(52.dp).clip(RoundedCornerShape(12.dp)).background(c.accent.copy(alpha = 0.1f)), contentAlignment = Alignment.Center) {
                                GroupIcon(GroupIconStore.iconUrl(group, profileIcon, custom), 44.dp) {
                                    Icon(Icons.Filled.Image, null, tint = c.accent)
                                }
                            }
                            Spacer(Modifier.width(12.dp))
                            Column {
                                Text(group, fontWeight = FontWeight.SemiBold, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(stringResource(when {
                                    custom[group] == "" -> R.string.e2_icon_src_default_chosen
                                    custom[group] != null -> R.string.e2_icon_src_custom
                                    hasProfileIcon -> R.string.e2_icon_src_profile
                                    else -> R.string.e2_icon_src_default
                                }), fontSize = 12.sp, color = c.secondary)
                            }
                        }
                    }
                }
                item { SectionTitle(stringResource(R.string.e2_icon_url)) }
                item {
                    AppCard {
                        OutlinedTextField(urlText, { urlText = it; urlError = null }, Modifier.fillMaxWidth(), singleLine = true,
                            placeholder = { Text("https://…/icon.png") },
                            textStyle = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp))
                        urlError?.let { Text(it, fontSize = 12.sp, color = c.warn) }
                        Button(onClick = {
                            val t = urlText.trim()
                            if (!IconCache.isImageUrl(t)) { urlError = errUrl; return@Button }
                            checking = true
                            scope.launch {
                                val ok = IconCache.load(t) != null
                                checking = false
                                if (!ok) urlError = errLoad else { GroupIconStore.set(group, t); onDismiss() }
                            }
                        }, enabled = urlText.isNotBlank() && !checking, modifier = Modifier.fillMaxWidth().padding(top = 6.dp)) {
                            if (checking) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                            else Text(stringResource(R.string.e2_icon_use_url))
                        }
                    }
                }
                item { SectionTitle(stringResource(R.string.e2_icon_galleries)) }
                items(iconSets) { set ->
                    SettingsGroup {
                        SettingsRow(set.name, subtitle = set.author, showDivider = false, onClick = { gallery = set })
                    }
                }
                item { Text(stringResource(R.string.e2_icon_galleries_note), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(horizontal = 6.dp)) }
                item {
                    SettingsGroup {
                        if (custom[group] != null) SettingsRow(
                            stringResource(if (hasProfileIcon) R.string.e2_icon_follow_profile else R.string.e2_icon_restore),
                            onClick = { GroupIconStore.set(group, null); onDismiss() }, trailing = {})
                        if (custom[group] != "" && (custom[group] != null || hasProfileIcon)) SettingsRow(
                            stringResource(R.string.e2_icon_use_default), onClick = { GroupIconStore.set(group, ""); onDismiss() }, trailing = {})
                        SettingsRow(stringResource(R.string.e2_icon_clear_cache), showDivider = false, onClick = {
                            IconCache.clear()
                        }, trailing = {})
                    }
                }
                item { Text(stringResource(R.string.e2_icon_local_note), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(horizontal = 6.dp)) }
            }
        }
    }
}

private val galleryHttp by lazy { OkHttpClient.Builder().connectTimeout(10, TimeUnit.SECONDS).readTimeout(20, TimeUnit.SECONDS).build() }

@Composable
private fun IconSetGrid(set: IconSetSource, onBack: () -> Unit, onPick: (String) -> Unit) {
    val c = LocalAppColors.current
    var icons by remember { mutableStateOf<List<IconGallery.Icon>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var search by remember { mutableStateOf("") }

    LaunchedEffect(set) {
        val cache = File(File(Paths.root, "icon-cache").apply { mkdirs() }, "index-" + set.index.hashCode().toUInt().toString(16) + ".json")
        withContext(Dispatchers.IO) { runCatching { AppJson.decodeFromString(IconGallery.serializer(), cache.readText()) }.getOrNull() }
            ?.let { icons = it.icons; loading = false }
        runCatching {
            withContext(Dispatchers.IO) {
                galleryHttp.newCall(Request.Builder().url(IconCache.mirrored(set.index)).build()).execute().use { r ->
                    if (!r.isSuccessful) error("HTTP ${r.code}")
                    val text = r.body?.string().orEmpty()
                    val g = AppJson.decodeFromString(IconGallery.serializer(), text)
                    runCatching { cache.writeText(text) }
                    g
                }
            }
        }.onSuccess { icons = it.icons; error = null }.onFailure { if (icons.isEmpty()) error = it.message ?: it.toString() }
        loading = false
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(set.name, onBack) }) { pad ->
        val shown = if (search.isBlank()) icons else icons.filter { it.name.contains(search, true) }
        LazyVerticalGrid(GridCells.Adaptive(72.dp), Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item(span = { GridItemSpan(maxLineSpan) }) {
                Column {
                    OutlinedTextField(search, { search = it }, Modifier.fillMaxWidth(), singleLine = true,
                        placeholder = { Text(stringResource(R.string.e2_icon_search)) })
                    if (loading && icons.isEmpty()) CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp))
                    error?.let { Text(stringResource(R.string.e2_icon_gallery_failed, it), color = c.bad, fontSize = 12.sp) }
                }
            }
            items(shown) { icon ->
                Column(Modifier.clickable { onPick(icon.url) }, horizontalAlignment = Alignment.CenterHorizontally) {
                    Box(Modifier.size(60.dp).clip(RoundedCornerShape(12.dp)).background(c.card), contentAlignment = Alignment.Center) {
                        GroupIcon(icon.url, 44.dp) { CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 1.5.dp) }
                    }
                    Text(icon.name.removeSuffix(".png"), fontSize = 9.sp, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
        }
    }
}
