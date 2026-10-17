package io.github.astemo6.mihomo.ui.settings

import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.AltRoute
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.AutoFixHigh
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.SettingsEthernet
import androidx.compose.material.icons.filled.SpaceDashboard
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.os.LocaleListCompat
import io.github.astemo6.mihomo.BuildConfig
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.Routes
import io.github.astemo6.mihomo.ui.feature2.Feature2Routes
import androidx.compose.material.icons.automirrored.filled.ListAlt
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.BarChart
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.automirrored.filled.ManageSearch
import androidx.compose.material.icons.filled.MedicalServices
import io.github.astemo6.mihomo.ui.Panel
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import io.github.astemo6.mihomo.ui.theme.PanelColors

private data class GridItem(val label: Int, val icon: ImageVector, val color: Color, val onClick: () -> Unit)

/** QX-style settings: section button grid, then 面板 & 工具栏 and 其他设置. */
@Composable
fun SettingsScreen(
    vm: MainViewModel,
    onBack: () -> Unit,
    navigate: (String) -> Unit,
) {
    val c = LocalAppColors.current
    val theme by AppSettings.theme.collectAsState()
    var showTheme by remember { mutableStateOf(false) }
    var showLang by remember { mutableStateOf(false) }
    var showAbout by remember { mutableStateOf(false) }

    val goPanel: (Panel) -> Unit = { p -> vm.setPanel(p); onBack() }
    val grid = listOf(
        GridItem(R.string.sec_nodes, Icons.Filled.Public, PanelColors.nodes) { goPanel(Panel.NODES) },
        GridItem(R.string.sec_rules, Icons.AutoMirrored.Filled.AltRoute, PanelColors.rules) { goPanel(Panel.RULES) },
        GridItem(R.string.sec_rewrite, Icons.Filled.AutoFixHigh, PanelColors.rewrite) { navigate(Routes.REWRITE) },
        GridItem(R.string.sec_mitm, Icons.Filled.Lock, Color(0xFFFF2D55)) { navigate(Routes.MITM) },
        GridItem(R.string.sec_tools, Icons.Filled.Build, PanelColors.logs) { goPanel(Panel.LOGS) },
        GridItem(R.string.sec_profiles, Icons.Filled.Folder, Color(0xFF5856D6)) { navigate(Routes.PROFILES) },
    )
    // 数据 & 工具: DNS / scripts here, the rest are the A2 data screens (ui/feature2, routes are plain strings).
    val grid2 = listOf(
        GridItem(R.string.dns, Icons.Filled.Dns, Color(0xFF32ADE6)) { navigate(Routes.DNS) },
        GridItem(R.string.scripts, Icons.Filled.Code, PanelColors.rewrite) { navigate(Routes.SCRIPTS) },
        GridItem(R.string.f2_rulesets, Icons.AutoMirrored.Filled.ListAlt, PanelColors.rules) { navigate(Feature2Routes.RULESETS) },
        GridItem(R.string.f2_dnslog, Icons.AutoMirrored.Filled.ManageSearch, Color(0xFF5AC8FA)) { navigate(Feature2Routes.DNSLOG) },
        GridItem(R.string.f2_traffic, Icons.Filled.BarChart, PanelColors.activity) { navigate(Feature2Routes.TRAFFIC) },
        GridItem(R.string.f2_nodesubs, Icons.Filled.CloudSync, PanelColors.nodes) { navigate(Feature2Routes.NODESUBS) },
        GridItem(R.string.f2_groups, Icons.Filled.AccountTree, Color(0xFFFF9F0A)) { navigate(Feature2Routes.GROUPS) },
        GridItem(R.string.f2_manualnodes, Icons.Filled.EditNote, Color(0xFF30B0C7)) { navigate(Feature2Routes.MANUALNODES) },
        GridItem(R.string.f2_diagnostics, Icons.Filled.MedicalServices, Color(0xFF8E8E93)) { navigate(Feature2Routes.DIAGNOSTICS) },
    )

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.settings), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            item { ButtonGrid(grid) }
            item { SectionTitle(stringResource(R.string.sec_data_tools)) }
            item { ButtonGrid(grid2) }
            item { SectionTitle(stringResource(R.string.sec_panels_toolbar)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.panels_toolbar), stringResource(R.string.panels_toolbar_desc),
                        icon = Icons.Filled.SpaceDashboard, iconTint = PanelColors.activity, showDivider = false,
                        onClick = { navigate(Routes.PANELS) })
                }
            }
            item { SectionTitle(stringResource(R.string.sec_other)) }
            item {
                SettingsGroup {
                    SettingsRow(stringResource(R.string.connection), stringResource(R.string.connection_desc),
                        icon = Icons.Filled.SettingsEthernet, iconTint = PanelColors.nodes, onClick = { navigate(Routes.CONNECTION) })
                    SettingsRow(stringResource(R.string.per_app), stringResource(R.string.per_app_desc),
                        icon = Icons.Filled.Apps, iconTint = PanelColors.rules, onClick = { navigate(Routes.PER_APP) },
                        value = stringResource(when (AppSettings.perAppMode) {
                            AppSettings.PerAppMode.OFF -> R.string.off
                            AppSettings.PerAppMode.ALLOW -> R.string.per_app_allow
                            AppSettings.PerAppMode.DENY -> R.string.per_app_deny
                        }))
                    SettingsRow(stringResource(R.string.appearance), icon = Icons.Filled.DarkMode, iconTint = Color(0xFF636366),
                        value = stringResource(themeLabel(theme)), onClick = { showTheme = true })
                    SettingsRow(stringResource(R.string.language), icon = Icons.Filled.Language, iconTint = Color(0xFF32ADE6),
                        value = currentLanguageLabel(), onClick = { showLang = true })
                    SettingsRow(stringResource(R.string.about), icon = Icons.Filled.Info, iconTint = Color(0xFF8E8E93),
                        value = BuildConfig.VERSION_NAME, showDivider = false, onClick = { showAbout = true })
                }
            }
        }
    }

    if (showTheme) {
        ChoiceDialog(
            title = stringResource(R.string.appearance),
            options = AppSettings.Theme.entries.map { it to stringResource(themeLabel(it)) },
            selected = theme,
            onPick = { AppSettings.setTheme(it); showTheme = false },
            onDismiss = { showTheme = false },
        )
    }
    if (showLang) {
        val current = AppCompatDelegate.getApplicationLocales().toLanguageTags()
        ChoiceDialog(
            title = stringResource(R.string.language),
            options = listOf("" to stringResource(R.string.follow_system), "zh-Hans" to "简体中文", "zh-Hant" to "繁體中文", "en" to "English"),
            selected = current,
            onPick = { tag ->
                showLang = false
                AppCompatDelegate.setApplicationLocales(if (tag.isEmpty()) LocaleListCompat.getEmptyLocaleList() else LocaleListCompat.forLanguageTags(tag))
            },
            onDismiss = { showLang = false },
        )
    }
    if (showAbout) {
        val core = remember { Core.version }
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text(stringResource(R.string.app_name)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("${stringResource(R.string.version)} ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})")
                    Text(core.ifEmpty { "mihomo" })
                    Text(stringResource(R.string.license_note), fontSize = 12.sp, color = c.secondary)
                }
            },
            confirmButton = { TextButton(onClick = { showAbout = false }) { Text(stringResource(R.string.ok)) } },
        )
    }
}

@Composable
private fun ButtonGrid(items: List<GridItem>) {
    val c = LocalAppColors.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        items.chunked(3).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                row.forEach { g ->
                    Column(
                        Modifier.weight(1f).aspectRatio(1.15f).clip(RoundedCornerShape(14.dp)).background(c.card)
                            .clickable(onClick = g.onClick).padding(10.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally,
                    ) {
                        Box(Modifier.size(38.dp).clip(RoundedCornerShape(10.dp)).background(g.color), contentAlignment = Alignment.Center) {
                            Icon(g.icon, null, tint = Color.White, modifier = Modifier.size(22.dp))
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(stringResource(g.label), fontSize = 13.sp, color = c.text, textAlign = TextAlign.Center, maxLines = 2)
                    }
                }
                repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
}

private fun themeLabel(t: AppSettings.Theme): Int = when (t) {
    AppSettings.Theme.SYSTEM -> R.string.follow_system
    AppSettings.Theme.LIGHT -> R.string.theme_light
    AppSettings.Theme.DARK -> R.string.theme_dark
}

@Composable
private fun currentLanguageLabel(): String = when (AppCompatDelegate.getApplicationLocales().toLanguageTags()) {
    "" -> stringResource(R.string.follow_system)
    "zh-Hans", "zh-CN" -> "简体中文"
    "zh-Hant", "zh-TW", "zh-HK" -> "繁體中文"
    "en" -> "English"
    else -> AppCompatDelegate.getApplicationLocales().toLanguageTags()
}

@Composable
fun <T> ChoiceDialog(title: String, options: List<Pair<T, String>>, selected: T, onPick: (T) -> Unit, onDismiss: () -> Unit) {
    val c = LocalAppColors.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                options.forEach { (v, label) ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).clickable { onPick(v) }.padding(vertical = 12.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(label, modifier = Modifier.weight(1f), fontWeight = if (v == selected) FontWeight.SemiBold else FontWeight.Normal)
                        if (v == selected) Box(Modifier.size(8.dp).clip(RoundedCornerShape(4.dp)).background(c.accent))
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
