package io.github.astemo6.mihomo.ui.settings

import androidx.compose.foundation.background
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.UiLayout
import io.github.astemo6.mihomo.ui.Panel
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.SettingsGroup
import io.github.astemo6.mihomo.ui.home.panelSpec
import io.github.astemo6.mihomo.ui.home.toolbarSpec
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

/** 面板 & 工具栏: reorder / hide the home panels and the floating toolbar buttons. */
@Composable
fun PanelsToolbarScreen(onBack: () -> Unit) {
    val c = LocalAppColors.current
    val panelOrder by UiLayout.panelOrder.collectAsState()
    val hiddenPanels by UiLayout.hiddenPanels.collectAsState()
    val toolbar by UiLayout.toolbarOrder.collectAsState()
    val hiddenToolbar by UiLayout.hiddenToolbar.collectAsState()
    @Suppress("UNUSED_VARIABLE") val dep = panelOrder // recompose on order changes
    val panels = UiLayout.orderedPanels(Panel.entries.toList()) { it.name }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.panels_toolbar), onBack) {
            TextButton(onClick = { UiLayout.reset() }) { Text(stringResource(R.string.reset)) }
        }
    }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp)) {
            item { SectionTitle(stringResource(R.string.panels)) }
            item {
                SettingsGroup {
                    panels.forEachIndexed { i, p ->
                        val spec = panelSpec(p)
                        ReorderRow(
                            label = stringResource(spec.label), icon = spec.icon, color = spec.color,
                            visible = p.name !in hiddenPanels,
                            canUp = i > 0, canDown = i < panels.lastIndex, showDivider = i < panels.lastIndex,
                            onVisible = { UiLayout.setPanelHidden(p.name, !it, Panel.entries.size) },
                            onMove = { d ->
                                val l = panels.map { it.name }.toMutableList()
                                val j = i + d
                                l.removeAt(i); l.add(j, p.name)
                                UiLayout.setPanelOrder(l)
                            },
                        )
                    }
                }
            }
            item { Text(stringResource(R.string.panels_desc), fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(6.dp)) }
            item { SectionTitle(stringResource(R.string.toolbar)) }
            item {
                SettingsGroup {
                    toolbar.forEachIndexed { i, t ->
                        val spec = toolbarSpec(t)
                        ReorderRow(
                            label = stringResource(spec.label), icon = spec.icon, color = c.accent,
                            visible = t !in hiddenToolbar,
                            canUp = i > 0, canDown = i < toolbar.lastIndex, showDivider = i < toolbar.lastIndex,
                            onVisible = { UiLayout.setToolbarHidden(t, !it) },
                            onMove = { d -> UiLayout.moveToolbar(t, d) },
                        )
                    }
                }
            }
            item { Text(stringResource(R.string.toolbar_desc), fontSize = 12.sp, color = c.secondary, modifier = Modifier.padding(6.dp)) }
        }
    }
}

@Composable
private fun ReorderRow(
    label: String, icon: ImageVector, color: Color, visible: Boolean,
    canUp: Boolean, canDown: Boolean, showDivider: Boolean,
    onVisible: (Boolean) -> Unit, onMove: (Int) -> Unit,
) {
    val c = LocalAppColors.current
    Column {
        Row(Modifier.fillMaxWidth().padding(start = 14.dp, end = 6.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(28.dp).clip(RoundedCornerShape(7.dp)).background(if (visible) color else c.secondary), contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = Color.White, modifier = Modifier.size(18.dp))
            }
            Spacer(Modifier.width(12.dp))
            Text(label, fontSize = 15.sp, color = if (visible) c.text else c.secondary, modifier = Modifier.weight(1f))
            IconButton(onClick = { onMove(-1) }, enabled = canUp) { Icon(Icons.Filled.KeyboardArrowUp, stringResource(R.string.move_up)) }
            IconButton(onClick = { onMove(1) }, enabled = canDown) { Icon(Icons.Filled.KeyboardArrowDown, stringResource(R.string.move_down)) }
            Switch(visible, onVisible, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
        }
        if (showDivider) HorizontalDivider(Modifier.padding(start = 54.dp), color = c.separator, thickness = 0.5.dp)
    }
}
