package io.github.astemo6.mihomo.data

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Toolbar buttons that can be reordered / hidden (the windmill is always last and never hidden). */
enum class ToolbarItem { SEARCH, ADD, STATS, DNS, REQUESTS }

/** Panel strip order + hidden panels, toolbar order + hidden buttons ("面板 & 工具栏"). Stored by enum name. */
object UiLayout {
    private lateinit var prefs: SharedPreferences

    /** Panel names in the order shown (names of ui.Panel; kept as strings to stay UI-independent). */
    private val _panelOrder = MutableStateFlow<List<String>>(emptyList())
    val panelOrder: StateFlow<List<String>> = _panelOrder.asStateFlow()
    private val _hiddenPanels = MutableStateFlow<Set<String>>(emptySet())
    val hiddenPanels: StateFlow<Set<String>> = _hiddenPanels.asStateFlow()

    private val _toolbarOrder = MutableStateFlow(ToolbarItem.entries.toList())
    val toolbarOrder: StateFlow<List<ToolbarItem>> = _toolbarOrder.asStateFlow()
    private val _hiddenToolbar = MutableStateFlow<Set<ToolbarItem>>(emptySet())
    val hiddenToolbar: StateFlow<Set<ToolbarItem>> = _hiddenToolbar.asStateFlow()

    fun init(context: Context) {
        prefs = context.getSharedPreferences("ui_layout", Context.MODE_PRIVATE)
        _panelOrder.value = prefs.getString("panelOrder", "").orEmpty().split(',').filter { it.isNotBlank() }
        _hiddenPanels.value = prefs.getString("hiddenPanels", "").orEmpty().split(',').filter { it.isNotBlank() }.toSet()
        val saved = prefs.getString("toolbarOrder", "").orEmpty().split(',')
            .mapNotNull { n -> ToolbarItem.entries.firstOrNull { it.name == n } }
        _toolbarOrder.value = (saved + ToolbarItem.entries).distinct()
        _hiddenToolbar.value = prefs.getString("hiddenToolbar", "").orEmpty().split(',')
            .mapNotNull { n -> ToolbarItem.entries.firstOrNull { it.name == n } }.toSet()
    }

    /** Applies the saved order to [all] (unknown / new names keep their default position at the end). */
    fun <T> orderedPanels(all: List<T>, name: (T) -> String): List<T> {
        val order = _panelOrder.value
        return all.sortedBy { p -> order.indexOf(name(p)).let { if (it < 0) Int.MAX_VALUE else it } }
    }

    fun setPanelOrder(names: List<String>) {
        _panelOrder.value = names
        prefs.edit().putString("panelOrder", names.joinToString(",")).apply()
    }

    fun setPanelHidden(name: String, hidden: Boolean, total: Int) {
        val cur = _hiddenPanels.value
        val next = if (hidden) cur + name else cur - name
        if (next.size >= total) return // keep at least one panel
        _hiddenPanels.value = next
        prefs.edit().putString("hiddenPanels", next.joinToString(",")).apply()
    }

    fun setToolbarOrder(items: List<ToolbarItem>) {
        _toolbarOrder.value = items
        prefs.edit().putString("toolbarOrder", items.joinToString(",") { it.name }).apply()
    }

    fun setToolbarHidden(item: ToolbarItem, hidden: Boolean) {
        val next = if (hidden) _hiddenToolbar.value + item else _hiddenToolbar.value - item
        _hiddenToolbar.value = next
        prefs.edit().putString("hiddenToolbar", next.joinToString(",") { it.name }).apply()
    }

    fun moveToolbar(item: ToolbarItem, delta: Int) {
        val l = _toolbarOrder.value.toMutableList()
        val i = l.indexOf(item)
        val j = (i + delta).coerceIn(0, l.lastIndex)
        if (i < 0 || i == j) return
        l.removeAt(i); l.add(j, item)
        setToolbarOrder(l)
    }

    fun reset() {
        setPanelOrder(emptyList())
        _hiddenPanels.value = emptySet()
        setToolbarOrder(ToolbarItem.entries.toList())
        _hiddenToolbar.value = emptySet()
        prefs.edit().remove("hiddenPanels").remove("hiddenToolbar").apply()
    }
}
