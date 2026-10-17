package io.github.astemo6.mihomo.data

import io.github.astemo6.mihomo.core.Paths
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import java.io.File

/**
 * User policy-group icon overrides, like the iOS GroupIconStore: `<home>/group-icons.json`
 * (group name → image URL; "" = always the default avatar even when the profile has an `icon:`).
 * Never written into the profile.
 */
object GroupIconStore {
    private val ser = MapSerializer(String.serializer(), String.serializer())
    private val _custom = MutableStateFlow<Map<String, String>>(emptyMap())
    val custom: StateFlow<Map<String, String>> = _custom.asStateFlow()
    private var loaded = false

    private val file: File get() = File(Paths.home, "group-icons.json")

    fun reload() {
        _custom.value = runCatching { AppJson.decodeFromString(ser, file.readText()) }.getOrDefault(emptyMap())
        loaded = true
    }

    fun ensureLoaded() { if (!loaded) reload() }

    /** The image URL to show for a group, or null for the default avatar. */
    fun iconUrl(group: String, profileIcon: String?, map: Map<String, String> = _custom.value): String? {
        map[group]?.let { return it.ifEmpty { null } }
        val p = profileIcon?.trim().orEmpty()
        return if (p.startsWith("http://", true) || p.startsWith("https://", true)) p else null
    }

    /** null = follow the profile; "" = default avatar; otherwise an image URL. */
    @Synchronized
    fun set(group: String, url: String?) {
        ensureLoaded()
        val m = _custom.value.toMutableMap()
        if (url == null) m.remove(group) else m[group] = url
        _custom.value = m
        val tmp = File(Paths.home, "group-icons.json.tmp")
        tmp.writeText(AppJson.encodeToString(ser, m.toSortedMap()))
        if (!tmp.renameTo(file)) { file.writeText(tmp.readText()); tmp.delete() }
    }
}
