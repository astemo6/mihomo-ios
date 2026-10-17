package io.github.astemo6.mihomo.data.feature2

import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.Profile
import io.github.astemo6.mihomo.data.ProfileStore
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/**
 * 手动节点 (iOS ProfileStore manual-nodes section): a local profile with id "manual-nodes" whose file
 * (filesDir/profiles/manual-nodes.yaml) the bridge edits (ManualList / ManualAddText / ManualUpsert /
 * ManualDelete) and, with overrides.mergeManual, merges into every profile.
 *
 * [ensureProfile] adds the fixed-id index entry through [ProfileStore.ensureProfile].
 */
object ManualNodes {
    const val ID = ProfileStore.MANUAL_ID
    val path: String get() = Paths.profile(ID).absolutePath

    val profile: Profile? get() = ProfileStore.profiles.value.firstOrNull { it.id == ID }

    fun ensureProfile(defaultName: String): Profile {
        profile?.let { return it }
        if (!Paths.profile(ID).exists()) F2Core.manualDelete(path, "") // writes an empty manual profile
        return ProfileStore.ensureProfile(ID, defaultName, first = true)
    }

    fun list(): List<JsonObject> {
        if (!Paths.profile(ID).exists()) return emptyList()
        return runCatching { AppJson.parseToJsonElement(F2Core.manualList(path)).jsonArray.map { it.jsonObject } }
            .getOrDefault(emptyList())
    }

    /** Number added; throws with the parser's message. */
    fun addText(defaultName: String, text: String): Int {
        ensureProfile(defaultName)
        val n = F2Core.manualAddText(path, text)
        if (n < 0) throw IllegalArgumentException(F2Core.lastError().ifBlank { "?" })
        return n
    }

    fun upsert(defaultName: String, node: JsonObject, oldName: String?) {
        ensureProfile(defaultName)
        val err = F2Core.manualUpsert(path, node.toString(), oldName.orEmpty())
        if (err.isNotEmpty()) throw IllegalArgumentException(err)
    }

    fun delete(name: String) { F2Core.manualDelete(path, name) }

    fun shareLink(node: JsonObject): String = F2Core.nodeShareLink(node.toString())

    /** All manual nodes as one base64 subscription text. */
    fun subscription(): String = F2Core.manualSubscription(path)

    val isActive: Boolean get() = ProfileStore.activeId.value == ID
}
