package io.github.astemo6.mihomo.data.feature2

import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppJson
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File
import java.util.UUID

/** Pretty JSON for the override stores the Go bridge reads (same files and keys as the iOS app). */
internal val StoreJson = Json(AppJson) { prettyPrint = true; encodeDefaults = true; explicitNulls = false }

internal object JsonFiles {
    fun <T> read(file: File, s: KSerializer<T>): T? =
        runCatching { if (file.exists()) AppJson.decodeFromString(s, file.readText()) else null }.getOrNull()

    fun <T> write(file: File, s: KSerializer<T>, value: T) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(StoreJson.encodeToString(s, value))
        if (!tmp.renameTo(file)) { file.writeText(tmp.readText()); tmp.delete() }
    }
}

// ---------------------------------------------------------------------------------------------------
// 节点处理 rules: <home>/subscriptions.json, keyed by profile id or "nodesub-<id>" (bridge/subrules.go)

@Serializable
data class RenameRule(val pattern: String = "", val replace: String = "", val enabled: Boolean = true)

@Serializable
data class SubRules(
    val enabled: Boolean = true,
    val include: String = "",
    val exclude: String = "",
    val regex: Boolean = false,
    val stripPrefixes: List<String> = emptyList(),
    val stripFlags: Boolean = false,
    val renames: List<RenameRule> = emptyList(),
    val addFlag: Boolean = false,
    val prefix: String = "",
    val dedupe: Boolean = false,
    /** "" keep | name | region */
    val sort: String = "",
) {
    val isEmpty: Boolean
        get() = include.isEmpty() && exclude.isEmpty() && stripPrefixes.isEmpty() && !stripFlags && renames.isEmpty() &&
            !addFlag && prefix.isEmpty() && !dedupe && sort.isEmpty()
}

object SubRulesStore {
    private val file: File get() = File(Paths.home, "subscriptions.json")
    private val ser = MapSerializer(String.serializer(), SubRules.serializer())

    fun all(): Map<String, SubRules> = JsonFiles.read(file, ser) ?: emptyMap()
    fun get(key: String): SubRules? = all()[key]
    fun set(key: String, rules: SubRules?) {
        val m = all().toMutableMap()
        if (rules == null) m.remove(key) else m[key] = rules
        JsonFiles.write(file, ser, m)
    }
}

@Serializable
data class SubPreviewNode(
    val original: String = "",
    val name: String = "",
    val type: String = "",
    val region: String? = null,
    val kept: Boolean = false,
    val reason: String? = null,
    val source: String? = null,
)

@Serializable
data class SubPreviewResult(
    val nodes: List<SubPreviewNode> = emptyList(),
    val total: Int = 0,
    val kept: Int = 0,
    val providers: List<String> = emptyList(),
    val errors: List<String> = emptyList(),
)

// ---------------------------------------------------------------------------------------------------
// 自定义规则 / remote rule lists: <home>/rules.json {"rules":[…]} (bridge/customrules.go)

@Serializable
data class CustomRule(
    val id: String = UUID.randomUUID().toString(),
    val line: String,
    val enabled: Boolean = true,
    /** remote lists: seconds (default 86400) */
    val interval: Int? = null,
) {
    val isRemote: Boolean get() = line.contains("://")
}

@Serializable
private data class CustomRulesFile(val rules: List<CustomRule> = emptyList())

@Serializable
data class RuleCheck(
    val id: String? = null,
    val line: String? = null,
    val enabled: Boolean? = null,
    val rule: String? = null,
    val policy: String? = null,
    val error: String? = null,
    val note: String? = null,
    val unresolved: String? = null,
)

object CustomRulesStore {
    private val file: File get() = File(Paths.home, "rules.json")

    fun load(): List<CustomRule> = JsonFiles.read(file, CustomRulesFile.serializer())?.rules ?: emptyList()
    fun save(rules: List<CustomRule>) = JsonFiles.write(file, CustomRulesFile.serializer(), CustomRulesFile(rules))

    /** id → check of every rule against the active profile. */
    fun checks(): Map<String, RuleCheck> {
        val path = F2Core.activePath ?: return emptyMap()
        val list = runCatching {
            AppJson.decodeFromString(ListSerializer(RuleCheck.serializer()), F2Core.checkCustomRules(path))
        }.getOrDefault(emptyList())
        return list.mapNotNull { c -> c.id?.let { it to c } }.toMap()
    }

    fun check(line: String): RuleCheck? {
        val path = F2Core.activePath ?: return null
        return runCatching { AppJson.decodeFromString(RuleCheck.serializer(), F2Core.checkRuleLine(path, line)) }.getOrNull()
    }

    /** Policy groups of the active profile (targets for pickers). */
    fun profileGroups(): List<String> {
        val path = F2Core.activePath ?: return emptyList()
        return runCatching { AppJson.decodeFromString(ListSerializer(String.serializer()), F2Core.profileGroups(path)) }
            .getOrDefault(emptyList())
    }
}

// ---------------------------------------------------------------------------------------------------
// 策略组编辑: <home>/group-edits.json {"<profile id>": GroupEdits} (bridge/groupedits.go)

@Serializable
data class GroupSpec(
    val name: String,
    val type: String = "select",
    val proxies: List<String> = emptyList(),
    val use: List<String>? = null,
    val includeAll: Boolean? = null,
    val filter: String? = null,
    val excludeFilter: String? = null,
    val url: String? = null,
    val interval: Int? = null,
    val tolerance: Int? = null,
    val lazy: Boolean? = null,
    val strategy: String? = null,
    val icon: String? = null,
    val hidden: Boolean? = null,
)

@Serializable
data class GroupEdit(val deleted: Boolean? = null, val spec: GroupSpec? = null)

@Serializable
data class GroupEdits(val edits: Map<String, GroupEdit>? = null, val added: List<GroupSpec>? = null) {
    val isEmpty: Boolean get() = edits.isNullOrEmpty() && added.isNullOrEmpty()
}

@Serializable
data class GroupSpecsResult(
    val groups: List<GroupSpec> = emptyList(),
    val providers: List<String> = emptyList(),
    val proxies: List<String> = emptyList(),
)

object GroupEditStore {
    private val file: File get() = File(Paths.home, "group-edits.json")
    private val ser = MapSerializer(String.serializer(), GroupEdits.serializer())

    fun all(): Map<String, GroupEdits> = JsonFiles.read(file, ser) ?: emptyMap()
    fun get(profileId: String): GroupEdits = all()[profileId] ?: GroupEdits()
    fun set(profileId: String, e: GroupEdits) {
        val m = all().toMutableMap()
        if (e.isEmpty) m.remove(profileId) else m[profileId] = e
        JsonFiles.write(file, ser, m)
    }

    fun json(e: GroupEdits): String = AppJson.encodeToString(GroupEdits.serializer(), e)

    fun specs(profilePath: String): GroupSpecsResult =
        runCatching { AppJson.decodeFromString(GroupSpecsResult.serializer(), F2Core.groupSpecs(profilePath)) }
            .getOrDefault(GroupSpecsResult())
}

// ---------------------------------------------------------------------------------------------------
// 智能选择 / 前置代理: <home>/groups.json {"<profile id>": {"smart": [..], "dialer": {group: via}}} (bridge/smart.go, chain.go)

@Serializable
data class GroupSettings(val smart: List<String>? = null, val dialer: Map<String, String>? = null)

@Serializable
data class SmartMember(val name: String, val score: Double = -1.0, val avg: Int = 0, val fails: Int = 0, val count: Int = 0, val alive: Boolean = false)

@Serializable
data class SmartStatus(
    val name: String,
    val type: String? = null,
    val now: String? = null,
    val pinned: String? = null,
    val switchedAt: Double? = null,
    val checkedAt: Double? = null,
    val members: List<SmartMember>? = null,
)

@Serializable
data class SmartStatusResponse(val groups: List<SmartStatus> = emptyList())

object SmartGroupsStore {
    private val file: File get() = File(Paths.home, "groups.json")
    private val ser = MapSerializer(String.serializer(), GroupSettings.serializer())

    fun all(): Map<String, GroupSettings> = JsonFiles.read(file, ser) ?: emptyMap()

    fun isSmart(profileId: String, group: String): Boolean = all()[profileId]?.smart?.contains(group) == true

    fun setSmart(profileId: String, group: String, on: Boolean) {
        val m = all().toMutableMap() // re-read: Go writes `dialer` into the same file
        val st = m[profileId] ?: GroupSettings()
        val list = st.smart.orEmpty().filter { it != group } + if (on) listOf(group) else emptyList()
        m[profileId] = st.copy(smart = list.ifEmpty { null })
        JsonFiles.write(file, ser, m)
    }

    fun via(profileId: String, group: String): String? = all()[profileId]?.dialer?.get(group)
}
