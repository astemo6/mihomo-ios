package io.github.astemo6.mihomo.data.feature2

import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.AppJson
import kotlinx.serialization.Serializable

/** The parts of bridge InspectProfile (the runtime view of a profile, offline) that feature2 needs. */
@Serializable
data class InspectProxyF2(val name: String, val type: String = "", val server: String? = null, val port: Int? = null, val source: String? = null)

@Serializable
data class InspectGroupF2(
    val name: String,
    val type: String = "",
    val proxies: List<String>? = null,
    val use: List<String>? = null,
    val hidden: Boolean = false,
    val selected: String? = null,
)

@Serializable
data class InspectRuleF2(val type: String = "", val payload: String = "", val proxy: String = "")

@Serializable
data class InspectProviderF2(val name: String, val vehicle: String? = null, val count: Int = 0, val proxies: List<InspectProxyF2>? = null)

@Serializable
data class InspectF2(
    val proxies: List<InspectProxyF2> = emptyList(),
    val groups: List<InspectGroupF2> = emptyList(),
    val rules: List<InspectRuleF2> = emptyList(),
    val proxyProviders: List<InspectProviderF2> = emptyList(),
    val error: String? = null,
) {
    /** Every node name (inline + cached provider nodes). */
    val allNodeNames: List<String> get() = (proxies.map { it.name } + proxyProviders.flatMap { p -> p.proxies.orEmpty().map { it.name } }).distinct()

    companion object {
        fun load(path: String): InspectF2 =
            runCatching { AppJson.decodeFromString(serializer(), Core.inspectProfile(path)) }.getOrDefault(InspectF2())
    }
}

@Serializable
data class ChainCandidate(val name: String, val type: String = "", val group: Boolean = false)

@Serializable
data class ChainCandidates(val current: String = "", val candidates: List<ChainCandidate> = emptyList()) {
    companion object {
        /** 前置代理 candidates of a node ("node") or group ("group") that would not form a loop. */
        fun load(profilePath: String, kind: String, name: String): ChainCandidates =
            runCatching { AppJson.decodeFromString(serializer(), F2Core.chainCandidates(profilePath, kind, name)) }.getOrDefault(ChainCandidates())
    }
}
