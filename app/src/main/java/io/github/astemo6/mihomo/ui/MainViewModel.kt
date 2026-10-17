package io.github.astemo6.mihomo.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ConnectionItem
import io.github.astemo6.mihomo.api.ControllerClient
import io.github.astemo6.mihomo.api.IpInfo
import io.github.astemo6.mihomo.api.LogLine
import io.github.astemo6.mihomo.api.ProxyItem
import io.github.astemo6.mihomo.api.RuleItem
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.EngineException
import io.github.astemo6.mihomo.data.EngineModule
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.ParsedEngineText
import io.github.astemo6.mihomo.data.ImportException
import io.github.astemo6.mihomo.data.ImportRouter
import io.github.astemo6.mihomo.data.Overrides
import io.github.astemo6.mihomo.data.Profile
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnInfo
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.vpn.VpnStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicLong

enum class Panel { NODES, ACTIVITY, RULES, REWRITE, LOGS }

/** One policy-group card (live from /proxies, or offline from InspectProfile). */
data class GroupCard(
    val name: String,
    val type: String,
    val now: String?,
    val members: List<String>,
    val chain: List<String>,
    val icon: String?,
    val selectable: Boolean,
    val fixed: String?,
)

data class ResourceCard(
    val profile: Profile?,
    val nodes: List<String>,
)

@Serializable
private data class InspectProxy(val name: String, val type: String = "", val source: String? = null)

@Serializable
private data class InspectGroup(
    val name: String,
    val type: String = "",
    val proxies: List<String>? = null,
    val use: List<String>? = null,
    val hidden: Boolean = false,
    val icon: String? = null,
    val selected: String? = null,
)

@Serializable
private data class InspectRule(val type: String = "", val payload: String = "", val proxy: String = "")

@Serializable
private data class InspectProvider(val name: String, val proxies: List<InspectProxy>? = null)

@Serializable
private data class InspectResult(
    val mode: String = "rule",
    val proxies: List<InspectProxy> = emptyList(),
    val groups: List<InspectGroup> = emptyList(),
    val rules: List<InspectRule> = emptyList(),
    val proxyProviders: List<InspectProvider> = emptyList(),
    val error: String? = null,
)

data class Message(val id: Long, val text: String)

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val ctx get() = getApplication<Application>()

    val vpn: StateFlow<VpnInfo> = VpnState.info
    val profiles = ProfileStore.profiles
    val activeId = ProfileStore.activeId
    val updating = ProfileStore.updating

    private val _panel = MutableStateFlow(Panel.NODES)
    val panel: StateFlow<Panel> = _panel.asStateFlow()

    private val _mode = MutableStateFlow(Overrides.load().mode)
    val mode: StateFlow<String> = _mode.asStateFlow()

    private val _ip = MutableStateFlow(AppSettings.lastIpInfo?.let { runCatching { AppJson.decodeFromString(IpInfo.serializer(), it) }.getOrNull() })
    val ip: StateFlow<IpInfo?> = _ip.asStateFlow()
    private val _ipLoading = MutableStateFlow(false)
    val ipLoading: StateFlow<Boolean> = _ipLoading.asStateFlow()

    private val _groups = MutableStateFlow<List<GroupCard>>(emptyList())
    val groups: StateFlow<List<GroupCard>> = _groups.asStateFlow()
    private val _resource = MutableStateFlow(ResourceCard(null, emptyList()))
    val resource: StateFlow<ResourceCard> = _resource.asStateFlow()
    private val _nodeTypes = MutableStateFlow<Map<String, String>>(emptyMap())
    val nodeTypes: StateFlow<Map<String, String>> = _nodeTypes.asStateFlow()

    private val _delays = MutableStateFlow<Map<String, Int>>(emptyMap())
    val delays: StateFlow<Map<String, Int>> = _delays.asStateFlow()
    private val _testing = MutableStateFlow<Set<String>>(emptySet())
    val testing: StateFlow<Set<String>> = _testing.asStateFlow()

    private val _connections = MutableStateFlow<List<ConnectionItem>>(emptyList())
    val connections: StateFlow<List<ConnectionItem>> = _connections.asStateFlow()
    private val _totals = MutableStateFlow(0L to 0L)
    val totals: StateFlow<Pair<Long, Long>> = _totals.asStateFlow()
    private val _speed = MutableStateFlow(0L to 0L)
    val speed: StateFlow<Pair<Long, Long>> = _speed.asStateFlow()

    private val _rules = MutableStateFlow<List<RuleItem>>(emptyList())
    val rules: StateFlow<List<RuleItem>> = _rules.asStateFlow()

    private val _logs = MutableStateFlow<List<LogLine>>(emptyList())
    val logs: StateFlow<List<LogLine>> = _logs.asStateFlow()
    private val _logLevel = MutableStateFlow("info")
    val logLevel: StateFlow<String> = _logLevel.asStateFlow()
    private val _logsPaused = MutableStateFlow(false)
    val logsPaused: StateFlow<Boolean> = _logsPaused.asStateFlow()
    private val logSeq = AtomicLong()

    private val _message = MutableStateFlow<Message?>(null)
    val message: StateFlow<Message?> = _message.asStateFlow()
    private val msgSeq = AtomicLong()

    private val _importing = MutableStateFlow(false)
    val importing: StateFlow<Boolean> = _importing.asStateFlow()

    /** An import that came from outside (link / share sheet) waiting for the user's OK. */
    private val _pendingImport = MutableStateFlow<ImportRouter.Request?>(null)
    val pendingImport: StateFlow<ImportRouter.Request?> = _pendingImport.asStateFlow()

    val running: StateFlow<Boolean> = vpn.map { it.status == VpnStatus.RUNNING }.distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    private var liveJobs = mutableListOf<Job>()
    private var logJob: Job? = null

    init {
        viewModelScope.launch {
            running.collect { on ->
                liveJobs.forEach { it.cancel() }
                liveJobs.clear()
                logJob?.cancel()
                if (on) startLive() else {
                    _connections.value = emptyList()
                    _speed.value = 0L to 0L
                    loadOffline()
                }
                delay(if (on) 1200 else 300)
                refreshIp()
            }
        }
        viewModelScope.launch {
            activeId.collect { if (!running.value) loadOffline() }
        }
        viewModelScope.launch { ProfileStore.autoUpdateIfNeeded() }
    }

    fun toast(text: String) {
        _message.value = Message(msgSeq.incrementAndGet(), text)
    }

    fun consumeMessage(id: Long) {
        if (_message.value?.id == id) _message.value = null
    }

    fun setPanel(p: Panel) {
        _panel.value = p
        if (p == Panel.RULES && running.value) viewModelScope.launch { loadLiveRules() }
    }

    // ---- live (core running) ------------------------------------------------------------------

    private fun startLive() {
        _logs.value = emptyList()
        liveJobs += viewModelScope.launch {
            while (isActive) {
                runCatching { applyLiveProxies(ControllerClient.proxies()) }
                delay(5000)
            }
        }
        liveJobs += viewModelScope.launch {
            while (isActive) {
                ControllerClient.traffic().catch { }.collect { _speed.value = it.up to it.down }
                delay(2000)
            }
        }
        liveJobs += viewModelScope.launch {
            while (isActive) {
                ControllerClient.connectionsStream().catch { }.collect { r ->
                    _connections.value = (r.connections ?: emptyList()).sortedByDescending { it.start ?: "" }
                    _totals.value = (r.uploadTotal ?: 0L) to (r.downloadTotal ?: 0L)
                }
                delay(2000)
            }
        }
        liveJobs += viewModelScope.launch {
            runCatching {
                val m = ControllerClient.configs()["mode"]?.toString()?.trim('"')
                if (!m.isNullOrEmpty()) _mode.value = m.lowercase()
            }
            loadLiveRules()
        }
        restartLogs()
    }

    private suspend fun loadLiveRules() {
        runCatching { _rules.value = ControllerClient.rules() }
    }

    private fun applyLiveProxies(p: Map<String, ProxyItem>) {
        val global = p["GLOBAL"]
        val order = global?.all.orEmpty().filter { p[it]?.isGroup == true }
        val names = (order + p.values.filter { it.isGroup && it.name != "GLOBAL" }.map { it.name }.sorted()).distinct()
        val cards = names.mapNotNull { n ->
            val g = p[n] ?: return@mapNotNull null
            if (g.hidden == true) return@mapNotNull null
            val chain = mutableListOf(n)
            var cur = g.now
            while (cur != null && chain.size < 6 && cur !in chain) {
                chain += cur
                cur = p[cur]?.now
            }
            GroupCard(n, g.type, g.now, g.all.orEmpty(), chain, g.icon, g.isSelectable, g.fixed?.ifEmpty { null })
        }
        _groups.value = cards
        val url = Overrides.load().testUrlOrDefault
        val d = p.values.mapNotNull { item -> item.lastDelay(url)?.let { item.name to it } }.toMap()
        _delays.update { old -> old + d }
        val leaves = p.values.filter { !it.isGroup && it.type !in setOf("Direct", "Reject", "RejectDrop", "Pass", "Compatible", "Dns") }
        _nodeTypes.value = p.mapValues { it.value.type }
        _resource.value = ResourceCard(ProfileStore.active, leaves.map { it.name }.sorted())
        cards.firstOrNull()?.let { c -> VpnState.update { it.copy(nodeText = c.chain.joinToString(" ➤ ")) } }
    }

    fun restartLogs() {
        logJob?.cancel()
        if (!running.value) return
        val level = _logLevel.value
        logJob = viewModelScope.launch {
            while (isActive) {
                ControllerClient.logs(level).catch { }.collect { l ->
                    if (_logsPaused.value) return@collect
                    val line = LogLine(logSeq.incrementAndGet(), l.type, l.payload, System.currentTimeMillis())
                    _logs.update { (listOf(line) + it).take(500) }
                }
                delay(2000)
            }
        }
    }

    fun setLogLevel(level: String) {
        _logLevel.value = level
        restartLogs()
    }

    fun toggleLogsPaused() { _logsPaused.update { !it } }
    fun clearLogs() { _logs.value = emptyList() }

    // ---- offline (core stopped): the same cards from the profile file -------------------------

    private var offlinePath: String? = null

    private fun loadOffline() {
        val p = ProfileStore.active
        if (p == null) {
            _groups.value = emptyList(); _rules.value = emptyList(); _resource.value = ResourceCard(null, emptyList())
            return
        }
        viewModelScope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { AppJson.decodeFromString(InspectResult.serializer(), Core.inspectProfile(p.file.absolutePath)) }.getOrNull()
            } ?: return@launch
            offlinePath = p.file.absolutePath
            val providerNodes = r.proxyProviders.associate { pp -> pp.name to pp.proxies.orEmpty().map { it.name } }
            val cards = r.groups.filter { !it.hidden }.map { g ->
                val members = (g.proxies.orEmpty() + g.use.orEmpty().flatMap { providerNodes[it].orEmpty() }).distinct()
                GroupCard(g.name, g.type, g.selected ?: members.firstOrNull(), members, emptyList(), g.icon,
                    g.type == "select", null)
            }
            val byName = cards.associateBy { it.name }
            _groups.value = cards.map { c ->
                val chain = mutableListOf(c.name)
                var cur = c.now
                while (cur != null && chain.size < 6 && cur !in chain) {
                    chain += cur
                    cur = byName[cur]?.now
                }
                c.copy(chain = chain)
            }
            _rules.value = r.rules.mapIndexed { i, x -> RuleItem(i, x.type, x.payload, x.proxy) }
            val all = r.proxies.map { it.name } + providerNodes.values.flatten()
            _nodeTypes.value = (r.proxies + r.proxyProviders.flatMap { it.proxies.orEmpty() }).associate { it.name to it.type }
            _resource.value = ResourceCard(p, all.distinct())
            if (r.mode.isNotEmpty() && Overrides.load().mode.isEmpty()) _mode.value = r.mode
        }
    }

    // ---- actions ------------------------------------------------------------------------------

    fun select(group: GroupCard, node: String) {
        if (running.value) {
            viewModelScope.launch {
                runCatching { ControllerClient.select(group.name, node) }
                    .onFailure { toast(it.message ?: "") }
                // Persist like iOS so the choice survives the next start.
                ProfileStore.active?.let { p -> withContext(Dispatchers.IO) { Core.saveSelection(p.file.absolutePath, group.name, node) } }
                runCatching { applyLiveProxies(ControllerClient.proxies()) }
            }
        } else if (group.selectable) {
            val p = ProfileStore.active ?: return
            viewModelScope.launch {
                withContext(Dispatchers.IO) { Core.saveSelection(p.file.absolutePath, group.name, node) }
                loadOffline()
            }
        }
    }

    fun testGroup(group: GroupCard) {
        if (group.name in _testing.value) return
        _testing.update { it + group.name }
        viewModelScope.launch {
            try {
                if (running.value) {
                    val r = runCatching { ControllerClient.groupDelay(group.name) }.getOrElse { emptyMap() }
                    _delays.update { old -> old + group.members.associateWith { r[it] ?: 0 } }
                } else {
                    testOffline(group.members)
                }
            } finally {
                _testing.update { it - group.name }
            }
        }
    }

    fun testNodes(names: List<String>, key: String) {
        if (key in _testing.value) return
        _testing.update { it + key }
        viewModelScope.launch {
            try {
                if (running.value) {
                    val sem = Semaphore(8)
                    names.map { n -> async { sem.withPermit { n to runCatching { ControllerClient.proxyDelay(n) }.getOrDefault(0) } } }
                        .awaitAll().let { res -> _delays.update { it + res.toMap() } }
                } else testOffline(names)
            } finally {
                _testing.update { it - key }
            }
        }
    }

    fun testNode(name: String) = testNodes(listOf(name), "node:$name")

    private suspend fun testOffline(names: List<String>) {
        val p = offlinePath ?: return
        val o = Overrides.load()
        val groupNames = _groups.value.map { it.name }.toSet()
        val sem = Semaphore(6)
        val res = withContext(Dispatchers.IO) {
            names.filter { it !in groupNames && it != "DIRECT" && it != "REJECT" }.map { n ->
                async { sem.withPermit { n to Core.testDelayByName(p, n, o.testUrlOrDefault, o.testTimeout).coerceAtLeast(0) } }
            }.awaitAll()
        }
        _delays.update { it + res.toMap() }
    }

    fun setMode(m: String) {
        _mode.value = m
        Overrides.update { it.copy(mode = m) }
        VpnState.update { it.copy(mode = m) }
        if (running.value) viewModelScope.launch {
            runCatching { ControllerClient.setMode(m) }.onFailure { toast(it.message ?: "") }
            runCatching { ControllerClient.closeAllConnections() }
        }
    }

    fun closeConnection(id: String) = viewModelScope.launch { runCatching { ControllerClient.closeConnection(id) } }
    fun closeAllConnections() = viewModelScope.launch { runCatching { ControllerClient.closeAllConnections() } }

    fun refreshIp() {
        if (_ipLoading.value) return
        _ipLoading.value = true
        viewModelScope.launch {
            val info = IpInfo.fetch()
            if (info != null) {
                _ip.value = info
                AppSettings.lastIpInfo = AppJson.encodeToString(IpInfo.serializer(), info)
            }
            _ipLoading.value = false
        }
    }

    // ---- VPN ----------------------------------------------------------------------------------

    fun connect() {
        if (ProfileStore.active == null) {
            toast(ctx.getString(R.string.err_no_profile)); return
        }
        VpnController.start(ctx)
    }

    fun disconnect() = VpnController.stop(ctx)
    fun clearVpnError() = VpnState.clearError()

    /** Apply changed settings: reload the core when running. */
    fun applySettings() = VpnController.reload(ctx)

    // ---- profiles / import --------------------------------------------------------------------

    fun setActive(p: Profile) = ProfileStore.setActive(p)
    fun deleteProfile(p: Profile) = ProfileStore.delete(p)
    fun renameProfile(p: Profile, name: String) = ProfileStore.rename(p, name)
    fun setInterval(p: Profile, h: Int) = ProfileStore.setInterval(p, h)

    fun refreshProfile(p: Profile) = viewModelScope.launch {
        val err = ProfileStore.refresh(p)
        toast(if (err == null) ctx.getString(R.string.msg_updated, p.name) else ctx.getString(R.string.msg_update_failed, describe(err)))
    }

    fun refreshAll() = viewModelScope.launch {
        val errs = ProfileStore.refreshAll()
        toast(if (errs.isEmpty()) ctx.getString(R.string.msg_all_updated) else errs.joinToString("\n") { describe(it) })
    }

    fun offerImport(req: ImportRouter.Request) { _pendingImport.value = req }
    fun dismissImport() { _pendingImport.value = null }

    fun import(req: ImportRouter.Request) {
        _pendingImport.value = null
        if (_importing.value) return
        _importing.value = true
        viewModelScope.launch {
            try {
                when (req) {
                    is ImportRouter.Request.Remote -> {
                        val p = ProfileStore.addRemote(req.url, req.name)
                        toast(ctx.getString(R.string.msg_imported, p.name))
                    }
                    is ImportRouter.Request.Text -> {
                        val (p, note) = ProfileStore.addLocal(req.name, req.text)
                        toast(ctx.getString(R.string.msg_imported, p.name) + (note?.let { "\n$it" } ?: ""))
                    }
                    is ImportRouter.Request.ModuleUrl -> importModule { EngineStore.addModule(req.url) }
                    is ImportRouter.Request.ModuleText -> importModule { EngineStore.addModuleText(req.text, req.name) }
                }
                if (!running.value) loadOffline()
            } catch (e: ImportException) {
                // ClassifyText said module:* (pasted text, a shared file or a URL that turned out to be a module).
                val msg = e.message.orEmpty()
                if (msg.startsWith("MODULE:")) {
                    when (req) {
                        is ImportRouter.Request.Remote -> importModule { EngineStore.addModule(req.url) }
                        is ImportRouter.Request.Text -> importModule { EngineStore.addModuleText(req.text, req.name) }
                        else -> toast(ctx.getString(R.string.msg_import_failed, describe(msg)))
                    }
                } else toast(ctx.getString(R.string.msg_import_failed, describe(msg)))
            } catch (e: Exception) {
                toast(ctx.getString(R.string.msg_import_failed, e.message ?: e.toString()))
            } finally {
                _importing.value = false
            }
        }
    }

    private suspend fun importModule(block: suspend () -> Pair<EngineModule, ParsedEngineText>) {
        try {
            val (m, p) = block()
            val scripts = p.rules.count { it.kind == "script" }
            var msg = ctx.getString(R.string.msg_module_added, m.name, p.rules.size - scripts, scripts, p.hostnames.size)
            if (p.unsupported.isNotEmpty()) msg += "\n" + ctx.getString(R.string.msg_module_unsupported, p.unsupported.size)
            if (p.hostnames.isNotEmpty() && !EngineStore.ca.value.exists) msg += "\n" + ctx.getString(R.string.msg_module_needs_ca)
            toast(msg)
        } catch (e: EngineException) {
            toast(ctx.getString(R.string.msg_import_failed, describe(e.message ?: "")))
        } catch (e: Exception) {
            toast(ctx.getString(R.string.msg_import_failed, e.message ?: e.toString()))
        }
    }

    /** Maps the store's error codes to localized text. */
    fun describe(code: String): String = when {
        code == "BAD_URL" -> ctx.getString(R.string.err_bad_url)
        code == "EMPTY" -> ctx.getString(R.string.err_empty)
        code == "UNRECOGNIZED" -> ctx.getString(R.string.err_unrecognized)
        code.startsWith("MODULE:") -> ctx.getString(R.string.err_unrecognized)
        code == "EMPTY_MODULE" -> ctx.getString(R.string.err_empty_module)
        code == "DUPLICATE" -> ctx.getString(R.string.err_duplicate_module)
        else -> code
    }
}
