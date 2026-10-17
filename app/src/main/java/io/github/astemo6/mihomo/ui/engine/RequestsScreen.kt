package io.github.astemo6.mihomo.ui.engine

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.api.ApiException
import io.github.astemo6.mihomo.data.DebugSample
import io.github.astemo6.mihomo.data.EngineApi
import io.github.astemo6.mihomo.data.HttpReqDetail
import io.github.astemo6.mihomo.data.HttpReqSummary
import io.github.astemo6.mihomo.data.ReplayEdit
import io.github.astemo6.mihomo.data.ReplayResult
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * HTTP 请求 (iOS 请求 → HTTP): requests seen by the HTTP engine (GET /mitm/requests, polled every 1.5 s),
 * with a detail view (headers / bodies, cURL, replay, edit-and-replay, debug a script with it).
 */
@Composable
fun RequestsScreen(vm: MainViewModel, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val running by vm.running.collectAsState()
    val scope = rememberCoroutineScope()
    var items by remember { mutableStateOf<List<HttpReqSummary>>(emptyList()) }
    var error by remember { mutableStateOf<String?>(null) }
    var query by remember { mutableStateOf("") }
    var detail by remember { mutableStateOf<Long?>(null) }
    var debugSample by remember { mutableStateOf<DebugSample?>(null) }

    LaunchedEffect(running) {
        if (!running) return@LaunchedEffect
        while (isActive) {
            runCatching { EngineApi.requests() }
                .onSuccess { items = it.sortedByDescending { r -> r.id }; error = null }
                .onFailure { error = it.message }
            delay(1500)
        }
    }

    debugSample?.let { s ->
        BackHandler { debugSample = null }
        ScriptEditorScreen(vm, ScriptTarget.Scratch, initialSample = s, onBack = { debugSample = null })
        return
    }
    detail?.let { id ->
        BackHandler { detail = null }
        RequestDetailScreen(vm, id, onBack = { detail = null }, onDebug = { debugSample = it })
        return
    }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(stringResource(R.string.e2_requests), onBack) {
            TextButton(onClick = { scope.launch { runCatching { EngineApi.clearRequests() }; items = emptyList() } }, enabled = running) {
                Text(stringResource(R.string.clear))
            }
        }
    }) { pad ->
        val shown = if (query.isBlank()) items else items.filter { it.url.contains(query, true) || it.matched.orEmpty().any { m -> m.contains(query, true) } }
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            item {
                OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), singleLine = true,
                    placeholder = { Text(stringResource(R.string.e2_requests_search)) })
            }
            when {
                !running -> item { AppCard { EmptyHint(stringResource(R.string.need_running)) } }
                error != null && items.isEmpty() -> item { AppCard { Text(error.orEmpty(), color = c.bad, fontSize = 12.sp) } }
                shown.isEmpty() -> item { AppCard { EmptyHint(stringResource(R.string.e2_requests_empty)) } }
            }
            items(shown, key = { it.id }) { r -> RequestRow(r) { detail = r.id } }
        }
    }
}

@Composable
private fun RequestRow(r: HttpReqSummary, onClick: () -> Unit) {
    val c = LocalAppColors.current
    AppCard(Modifier.clickable(onClick = onClick), padding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Tag(r.method, c.accent)
            if (r.mitm) { Spacer(Modifier.width(4.dp)); Tag("MitM", c.warn) }
            Spacer(Modifier.width(6.dp))
            Text(r.host, fontFamily = FontFamily.Monospace, fontSize = 13.sp, color = c.text, maxLines = 1,
                overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
            val st = if (r.status > 0) r.status.toString() else if (r.done) "—" else "…"
            Text(st, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = when {
                r.status >= 400 || (r.status == 0 && r.done) -> c.bad
                r.status >= 300 -> c.warn
                else -> c.good
            })
        }
        Text(r.path, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.secondary, maxLines = 2, overflow = TextOverflow.Ellipsis)
        r.matched?.takeIf { it.isNotEmpty() }?.let { Text(it.joinToString(" · "), fontSize = 11.sp, color = c.accent, maxLines = 2) }
        r.notes?.takeIf { it.isNotEmpty() }?.let { Text(it.joinToString(" · "), fontSize = 11.sp, color = c.warn, maxLines = 2) }
        Text(listOfNotNull(
            Fmt.time((r.time * 1000).toLong()),
            r.duration?.let { "${it.toInt()} ms" },
            Fmt.bytes(r.bytes),
            if (r.local) stringResource(R.string.e2_local_response) else null,
        ).joinToString("  "), fontSize = 11.sp, color = c.secondary)
    }
}

@Composable
private fun RequestDetailScreen(vm: MainViewModel, id: Long, onBack: () -> Unit, onDebug: (DebugSample) -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var d by remember { mutableStateOf<HttpReqDetail?>(null) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var tab by remember { mutableIntStateOf(0) }
    var replaying by remember { mutableStateOf(false) }
    var replay by remember { mutableStateOf<ReplayResult?>(null) }
    var replayError by remember { mutableStateOf<String?>(null) }
    var editing by remember { mutableStateOf(false) }

    LaunchedEffect(id) {
        runCatching { EngineApi.request(id) }.onSuccess { d = it }.onFailure { loadError = it.message }
    }

    fun runReplay(edit: ReplayEdit?) {
        replaying = true; replayError = null; replay = null
        scope.launch {
            try {
                val r = EngineApi.replay(id, edit)
                if (r.error != null) replayError = r.error else replay = r
            } catch (e: ApiException) {
                replayError = e.message
            } catch (e: Exception) {
                replayError = e.message ?: e.toString()
            } finally { replaying = false }
        }
    }

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.e2_request_detail), onBack) }) { pad ->
        val x = d
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (x == null) {
                item {
                    AppCard {
                        if (loadError != null) Text(loadError.orEmpty(), color = c.bad, fontSize = 12.sp)
                        else CircularProgressIndicator(Modifier.size(24.dp).align(Alignment.CenterHorizontally))
                    }
                }
                return@LazyColumn
            }
            item {
                AppCard {
                    SelectionContainer { Text(x.url, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text) }
                    Spacer(Modifier.height(6.dp))
                    KvLine(stringResource(R.string.e2_method_status), "${x.method} · ${x.status}")
                    x.duration?.let { KvLine(stringResource(R.string.e2_duration), "${it.toInt()} ms") }
                    KvLine(stringResource(R.string.e2_size), Fmt.bytes(x.bytes))
                    KvLine(stringResource(R.string.e2_https_decrypt), stringResource(if (x.mitm) R.string.e2_yes else R.string.e2_no_plain))
                }
            }
            item { SectionTitle(stringResource(R.string.e2_actions)) }
            item {
                AppCard {
                    TextButton(onClick = { copyText(ctx, x.curl); vm.toast(ctx.getString(R.string.e2_copied)) }) { Text(stringResource(R.string.e2_copy_curl)) }
                    TextButton(onClick = { runReplay(null) }, enabled = x.canReplay && !replaying) { Text(stringResource(R.string.e2_replay)) }
                    TextButton(onClick = { editing = true }, enabled = x.canReplay && !replaying) { Text(stringResource(R.string.e2_edit_replay)) }
                    if (x.method != "TLS") TextButton(onClick = { onDebug(DebugSample.from(x)) }) { Text(stringResource(R.string.e2_debug_with_request)) }
                    if (!x.canReplay && x.method != "TLS") Text(stringResource(R.string.e2_cannot_replay), fontSize = 11.sp, color = c.secondary)
                    if (replaying) CircularProgressIndicator(Modifier.size(20.dp))
                    replayError?.let { Text(it, fontSize = 12.sp, color = c.bad) }
                    replay?.let { ReplayResultView(it) }
                    Text(stringResource(R.string.e2_replay_note), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(top = 4.dp))
                }
            }
            x.matched?.takeIf { it.isNotEmpty() }?.let { m ->
                item { SectionTitle(stringResource(R.string.e2_matched)) }
                item { AppCard { m.forEach { Text(it, fontSize = 12.sp, color = c.text) } } }
            }
            x.notes?.takeIf { it.isNotEmpty() }?.let { n ->
                item { SectionTitle(stringResource(R.string.e2_notes)) }
                item { AppCard { n.forEach { Text(it, fontSize = 12.sp, color = c.warn) } } }
            }
            item {
                TabRow(selectedTabIndex = tab, containerColor = c.bg) {
                    Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.e2_request)) })
                    Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.e2_response)) })
                }
            }
            val headers = (if (tab == 0) x.reqHeaders else x.respHeaders).orEmpty()
            item { SectionTitle(stringResource(R.string.e2_headers_n, headers.size)) }
            item { AppCard { if (headers.isEmpty()) Text("—", color = c.secondary) else HeaderLines(headers) } }
            item { SectionTitle(stringResource(R.string.e2_body)) }
            item {
                AppCard {
                    val body = if (tab == 0) x.reqBody else x.respBody
                    val bin = if (tab == 0) x.reqBodyBinary else x.respBodyBinary
                    when {
                        !body.isNullOrEmpty() -> {
                            val pretty = remember(body) { prettyBody(body) }
                            SelectionContainer { Text(pretty.take(100_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text) }
                            TextButton(onClick = { copyText(ctx, body); vm.toast(ctx.getString(R.string.e2_copied)) }) { Text(stringResource(R.string.e2_copy)) }
                        }
                        bin > 0 -> Text(stringResource(R.string.e2_body_binary, Fmt.bytes(bin.toLong()) +
                            (if (tab == 1) x.respEncoding?.let { ", $it" }.orEmpty() else "")), fontSize = 12.sp, color = c.secondary)
                        else -> Text(stringResource(R.string.e2_body_none), fontSize = 12.sp, color = c.secondary)
                    }
                }
            }
        }
    }

    if (editing) d?.let { x -> ReplayEditor(x, onSend = { editing = false; runReplay(it) }, onDismiss = { editing = false }) }
}

@Composable
private fun ReplayResultView(r: ReplayResult) {
    val c = LocalAppColors.current
    var show by remember { mutableStateOf(false) }
    Column(Modifier.padding(top = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("HTTP ${r.status}", fontWeight = FontWeight.Bold, color = if (r.status in 200..399) c.good else c.bad)
            Spacer(Modifier.width(8.dp))
            Text("${r.duration.toInt()} ms · ${Fmt.bytes(r.length.toLong())}", fontSize = 12.sp, color = c.secondary, modifier = Modifier.weight(1f))
            TextButton(onClick = { show = !show }) { Text(stringResource(if (show) R.string.e2_collapse else R.string.e2_view_response)) }
        }
        if (show) {
            HeaderLines(r.headers)
            when {
                !r.body.isNullOrEmpty() -> SelectionContainer {
                    Text(prettyBody(r.body).take(100_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text)
                }
                r.binary > 0 -> Text(stringResource(R.string.e2_body_binary, Fmt.bytes(r.binary.toLong())), fontSize = 12.sp, color = c.secondary)
            }
        }
    }
}

@Composable
private fun ReplayEditor(d: HttpReqDetail, onSend: (ReplayEdit) -> Unit, onDismiss: () -> Unit) {
    var method by remember { mutableStateOf(d.method) }
    var url by remember { mutableStateOf(d.url) }
    var headers by remember { mutableStateOf(DebugSample.headerText(d.reqHeaders)) }
    var body by remember { mutableStateOf(d.reqBody.orEmpty()) }
    val mono = androidx.compose.ui.text.TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.e2_edit_replay)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(method, { method = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text(stringResource(R.string.e2_method)) })
                OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), textStyle = mono, label = { Text("URL") })
                OutlinedTextField(headers, { headers = it }, Modifier.fillMaxWidth().height(140.dp), textStyle = mono,
                    label = { Text(stringResource(R.string.e2_headers_hint)) })
                OutlinedTextField(body, { body = it }, Modifier.fillMaxWidth().height(120.dp), textStyle = mono,
                    label = { Text(stringResource(R.string.e2_body)) })
            }
        },
        confirmButton = {
            TextButton(onClick = {
                onSend(ReplayEdit(method.trim().uppercase(), url.trim(), DebugSample.headers(headers), body))
            }, enabled = url.isNotBlank()) { Text(stringResource(R.string.e2_send)) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}
