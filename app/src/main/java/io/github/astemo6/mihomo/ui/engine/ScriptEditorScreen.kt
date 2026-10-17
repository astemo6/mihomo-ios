package io.github.astemo6.mihomo.ui.engine

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.DebugOutput
import io.github.astemo6.mihomo.data.DebugSample
import io.github.astemo6.mihomo.data.EngineExtras
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.ScriptDebugger
import io.github.astemo6.mihomo.ui.MainViewModel
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.components.Tag
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What the script editor opens. */
sealed interface ScriptTarget {
    /** Empty workbench with a template. */
    data object Scratch : ScriptTarget
    /** engine/scripts/<name> (editable). */
    data class Local(val name: String) : ScriptTarget
    /** A script-path from a rewrite line / module: local name → editable file, URL → cached copy, read-only. */
    data class Path(val path: String) : ScriptTarget

    companion object {
        fun forPath(path: String): ScriptTarget {
            val p = path.trim()
            if (p.startsWith("http://", true) || p.startsWith("https://", true)) return Path(p)
            val name = p.substringAfterLast('/')
            return if (name in EngineStore.localScripts()) Local(name) else Path(p)
        }
    }
}

private val SCRATCH_TEMPLATE = """// Script workbench: edit, then tap Debug run to execute once against the sample or a captured request.
// ${'$'}request / ${'$'}response / ${'$'}done behave as in the tunnel; console.log output is shown in the result.
let body = ${'$'}response.body;
try {
  const obj = JSON.parse(body);
  obj.ad = false;
  body = JSON.stringify(obj);
  console.log('modified');
} catch (e) {
  console.log('not json: ' + e);
}
${'$'}done({ body });
"""

/** 脚本编辑器 + 调试 (iOS ScriptWorkbenchView): JS editor for local scripts, read-only view of remote ones, debug runs via ScriptDebugRun. */
@Composable
fun ScriptEditorScreen(vm: MainViewModel, target: ScriptTarget, initialSample: DebugSample? = null, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var localName by remember(target) { mutableStateOf((target as? ScriptTarget.Local)?.name) }
    val remotePath = (target as? ScriptTarget.Path)?.path
    var code by remember(target) { mutableStateOf("") }
    var saved by remember(target) { mutableStateOf("") }
    var loadError by remember(target) { mutableStateOf<String?>(null) }
    var loading by remember(target) { mutableStateOf(true) }
    var sample by remember { mutableStateOf(initialSample ?: DebugSample()) }
    var showDebug by remember { mutableStateOf(initialSample != null) }
    var askSaveAs by remember { mutableStateOf(false) }
    var confirmLeave by remember { mutableStateOf(false) }

    LaunchedEffect(target) {
        when (target) {
            is ScriptTarget.Scratch -> { code = SCRATCH_TEMPLATE; saved = code }
            is ScriptTarget.Local -> { code = withContext(Dispatchers.IO) { EngineExtras.readLocalScript(target.name) }; saved = code }
            is ScriptTarget.Path -> EngineExtras.scriptSource(target.path)
                .onSuccess { code = it; saved = it }
                .onFailure { loadError = ctx.getString(R.string.e2_script_load_failed, it.message ?: "") }
        }
        loading = false
    }

    val readOnly = localName == null && remotePath != null
    val dirty = localName != null && code != saved
    val title = localName ?: remotePath?.substringAfterLast('/')?.ifEmpty { null } ?: stringResource(R.string.e2_workbench)
    val tryBack: () -> Unit = { if (dirty) confirmLeave = true else onBack() }

    if (showDebug) {
        BackHandler { showDebug = false }
        DebugPanel(sample, onSample = { sample = it }, code = code, path = if (readOnly) remotePath else null, name = title,
            onBack = { showDebug = false })
        return
    }
    BackHandler(enabled = dirty) { confirmLeave = true }

    Scaffold(containerColor = c.bg, topBar = {
        BackTopBar(title, tryBack) {
            if (localName != null) TextButton(onClick = {
                scope.launch {
                    val n = localName!!
                    withContext(Dispatchers.IO) { EngineExtras.saveLocalScript(n, code) }
                    saved = code
                    vm.toast(ctx.getString(R.string.e2_saved))
                }
            }, enabled = dirty) { Text(stringResource(if (dirty) R.string.e2_save else R.string.e2_saved_short)) }
            else TextButton(onClick = { askSaveAs = true }, enabled = !loading) { Text(stringResource(R.string.e2_save_as)) }
        }
    }, bottomBar = {
        Row(Modifier.fillMaxWidth().background(c.card).padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.e2_lines_chars, code.lines().size, code.length), fontSize = 11.sp, color = c.secondary, modifier = Modifier.weight(1f))
            Button(onClick = { showDebug = true }, enabled = !loading && code.isNotBlank()) { Text(stringResource(R.string.e2_debug_run)) }
        }
    }) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            loadError?.let { Text(it, color = c.bad, fontSize = 12.sp, modifier = Modifier.padding(12.dp)) }
            if (readOnly && loadError == null) Text(stringResource(R.string.e2_remote_readonly), fontSize = 12.sp, color = c.secondary,
                modifier = Modifier.fillMaxWidth().background(c.cardAlt).padding(horizontal = 12.dp, vertical = 8.dp))
            if (loading) CircularProgressIndicator(Modifier.padding(24.dp).size(24.dp))
            else CodeEditor(code, { if (!readOnly) code = it }, readOnly, Modifier.weight(1f))
        }
    }

    if (askSaveAs) {
        var name by remember { mutableStateOf(remotePath?.substringAfterLast('/')?.substringBefore('?')?.ifBlank { null } ?: "script.js") }
        AlertDialog(
            onDismissRequest = { askSaveAs = false },
            title = { Text(stringResource(R.string.e2_save_as_local)) },
            text = { OutlinedTextField(name, { name = it }, singleLine = true, label = { Text(stringResource(R.string.e2_file_name)) }) },
            confirmButton = {
                TextButton(onClick = {
                    askSaveAs = false
                    scope.launch {
                        val n = withContext(Dispatchers.IO) { EngineExtras.saveLocalScript(name, code) }
                        localName = n; saved = code
                        vm.toast(ctx.getString(R.string.e2_saved_as, n))
                    }
                }, enabled = name.isNotBlank()) { Text(stringResource(R.string.e2_save)) }
            },
            dismissButton = { TextButton(onClick = { askSaveAs = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
    if (confirmLeave) {
        AlertDialog(
            onDismissRequest = { confirmLeave = false },
            title = { Text(stringResource(R.string.e2_unsaved)) },
            confirmButton = { TextButton(onClick = { confirmLeave = false; onBack() }) { Text(stringResource(R.string.e2_discard), color = c.bad) } },
            dismissButton = { TextButton(onClick = { confirmLeave = false }) { Text(stringResource(R.string.cancel)) } },
        )
    }
}

/** Monospace editor with line numbers; scrolls both ways (no wrapping, like a code editor). */
@Composable
private fun CodeEditor(text: String, onChange: (String) -> Unit, readOnly: Boolean, modifier: Modifier = Modifier) {
    val c = LocalAppColors.current
    val v = rememberScrollState()
    val h = rememberScrollState()
    val style = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, lineHeight = 17.sp, color = c.text)
    Row(modifier.fillMaxWidth().background(c.card).verticalScroll(v)) {
        val n = text.count { it == '\n' } + 1
        Text((1..n).joinToString("\n"), style = style.copy(color = c.secondary), modifier = Modifier.padding(start = 6.dp, end = 6.dp, top = 8.dp).widthIn(min = 24.dp))
        Box(Modifier.weight(1f).horizontalScroll(h)) {
            BasicTextField(text, onChange, readOnly = readOnly, textStyle = style, cursorBrush = SolidColor(c.accent),
                modifier = Modifier.padding(top = 8.dp, end = 16.dp, bottom = 200.dp).widthIn(min = 300.dp))
        }
    }
}

@Composable
private fun DebugPanel(sample: DebugSample, onSample: (DebugSample) -> Unit, code: String, path: String?, name: String, onBack: () -> Unit) {
    val c = LocalAppColors.current
    val scope = rememberCoroutineScope()
    var running by remember { mutableStateOf(false) }
    var out by remember { mutableStateOf<DebugOutput?>(null) }
    val s = sample
    val mono = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    val http = s.type == "http-request" || s.type == "http-response"

    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(R.string.e2_debug_run), onBack) }) { pad ->
        LazyColumn(Modifier.fillMaxSize().padding(pad), contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 40.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ScriptDebugger.types.forEach { t -> FilterChip(s.type == t, { onSample(s.copy(type = t)) }, label = { Text(t, fontSize = 12.sp) }) }
                }
            }
            if (http) {
                item { SectionTitle(stringResource(R.string.e2_request)) }
                item {
                    AppCard {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedTextField(s.method, { onSample(s.copy(method = it)) }, Modifier.width(96.dp), singleLine = true, textStyle = mono,
                                label = { Text(stringResource(R.string.e2_method)) })
                            OutlinedTextField(s.url, { onSample(s.copy(url = it)) }, Modifier.weight(1f), singleLine = true, textStyle = mono, label = { Text("URL") })
                        }
                        OutlinedTextField(s.requestHeaders, { onSample(s.copy(requestHeaders = it)) }, Modifier.fillMaxWidth().height(110.dp), textStyle = mono,
                            label = { Text(stringResource(R.string.e2_headers_hint)) })
                        OutlinedTextField(s.requestBody, { onSample(s.copy(requestBody = it)) }, Modifier.fillMaxWidth().height(90.dp), textStyle = mono,
                            label = { Text(stringResource(R.string.e2_body)) })
                    }
                }
            }
            if (s.type == "http-response") {
                item { SectionTitle(stringResource(R.string.e2_response)) }
                item {
                    AppCard {
                        OutlinedTextField(s.status, { onSample(s.copy(status = it.filter(Char::isDigit).take(3))) }, Modifier.width(110.dp), singleLine = true,
                            textStyle = mono, label = { Text(stringResource(R.string.e2_status)) })
                        OutlinedTextField(s.responseHeaders, { onSample(s.copy(responseHeaders = it)) }, Modifier.fillMaxWidth().height(110.dp), textStyle = mono,
                            label = { Text(stringResource(R.string.e2_headers_hint)) })
                        OutlinedTextField(s.responseBody, { onSample(s.copy(responseBody = it)) }, Modifier.fillMaxWidth().height(140.dp), textStyle = mono,
                            label = { Text(stringResource(R.string.e2_body)) })
                    }
                }
            }
            item { SectionTitle(stringResource(R.string.e2_options)) }
            item {
                AppCard {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.e2_argument), fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f))
                        Switch(s.useArgument, { onSample(s.copy(useArgument = it)) }, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
                    }
                    if (s.useArgument) OutlinedTextField(s.argument, { onSample(s.copy(argument = it)) }, Modifier.fillMaxWidth(), textStyle = mono,
                        placeholder = { Text("key=value&…") })
                    if (http) Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.e2_binary_mode), fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f))
                        Switch(s.binary, { onSample(s.copy(binary = it)) }, colors = SwitchDefaults.colors(checkedTrackColor = c.good))
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(stringResource(R.string.e2_timeout_s, s.timeout), fontSize = 14.sp, color = c.text, modifier = Modifier.weight(1f))
                        TextButton(onClick = { onSample(s.copy(timeout = (s.timeout - 5).coerceAtLeast(5))) }) { Text("−") }
                        TextButton(onClick = { onSample(s.copy(timeout = (s.timeout + 5).coerceAtMost(60))) }) { Text("+") }
                    }
                    Text(stringResource(R.string.e2_debug_note), fontSize = 11.sp, color = c.secondary)
                }
            }
            item {
                Button(onClick = {
                    running = true
                    scope.launch {
                        out = runCatching { ScriptDebugger.run(code, path, name, s) }.getOrElse { DebugOutput(error = it.message) }
                        running = false
                    }
                }, enabled = !running, modifier = Modifier.fillMaxWidth()) {
                    if (running) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    else Text(stringResource(R.string.e2_run))
                }
            }
            out?.let { o -> item { DebugResult(o) } }
        }
    }
}

@Composable
private fun DebugResult(o: DebugOutput) {
    val c = LocalAppColors.current
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        AppCard {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Tag(if (o.ok) "OK" else stringResource(R.string.e2_failed), if (o.ok) c.good else c.bad)
                Spacer(Modifier.width(8.dp))
                Text("${o.durationMs} ms", fontSize = 12.sp, color = c.secondary)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(if (o.done) R.string.e2_done_called else R.string.e2_done_missing), fontSize = 12.sp,
                    color = if (o.done) c.secondary else c.warn)
            }
            o.error?.let { SelectionContainer { Text(it, fontSize = 12.sp, color = c.bad, fontFamily = FontFamily.Monospace) } }
            o.summary.forEach { Text("• $it", fontSize = 12.sp, color = c.text) }
        }
        if (o.logs.isNotEmpty()) {
            SectionTitle(stringResource(R.string.e2_console_n, o.logs.size))
            AppCard {
                SelectionContainer {
                    Column {
                        o.logs.forEach { l ->
                            Text("+${l.t}ms [${l.level}] ${l.msg}", fontFamily = FontFamily.Monospace, fontSize = 11.sp,
                                color = when (l.level) { "error" -> c.bad; "warn", "warning" -> c.warn; else -> c.text })
                        }
                    }
                }
            }
        }
        if (o.notifications.isNotEmpty()) {
            SectionTitle(stringResource(R.string.e2_notifications_n, o.notifications.size))
            AppCard {
                o.notifications.forEach { n ->
                    Text(listOfNotNull(n["title"], n["subtitle"]).filter { it.isNotEmpty() }.joinToString(" · "), fontWeight = FontWeight.Medium, fontSize = 13.sp, color = c.text)
                    n["body"]?.let { Text(it, fontSize = 12.sp, color = c.secondary) }
                }
            }
        }
        (o.mock ?: o.result)?.let { r ->
            SectionTitle(stringResource(if (o.mock != null) R.string.e2_mock_response else R.string.e2_result))
            AppCard {
                listOfNotNull(r.method, r.url, r.status?.takeIf { it > 0 }?.let { "HTTP $it" }).joinToString(" ").takeIf { it.isNotEmpty() }?.let {
                    Text(it, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text)
                }
                r.headers?.takeIf { it.isNotEmpty() }?.let { HeaderLines(it) }
                r.body?.takeIf { it.isNotEmpty() }?.let { b ->
                    Spacer(Modifier.height(6.dp))
                    if (r.bodyBase64 == true) Text(stringResource(R.string.e2_body_base64, b.length), fontSize = 12.sp, color = c.secondary)
                    else SelectionContainer { Text(prettyBody(b).take(60_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text) }
                }
            }
        }
        o.doneJSON?.takeIf { it.isNotEmpty() }?.let {
            SectionTitle("\$done")
            AppCard { SelectionContainer { Text(it.take(60_000), fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = c.text) } }
        }
    }
}
