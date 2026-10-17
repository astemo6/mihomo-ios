package io.github.astemo6.mihomo.ui.feature2

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.SettingsRow
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

/** Standard feature2 page: QX grey background, back bar, one lazy column of cards. */
@Composable
fun F2Page(
    title: String,
    onBack: () -> Unit,
    actions: @Composable RowScope.() -> Unit = {},
    content: LazyListScope.() -> Unit,
) {
    val c = LocalAppColors.current
    Scaffold(containerColor = c.bg, topBar = { BackTopBar(title, onBack, actions) }) { pad ->
        LazyColumn(
            Modifier.fillMaxSize().padding(pad),
            contentPadding = PaddingValues(16.dp, 4.dp, 16.dp, 32.dp),
            verticalArrangement = Arrangement.spacedBy(0.dp),
            content = content,
        )
    }
}

@Composable
fun F2Footer(text: String) {
    Text(text, fontSize = 12.sp, color = LocalAppColors.current.secondary, modifier = Modifier.padding(start = 6.dp, end = 6.dp, top = 6.dp))
}

@Composable
fun F2Field(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    placeholder: String = "",
    singleLine: Boolean = true,
    mono: Boolean = false,
    secure: Boolean = false,
    number: Boolean = false,
    minLines: Int = 1,
    isError: Boolean = false,
) {
    val c = LocalAppColors.current
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = { if (placeholder.isNotEmpty()) Text(placeholder, color = c.secondary, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        singleLine = singleLine,
        minLines = if (singleLine) 1 else minLines,
        isError = isError,
        textStyle = if (mono) TextStyle(fontFamily = FontFamily.Monospace, fontSize = 13.sp) else TextStyle(fontSize = 15.sp),
        visualTransformation = if (secure) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = when {
            number -> KeyboardType.Number
            secure -> KeyboardType.Password
            else -> KeyboardType.Uri
        }, autoCorrectEnabled = false),
        colors = OutlinedTextFieldDefaults.colors(focusedContainerColor = c.card, unfocusedContainerColor = c.card),
        modifier = modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
    )
}

/** A settings row whose value opens a dropdown of [options] (value to label). */
@Composable
fun ChoiceRow(
    title: String,
    options: List<Pair<String, String>>,
    selected: String,
    showDivider: Boolean = true,
    onSelect: (String) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    val label = options.firstOrNull { it.first == selected }?.second ?: selected.ifEmpty { "—" }
    Box {
        SettingsRow(title, value = label, showDivider = showDivider, onClick = { open = true })
        DropdownMenu(open, onDismissRequest = { open = false }, modifier = Modifier.align(Alignment.TopEnd)) {
            options.forEach { (v, l) ->
                DropdownMenuItem(
                    text = { Text(l) },
                    onClick = { open = false; onSelect(v) },
                    trailingIcon = { if (v == selected) Icon(Icons.Default.Check, null) },
                )
            }
        }
    }
}

@Composable
fun ConfirmDialog(title: String, text: String?, confirm: String, onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { if (text != null) Text(text) },
        confirmButton = { TextButton(onClick = { onDismiss(); onConfirm() }) { Text(confirm) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

@Composable
fun MessageDialog(text: String?, onDismiss: () -> Unit) {
    if (text == null) return
    AlertDialog(
        onDismissRequest = onDismiss,
        text = { Text(text) },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.f2_ok)) } },
    )
}

/** Multi-select list dialog with a search box. */
@Composable
fun MultiPickDialog(
    title: String,
    candidates: List<String>,
    initial: Set<String>,
    onDismiss: () -> Unit,
    onDone: (List<String>) -> Unit,
) {
    val picked = remember { mutableStateListOf<String>().apply { addAll(candidates.filter { it in initial }) } }
    var q by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                F2Field(stringResource(R.string.f2_search), q, { q = it })
                LazyColumn(Modifier.heightIn(max = 380.dp)) {
                    items(candidates.filter { q.isBlank() || it.contains(q, ignoreCase = true) }, key = { it }) { n ->
                        Row(
                            Modifier.fillMaxWidth().clickable { if (n in picked) picked.remove(n) else picked.add(n) }.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Checkbox(checked = n in picked, onCheckedChange = { if (it) picked.add(n) else picked.remove(n) })
                            Text(n, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onDismiss(); onDone(picked.toList()) }) { Text(stringResource(R.string.f2_done_n, picked.size)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.cancel)) } },
    )
}

object F2Util {
    fun toast(context: Context, text: String) = Toast.makeText(context, text, Toast.LENGTH_SHORT).show()

    fun copy(context: Context, text: String) {
        context.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("mihomo", text))
    }

    fun paste(context: Context): String =
        context.getSystemService(ClipboardManager::class.java)?.primaryClip?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()

    fun shareText(context: Context, text: String, title: String) {
        val i = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text)
        context.startActivity(Intent.createChooser(i, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun lines(text: String): List<String> = text.split('\n', ',').map { it.trim() }.filter { it.isNotEmpty() }
}

/** Human text for probe / unlock error codes (PolicyProbe / ProbeStore / UnlockNotes). */
@Composable
fun probeErrorText(code: String?): String? = when (code) {
    null -> null
    "not_connected" -> stringResource(R.string.f2_probe_not_connected)
    "needs_reconnect" -> stringResource(R.string.f2_probe_needs_reconnect)
    "unknown_policy" -> stringResource(R.string.f2_probe_unknown_policy)
    "no_answer" -> stringResource(R.string.f2_probe_no_answer)
    else -> code
}
