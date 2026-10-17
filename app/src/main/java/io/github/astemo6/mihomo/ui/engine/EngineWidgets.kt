package io.github.astemo6.mihomo.ui.engine

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.data.AppJson
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/** A compact dropdown: shows [label] for the current value, picks one of [options] (value to label). */
@Composable
internal fun DropdownField(
    label: String,
    options: List<Pair<String, String>>,
    modifier: Modifier = Modifier,
    onPick: (String) -> Unit,
) {
    val c = LocalAppColors.current
    var open by remember { mutableStateOf(false) }
    Box(modifier) {
        Row(
            Modifier.clip(RoundedCornerShape(8.dp)).background(c.cardAlt).clickable { open = true }
                .padding(start = 10.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, fontSize = 13.sp, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false))
            Icon(Icons.Filled.ArrowDropDown, null, tint = c.secondary)
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            options.forEach { (v, l) ->
                DropdownMenuItem(text = { Text(l, fontSize = 14.sp) }, onClick = { open = false; onPick(v) })
            }
        }
    }
}

/** A small key/value line (detail views). */
@Composable
internal fun KvLine(k: String, v: String) {
    val c = LocalAppColors.current
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(k, fontSize = 13.sp, color = c.secondary, modifier = Modifier.padding(end = 12.dp))
        Text(v, fontSize = 13.sp, color = c.text, modifier = Modifier.weight(1f), textAlign = androidx.compose.ui.text.style.TextAlign.End)
    }
}

@Composable
internal fun HeaderLines(headers: Map<String, String>) {
    val c = LocalAppColors.current
    Column {
        headers.keys.sortedBy { it.lowercase() }.forEach { k ->
            Text(k, fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(top = 4.dp))
            Text(headers[k].orEmpty(), fontSize = 12.sp, color = c.text, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
        }
    }
}

internal fun copyText(ctx: Context, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("mihomo", text))
}

private val prettyJson = Json { prettyPrint = true }

/** Pretty-prints JSON bodies; anything else is returned unchanged. */
internal fun prettyBody(s: String): String {
    val t = s.trim()
    if (t.length > 200_000 || !(t.startsWith("{") || t.startsWith("["))) return s
    return runCatching { prettyJson.encodeToString(JsonElement.serializer(), AppJson.parseToJsonElement(t)) }.getOrDefault(s)
}
