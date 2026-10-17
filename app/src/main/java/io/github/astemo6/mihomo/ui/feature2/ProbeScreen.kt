package io.github.astemo6.mihomo.ui.feature2

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.feature2.ProbeStore
import io.github.astemo6.mihomo.data.feature2.UnlockNotes
import io.github.astemo6.mihomo.data.feature2.UnlockResult
import io.github.astemo6.mihomo.data.feature2.UnlockService
import io.github.astemo6.mihomo.ui.Fmt
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.SectionTitle
import io.github.astemo6.mihomo.ui.theme.LocalAppColors
import kotlinx.coroutines.launch

/** 节点探测 detail of one policy: egress IP / location / ASN and 解锁检测 through MIHOMO-PROBE. */
@Composable
fun ProbeDetail(policy: String, onBack: () -> Unit) {
    F2Page(policy, onBack) { probeSection(policy) }
}

fun androidx.compose.foundation.lazy.LazyListScope.probeSection(policy: String) {
    item { ProbeBody(policy) }
}

@Composable
private fun ProbeBody(policy: String) {
    val c = LocalAppColors.current
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val entries by ProbeStore.entries.collectAsState()
    val running by ProbeStore.running.collectAsState()
    var error by remember(policy) { mutableStateOf<String?>(null) }
    val e = entries[policy]
    val busy = policy in running
    Column {
        Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Button(enabled = !busy, onClick = { error = null; scope.launch { ProbeStore.probeExit(policy)?.let { error = probeMessage(context, it) } } },
                modifier = Modifier.weight(1f)) { Text(stringResource(R.string.f2_probe_exit)) }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(enabled = !busy, onClick = { error = null; scope.launch { ProbeStore.probeUnlock(policy)?.let { error = probeMessage(context, it) } } },
                modifier = Modifier.weight(1f)) { Text(stringResource(R.string.f2_probe_unlock)) }
            if (busy) { Spacer(Modifier.width(8.dp)); CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp) }
        }
        error?.let { Text(it, color = c.bad, fontSize = 12.sp, modifier = Modifier.padding(bottom = 6.dp)) }
        SectionTitle(stringResource(R.string.f2_probe_exit_info))
        AppCard {
            val x = e?.exit
            if (x == null) Text(stringResource(R.string.f2_probe_none_yet), fontSize = 13.sp, color = c.secondary)
            else {
                Text("${x.flag}  ${x.ip}", fontSize = 17.sp, color = c.text, fontWeight = FontWeight.SemiBold)
                if (x.locationText.isNotEmpty()) Text(x.locationText, fontSize = 13.sp, color = c.text)
                if (x.asnText.isNotEmpty()) Text(x.asnText, fontSize = 12.sp, color = c.secondary)
                Text(listOfNotNull(x.source, e.exitMs?.let { Fmt.dateTime(it) }).joinToString(" · "), fontSize = 11.sp, color = c.secondary)
            }
        }
        SectionTitle(stringResource(R.string.f2_probe_unlock_results))
        AppCard {
            val r = e?.unlock
            if (r.isNullOrEmpty()) Text(stringResource(R.string.f2_probe_none_yet), fontSize = 13.sp, color = c.secondary)
            else {
                r.forEachIndexed { i, u ->
                    UnlockRow(u)
                    if (i < r.size - 1) HorizontalDivider(color = c.separator, thickness = 0.5.dp)
                }
                e.unlockMs?.let { Text(Fmt.dateTime(it), fontSize = 11.sp, color = c.secondary, modifier = Modifier.padding(top = 6.dp)) }
            }
        }
        F2Footer(stringResource(R.string.f2_probe_footer))
    }
}

@Composable
private fun serviceTitle(s: UnlockService): String = when (s) {
    UnlockService.bilibiliHKMOTW -> stringResource(R.string.f2_svc_bili_hkmotw)
    UnlockService.bilibiliTW -> stringResource(R.string.f2_svc_bili_tw)
    else -> s.title
}

@Composable
private fun noteText(n: String?): String? = when (n) {
    null -> null
    UnlockNotes.DENIED -> stringResource(R.string.f2_un_denied)
    UnlockNotes.ORIGINALS_ONLY -> stringResource(R.string.f2_un_originals)
    UnlockNotes.REGION -> stringResource(R.string.f2_un_region)
    UnlockNotes.WEB_ONLY -> stringResource(R.string.f2_un_web_only)
    UnlockNotes.WAF -> stringResource(R.string.f2_un_waf)
    UnlockNotes.UNRECOGNIZED -> stringResource(R.string.f2_un_unrecognized)
    UnlockNotes.TIMEOUT -> stringResource(R.string.f2_un_timeout)
    UnlockNotes.CONNECT -> stringResource(R.string.f2_un_connect)
    UnlockNotes.TLS -> stringResource(R.string.f2_un_tls)
    else -> n
}

@Composable
private fun UnlockRow(u: UnlockResult) {
    val c = LocalAppColors.current
    val (label, color) = when (u.status) {
        "yes" -> stringResource(R.string.f2_un_yes) to c.good
        "partial" -> (noteText(u.note) ?: stringResource(R.string.f2_un_partial)) to c.warn
        "no" -> stringResource(R.string.f2_un_no) to c.bad
        else -> stringResource(R.string.f2_un_failed) to c.secondary
    }
    Row(Modifier.padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(serviceTitle(u.service), fontSize = 14.sp, color = c.text)
            if (u.status != "partial") noteText(u.note)?.let { Text(it, fontSize = 11.sp, color = c.secondary) }
        }
        Text(listOfNotNull(u.flag ?: u.region, label).joinToString(" "), fontSize = 13.sp, color = color, fontWeight = FontWeight.SemiBold)
    }
}
