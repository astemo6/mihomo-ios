package io.github.astemo6.mihomo.ui.feature2

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.feature2.Feature2Hooks
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint

/** Routes handled by [Feature2Screen] (A2 parity screens of this branch). */
object Feature2Routes {
    const val RULESETS = "rulesets"
    const val DNSLOG = "dnslog"
    const val TRAFFIC = "traffic"
    const val NODESUBS = "nodesubs"
    const val GROUPS = "groups"
    const val MANUALNODES = "manualnodes"
    const val DIAGNOSTICS = "diagnostics"

    val all = listOf(RULESETS, DNSLOG, TRAFFIC, NODESUBS, GROUPS, MANUALNODES, DIAGNOSTICS)

    /** Title string resource of a route (for settings rows / menus of the host app). */
    fun titleRes(route: String): Int = when (route) {
        RULESETS -> R.string.f2_rulesets_title
        DNSLOG -> R.string.f2_dns_title
        TRAFFIC -> R.string.f2_traffic_title
        NODESUBS -> R.string.f2_nodesubs_title
        GROUPS -> R.string.f2_groups_title
        MANUALNODES -> R.string.f2_manual_title
        DIAGNOSTICS -> R.string.f2_diag_title
        else -> R.string.f2_unknown_title
    }
}

/**
 * Single entry point of the feature2 screens. Each screen draws its own top bar and handles its own
 * inner navigation (editors) with BackHandler; [onBack] leaves the feature.
 */
@Composable
fun Feature2Screen(route: String, onBack: () -> Unit) {
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        // Process-lifetime collectors (same process as the VPN service); idempotent.
        Feature2Hooks.onAppCreate(context)
    }
    when (route) {
        Feature2Routes.RULESETS -> RuleSetsScreen(onBack)
        Feature2Routes.DNSLOG -> DnsLogScreen(onBack)
        Feature2Routes.TRAFFIC -> TrafficScreen(onBack)
        Feature2Routes.NODESUBS -> NodeSubsScreen(onBack)
        Feature2Routes.GROUPS -> GroupsScreen(onBack)
        Feature2Routes.MANUALNODES -> ManualNodesScreen(onBack)
        Feature2Routes.DIAGNOSTICS -> DiagnosticsScreen(onBack)
        else -> {
            BackTopBar(stringResource(R.string.f2_unknown_title), onBack)
            EmptyHint(route)
        }
    }
}
