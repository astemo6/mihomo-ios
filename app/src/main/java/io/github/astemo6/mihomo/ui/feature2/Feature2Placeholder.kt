package io.github.astemo6.mihomo.ui.feature2

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.ui.components.AppCard
import io.github.astemo6.mihomo.ui.components.BackTopBar
import io.github.astemo6.mihomo.ui.components.EmptyHint
import io.github.astemo6.mihomo.ui.theme.LocalAppColors

/**
 * A2 data features (rule sets, DNS log, traffic statistics, node subscriptions, group editor, manual
 * nodes, diagnostics) are built in a separate worktree under this package. Until they are merged every
 * route lands here. Routes are plain strings so the merge only swaps [Feature2Screen]'s body.
 */
object Feature2Routes {
    const val RULESETS = "rulesets"
    const val DNSLOG = "dnslog"
    const val TRAFFIC = "traffic"
    const val NODESUBS = "nodesubs"
    const val GROUPS = "groups"
    const val MANUALNODES = "manualnodes"
    const val DIAGNOSTICS = "diagnostics"

    val all = listOf(RULESETS, DNSLOG, TRAFFIC, NODESUBS, GROUPS, MANUALNODES, DIAGNOSTICS)

    /** Title string of a route (also used by the settings grid). */
    fun title(route: String): Int = when (route) {
        RULESETS -> R.string.f2_rulesets
        DNSLOG -> R.string.f2_dnslog
        TRAFFIC -> R.string.f2_traffic
        NODESUBS -> R.string.f2_nodesubs
        GROUPS -> R.string.f2_groups
        MANUALNODES -> R.string.f2_manualnodes
        DIAGNOSTICS -> R.string.f2_diagnostics
        else -> R.string.app_name
    }
}

/** Entry point MainActivity calls for every [Feature2Routes] route. */
@Composable
fun Feature2Screen(route: String, onBack: () -> Unit) = Feature2Placeholder(route, onBack)

@Composable
fun Feature2Placeholder(route: String, onBack: () -> Unit) {
    val c = LocalAppColors.current
    Scaffold(containerColor = c.bg, topBar = { BackTopBar(stringResource(Feature2Routes.title(route)), onBack) }) { pad ->
        AppCard(Modifier.padding(pad).padding(16.dp)) {
            EmptyHint(stringResource(R.string.coming_a2))
        }
    }
}
