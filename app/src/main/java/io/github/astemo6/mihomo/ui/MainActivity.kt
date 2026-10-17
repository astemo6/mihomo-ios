package io.github.astemo6.mihomo.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import io.github.astemo6.mihomo.R
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.ImportRouter
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.ui.engine.MitmScreen
import io.github.astemo6.mihomo.ui.engine.RewriteScreen
import io.github.astemo6.mihomo.ui.engine.ScriptsScreen
import io.github.astemo6.mihomo.ui.feature2.Feature2Routes
import io.github.astemo6.mihomo.ui.feature2.Feature2Screen
import io.github.astemo6.mihomo.ui.home.HomeScreen
import io.github.astemo6.mihomo.ui.settings.PanelsToolbarScreen
import io.github.astemo6.mihomo.ui.tools.DnsScreen
import io.github.astemo6.mihomo.ui.profiles.AddProfileSheet
import io.github.astemo6.mihomo.ui.profiles.ProfilesScreen
import io.github.astemo6.mihomo.ui.profiles.readDocument
import io.github.astemo6.mihomo.ui.settings.ConnectionScreen
import io.github.astemo6.mihomo.ui.settings.PerAppScreen
import io.github.astemo6.mihomo.ui.settings.SettingsScreen
import io.github.astemo6.mihomo.ui.theme.MihomoTheme
import io.github.astemo6.mihomo.vpn.VpnController
import kotlinx.coroutines.launch

/** Navigation routes (plain strings; the A2 data screens use [Feature2Routes]). */
object Routes {
    const val HOME = "home"
    const val PROFILES = "profiles"
    const val SETTINGS = "settings"
    const val CONNECTION = "connection"
    const val PER_APP = "perapp"
    const val DNS = "dns"
    const val PANELS = "panels"
    const val REWRITE = "rewrite"
    const val MITM = "mitm"
    const val SCRIPTS = "scripts"
}

class MainActivity : AppCompatActivity() {
    companion object {
        /** From the tile / widget when the VPN permission is missing: ask, then connect. */
        const val ACTION_CONNECT = "io.github.astemo6.mihomo.CONNECT"
    }

    private val vm: MainViewModel by viewModels()

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) vm.connect()
        else vm.toast(getString(R.string.err_vpn_permission))
    }

    private val notifPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val theme by AppSettings.theme.collectAsState()
            MihomoTheme(theme) { AppRoot() }
        }
        if (savedInstanceState == null) handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        lifecycleScope.launch { ProfileStore.autoUpdateIfNeeded(); runCatching { io.github.astemo6.mihomo.data.feature2.Feature2Hooks.onForeground(this@MainActivity) } }
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            ACTION_CONNECT -> requestConnect()
            io.github.astemo6.mihomo.a3.A3Shortcuts.ACTION_OPEN_ROUTE ->
                io.github.astemo6.mihomo.a3.A3Shortcuts.pendingRoute.value = intent.getStringExtra(io.github.astemo6.mihomo.a3.A3Shortcuts.EXTRA_ROUTE)
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return
                when (data.scheme?.lowercase()) {
                    "clash", "clashmeta", "mihomo" -> {
                        val req = ImportRouter.fromUri(data)
                        if (req != null) vm.offerImport(req) else vm.toast(getString(R.string.err_unrecognized_link))
                    }
                    "content", "file" -> readDocument(this, data)?.let { vm.offerImport(it) }
                        ?: vm.toast(getString(R.string.err_read_file))
                }
            }
            Intent.ACTION_SEND -> {
                val text = intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty()
                ImportRouter.fromText(text)?.let { vm.offerImport(it) }
            }
        }
    }

    fun requestConnect() {
        if (ProfileStore.active == null) {
            vm.toast(getString(R.string.err_no_profile)); return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val prep = VpnService.prepare(this)
        if (prep != null) {
            runCatching { vpnPermission.launch(prep) }.onFailure { vm.toast(getString(R.string.err_vpn_permission)) }
        } else vm.connect()
    }

    @Composable
    private fun AppRoot() {
        val stack = remember { mutableStateListOf(Routes.HOME) }
        var showAdd by remember { mutableStateOf(false) }
        val message by vm.message.collectAsState()
        val pending by vm.pendingImport.collectAsState()
        val push: (String) -> Unit = { stack.add(it) }
        val pop: () -> Unit = { if (stack.size > 1) stack.removeAt(stack.lastIndex) }

        BackHandler(enabled = stack.size > 1) { pop() }
        // A3: route requested by an App Shortcut (e.g. 配置).
        val shortcutRoute by io.github.astemo6.mihomo.a3.A3Shortcuts.pendingRoute.collectAsState()
        LaunchedEffect(shortcutRoute) {
            shortcutRoute?.let { r -> if (stack.last() != r) push(r); io.github.astemo6.mihomo.a3.A3Shortcuts.pendingRoute.value = null }
        }

        when (val route = stack.last()) {
            Routes.HOME -> HomeScreen(
                vm,
                onToggle = { on -> if (on) requestConnect() else VpnController.stop(this) },
                onOpenSettings = { push(Routes.SETTINGS) },
                onAdd = { showAdd = true },
                onOpenProfiles = { push(Routes.PROFILES) },
                onOpenDns = { push(Routes.DNS) },
                onOpenLayout = { push(Routes.PANELS) },
                onOpenRewrite = { push(Routes.REWRITE) },
            )
            Routes.PROFILES -> ProfilesScreen(vm, onBack = pop, onAdd = { showAdd = true })
            Routes.SETTINGS -> SettingsScreen(vm, onBack = pop, navigate = push)
            Routes.CONNECTION -> ConnectionScreen(vm, onBack = pop)
            Routes.PER_APP -> PerAppScreen(vm, onBack = pop)
            Routes.DNS -> DnsScreen(vm, onBack = pop)
            Routes.PANELS -> PanelsToolbarScreen(onBack = pop)
            Routes.REWRITE -> RewriteScreen(vm, onBack = pop, onMitm = { push(Routes.MITM) }, onScripts = { push(Routes.SCRIPTS) })
            Routes.MITM -> MitmScreen(vm, onBack = pop)
            Routes.SCRIPTS -> ScriptsScreen(vm, onBack = pop)
            in Feature2Routes.all -> Feature2Screen(route, onBack = pop)
            in io.github.astemo6.mihomo.ui.a3.A3Routes.all -> io.github.astemo6.mihomo.ui.a3.A3Screen(route, vm, onBack = pop)
            else -> LaunchedEffect(route) { pop() }
        }

        if (showAdd) AddProfileSheet(vm) { showAdd = false }

        pending?.let { req ->
            AlertDialog(
                onDismissRequest = { vm.dismissImport() },
                title = { Text(stringResource(R.string.import_q)) },
                text = {
                    Text(when (req) {
                        is ImportRouter.Request.Remote -> req.url
                        is ImportRouter.Request.Text -> req.name.ifEmpty { req.text.take(200) }
                        is ImportRouter.Request.ModuleUrl -> getString(R.string.module) + "\n" + req.url
                        is ImportRouter.Request.ModuleText -> getString(R.string.module) + "\n" + req.name.ifEmpty { req.text.take(200) }
                    })
                },
                confirmButton = { TextButton(onClick = { vm.import(req) }) { Text(stringResource(R.string.import_)) } },
                dismissButton = { TextButton(onClick = { vm.dismissImport() }) { Text(stringResource(R.string.cancel)) } },
            )
        }

        LaunchedEffect(message) {
            message?.let { m ->
                Toast.makeText(this@MainActivity, m.text, if (m.text.length > 60) Toast.LENGTH_LONG else Toast.LENGTH_SHORT).show()
                vm.consumeMessage(m.id)
            }
        }
    }
}
