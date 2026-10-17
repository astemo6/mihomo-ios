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
import io.github.astemo6.mihomo.ui.home.HomeScreen
import io.github.astemo6.mihomo.ui.profiles.AddProfileSheet
import io.github.astemo6.mihomo.ui.profiles.ProfilesScreen
import io.github.astemo6.mihomo.ui.profiles.readDocument
import io.github.astemo6.mihomo.ui.settings.ConnectionScreen
import io.github.astemo6.mihomo.ui.settings.PerAppScreen
import io.github.astemo6.mihomo.ui.settings.SettingsScreen
import io.github.astemo6.mihomo.ui.theme.MihomoTheme
import io.github.astemo6.mihomo.vpn.VpnController
import kotlinx.coroutines.launch

enum class Screen { HOME, PROFILES, SETTINGS, CONNECTION, PER_APP }

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
        lifecycleScope.launch { ProfileStore.autoUpdateIfNeeded() }
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            ACTION_CONNECT -> requestConnect()
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
        val stack = remember { mutableStateListOf(Screen.HOME) }
        var showAdd by remember { mutableStateOf(false) }
        val message by vm.message.collectAsState()
        val pending by vm.pendingImport.collectAsState()
        val push: (Screen) -> Unit = { stack.add(it) }
        val pop: () -> Unit = { if (stack.size > 1) stack.removeAt(stack.lastIndex) }

        BackHandler(enabled = stack.size > 1) { pop() }

        when (stack.last()) {
            Screen.HOME -> HomeScreen(
                vm,
                onToggle = { on -> if (on) requestConnect() else VpnController.stop(this) },
                onOpenSettings = { push(Screen.SETTINGS) },
                onAdd = { showAdd = true },
                onOpenProfiles = { push(Screen.PROFILES) },
            )
            Screen.PROFILES -> ProfilesScreen(vm, onBack = pop, onAdd = { showAdd = true })
            Screen.SETTINGS -> SettingsScreen(vm, onBack = pop, onProfiles = { push(Screen.PROFILES) },
                onConnection = { push(Screen.CONNECTION) }, onPerApp = { push(Screen.PER_APP) })
            Screen.CONNECTION -> ConnectionScreen(vm, onBack = pop)
            Screen.PER_APP -> PerAppScreen(vm, onBack = pop)
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
