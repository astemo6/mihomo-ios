package io.github.astemo6.mihomo

import android.app.Application
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.core.Paths
import android.os.Handler
import android.os.Looper
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.EngineStore
import io.github.astemo6.mihomo.data.ProfileStore
import io.github.astemo6.mihomo.data.UiLayout
import io.github.astemo6.mihomo.vpn.MihomoTileService
import io.github.astemo6.mihomo.vpn.MihomoVpnService
import io.github.astemo6.mihomo.vpn.VpnController
import io.github.astemo6.mihomo.vpn.VpnState
import io.github.astemo6.mihomo.widget.StatusWidget

class MihomoApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Paths.init(this)
        AppSettings.init(this)
        UiLayout.init(this)
        ProfileStore.init()
        MihomoVpnService.createChannel(this)
        Core.initLogging()
        ProfileStore.onActiveChanged = { VpnController.reload(this) }
        Thread { EngineStore.init() }.start()
        io.github.astemo6.mihomo.data.feature2.Feature2Hooks.onAppCreate(this)
        // engine.json edits come in bursts (toggles): reload the running core once, 400 ms after the last.
        val main = Handler(Looper.getMainLooper())
        val reload = Runnable { VpnController.reload(this) }
        EngineStore.onChanged = { main.removeCallbacks(reload); main.postDelayed(reload, 400) }
        io.github.astemo6.mihomo.a3.A3Runtime.init(this)
        VpnState.listener = {
            MihomoTileService.requestUpdate(this)
            runCatching { StatusWidget.updateAll(this) }
        }
    }
}
