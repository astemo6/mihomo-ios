package io.github.astemo6.mihomo

import android.app.Application
import io.github.astemo6.mihomo.core.Core
import io.github.astemo6.mihomo.core.Paths
import io.github.astemo6.mihomo.data.AppSettings
import io.github.astemo6.mihomo.data.ProfileStore
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
        ProfileStore.init()
        MihomoVpnService.createChannel(this)
        Core.initLogging()
        ProfileStore.onActiveChanged = { VpnController.reload(this) }
        VpnState.listener = {
            MihomoTileService.requestUpdate(this)
            runCatching { StatusWidget.updateAll(this) }
        }
    }
}
