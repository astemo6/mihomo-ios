package io.github.astemo6.mihomo.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

enum class VpnStatus { STOPPED, CONNECTING, RUNNING, STOPPING }

data class VpnInfo(
    val status: VpnStatus = VpnStatus.STOPPED,
    /** epoch millis when the core came up */
    val since: Long? = null,
    /** why the last start failed / why the VPN stopped unexpectedly (shown once in the UI) */
    val error: String? = null,
    /** "Group ➤ Node" of the first policy group, for the widget / notification */
    val nodeText: String? = null,
    val mode: String? = null,
) {
    val isRunning: Boolean get() = status == VpnStatus.RUNNING
    val isBusy: Boolean get() = status == VpnStatus.CONNECTING || status == VpnStatus.STOPPING
}

/** In-process VPN state (service and UI share one process, so the Go runtime loads once). */
object VpnState {
    private val _info = MutableStateFlow(VpnInfo())
    val info: StateFlow<VpnInfo> = _info.asStateFlow()

    /** Called on every change (tile / widget refresh). */
    var listener: ((VpnInfo) -> Unit)? = null

    fun update(block: (VpnInfo) -> VpnInfo) {
        _info.update(block)
        listener?.invoke(_info.value)
    }

    fun clearError() = update { it.copy(error = null) }
}
