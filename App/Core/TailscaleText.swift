import Foundation

// MARK: - Tailscale Localized Text & String Mapping (App)
//
// Centralizes all Tailscale-specific localized strings, status mappings,
// reset confirmation dialog texts, and kernel error translations for the App.

enum TailscaleText {
    // MARK: - Kernel Guard & Message Localization

    /// Translates kernel / bridge guard messages and error strings for Tailscale.
    /// Returns a localized string if matched, or nil if the string is not Tailscale-specific.
    static func localize(_ s: String) -> String? {
        // v0.18 Tailscale guard messages (numbers vary; detailed readout in 诊断 → 隧道内存).
        if s.hasPrefix("Tailscale 未启动：") {
            return String(localized: "Tailscale 未启动：隧道扩展可用内存不足，继续启动可能让系统直接终止 VPN。详见 更多 → 诊断 → 隧道内存。")
        }
        if s.hasPrefix("Tailscale 已停止：") {
            return String(localized: "Tailscale 已停止：隧道扩展可用内存过低，为避免 VPN 被系统终止已关闭 Tailscale。重新连接后可再次使用。")
        }
        if s == "Tailscale 节点只能在连接后测速" {
            return String(localized: "Tailscale 节点只能在连接后测速")
        }
        return nil
    }

    // MARK: - Node State Text Mapping

    /// Maps status file `state` string to human-readable localized text.
    /// State values from NCTailscaleLoginState:
    /// - "started" -> "已连接"
    /// - "starting" -> "启动中"
    /// - "needsLogin" -> "需要登录"
    /// - "refused", "stopped" -> "内存不足已停用"
    /// - "failed" -> "启动失败"
    /// - "idle", empty, nil -> "未启动"
    static func statusStateText(_ state: String?) -> String {
        guard let s = state?.trimmingCharacters(in: .whitespacesAndNewlines), !s.isEmpty else {
            return String(localized: "未启动")
        }
        switch s {
        case "started":
            return String(localized: "已连接")
        case "starting":
            return String(localized: "启动中")
        case "needsLogin":
            return String(localized: "需要登录")
        case "refused", "stopped":
            return String(localized: "内存不足已停用")
        case "failed":
            return String(localized: "启动失败")
        case "idle":
            return String(localized: "未启动")
        default:
            return String(localized: "未启动")
        }
    }

    // MARK: - Reset Confirmation Dialog Texts

    static let resetConfirmTitle = String(localized: "重置 Tailscale 状态？")
    static let resetAction = String(localized: "重置状态")
    static let resetMenuLabel = String(localized: "重置 Tailscale 状态")

    /// Formats the confirmation message for resetting a Tailscale node's state.
    /// Explicitly informs the user that state-dir will be deleted and re-login will be required.
    /// Warns to disconnect the VPN first if the tunnel is currently active.
    static func resetConfirmMessage(nodeName: String, isVPNConnected: Bool) -> String {
        if isVPNConnected {
            return String(localized: "将删除节点「\(nodeName)」的状态目录并清除登录信息，下次连接需要重新登录。当前 VPN 正在运行，删除可能导致连接异常，请先断开 VPN。")
        } else {
            return String(localized: "将删除节点「\(nodeName)」的状态目录并清除登录信息，下次连接需要重新登录。")
        }
    }

    // MARK: - Peer Counts & DERP Region Formatting

    static func peerCountsText(direct: Int, relay: Int) -> String {
        return String(localized: "直连 \(direct) / 中继 \(relay)")
    }

    static func derpRegionText(_ region: Int) -> String {
        return "Region \(region)"
    }

    // MARK: - Status File Diagnostics Texts

    static let statusFileNotFound = String(localized: "状态文件不存在")
}
