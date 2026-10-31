import Foundation
import UIKit

/// 诊断 → 导出诊断包: asks the running tunnel to flush its core-log / memory rings, collects the app's
/// own state, and writes one redacted zip.
@MainActor
enum DiagnosticsExporter {
    /// Builds the bundle and returns its file URL (in the app's temporary directory).
    static func export(vpn: VPNManager) async throws -> URL {
        let tunnelReply = await flushTunnel(vpn)
        let info = appInfo(vpn: vpn, tunnelReply: tunnelReply)
        let stamp = Self.stamp.string(from: Date())
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("diagnostics", isDirectory: true)
        try? FileManager.default.removeItem(at: dir) // keep only the newest bundle around
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let out = dir.appendingPathComponent("Tern-diagnostics-\(stamp).zip")
        let home = AppShared.homeURL.path
        let profile = AppShared.activeProfileURL?.path ?? ""
        let cachedModules = EngineStore.shared.moduleInfo
        try await Task.detached(priority: .userInitiated) {
            try DiagnosticSummary.writeBundle(home: home, profilePath: profile, appInfo: info, outPath: out.path,
                                              cachedModuleInfo: cachedModules)
        }.value
        return out
    }

    /// The same content as one redacted text (for pasting into a chat).
    static func summaryText(vpn: VPNManager) async -> String {
        let tunnelReply = await flushTunnel(vpn)
        let info = appInfo(vpn: vpn, tunnelReply: tunnelReply)
        let home = AppShared.homeURL.path
        let profile = AppShared.activeProfileURL?.path ?? ""
        let cachedModules = EngineStore.shared.moduleInfo
        return await Task.detached(priority: .userInitiated) {
            DiagnosticSummary.generate(home: home, profilePath: profile, appInfo: info, cachedModuleInfo: cachedModules)
        }.value
    }

    private static func flushTunnel(_ vpn: VPNManager) async -> String? {
        guard vpn.isConnected, let d = await vpn.send(.dumpDiagnostics, timeout: 4) else { return nil }
        return String(data: d, encoding: .utf8)
    }

    private static let stamp: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f
    }()

    static func version(of bundle: Bundle?) -> String {
        guard let bundle else { return "?" }
        let v = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let b = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
        return "\(v) (\(b))"
    }

    static var tunnelBundle: Bundle? {
        guard let plug = Bundle.main.builtInPlugInsURL,
              let items = try? FileManager.default.contentsOfDirectory(at: plug, includingPropertiesForKeys: nil) else { return nil }
        return items.filter { $0.pathExtension == "appex" }.compactMap { Bundle(url: $0) }.first
    }

    /// key=value lines; DiagnosticSummary adds the core version and redacts everything again.
    static func appInfo(vpn: VPNManager, tunnelReply: String?) -> String {
        let o = CoreOverrides.load()
        let dev = UIDevice.current
        var sys = utsname()
        uname(&sys)
        let machine = withUnsafeBytes(of: &sys.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        let engine = EngineStore.shared.config
        var lines: [String] = [
            "app=\(version(of: .main))",
            "tunnel=\(version(of: tunnelBundle))",
            "ios=\(dev.systemName) \(dev.systemVersion)",
            "device=\(machine) (\(dev.userInterfaceIdiom == .pad ? "iPad" : "iPhone"))",
            "language=\(Locale.preferredLanguages.prefix(3).joined(separator: ","))",
            "app.id=\(AppShared.mainAppBundleID)",
            "tunnel.id=\(AppShared.tunnelBundleID)",
            "appgroup=\(AppShared.appGroup) source=\(AppShared.appGroupSource) container=\(AppShared.containerOK ? "OK" : "UNAVAILABLE")",
            "appgroup.provisioned=\(AppShared.provisionedAppGroups().joined(separator: ","))",
            // r7 R7A-3 / B05: every candidate with what decided the choice.
            "appgroup.candidates=" + AppShared.appGroupCandidates.map { "\($0.group)[\($0.source)\($0.accepted ? "" : ",denied")\($0.hasData ? ",data" : "")\($0.ours ? ",marker" : "")]" }.joined(separator: " "),
            "appgroup.warning=\(AppShared.appGroupWarning ?? "-")",
            "vpn.status=\(vpn.statusText) configured=\(vpn.hasConfiguration)",
            "vpn.lastError=\(vpn.lastError ?? "-")",
            "tunnel.lastStop=\(TunnelStopReason.last() ?? "-")",
            "tunnel.memory=\(tunnelReply ?? "-（未连接或扩展无响应）")",
            "mode=\(o.tunnelMode) dns=\(o.dnsMode) ipv6=\(o.ipv6Mode) ipPref=\(o.ipPreference) mtu=\(o.tunMTU) memlimit=\(o.memoryLimitMB)MB testURL=\(o.testURL) hcOverride=\(o.overrideHealthCheck) loglevel=\(o.logLevel) sniffer=\(o.sniffer) httpdnsGuard=\(o.httpdnsGuard) allowLan=\(o.allowLan) mergeManual=\(o.mergeManual) safeMode=\(o.safeMode) stunDrop=\(o.stunDropDirect) blockWebRTC=\(o.blockWebRTC) udpFallback=\(o.udpFallback) notDefaultRoute=\(o.notDefaultRoute) hideVPNIcon=\(o.hideVPNIcon) dnsHijack=\(o.dnsHijack.count) tcpDelay=\(o.tcpHandshakeDelay) localTunnel=\(o.localDeviceTunnel ? o.localDeviceTunnelPeer : "off")",
            "tunnel.scope includeAll=\(o.includeAllNetworks) faceTime=\(o.faceTimeProxy) enforceRoutes=\(o.enforceRoutes) local=\(!o.excludeLocalNetworks) apns=\(!o.excludeAPNs) cellular=\(!o.excludeCellularServices) device=\(!o.excludeDeviceCommunication)",
            "ondemand=\(OnDemandSettings.load().mode.rawValue) paused=\(OnDemandSettings.isPaused)",
            "engine.enabled=\(engine.enabled) mitm=\(engine.mitm) modules=\(engine.modules.filter(\.enabled).count)/\(engine.modules.count)",
            "profiles=\(ProfileStore.shared.profiles.count) active=\(ProfileStore.shared.active?.kind.rawValue ?? "none")",
            "app.memory=\(ProcessMemory.summary())",
        ]
        if let p = ProfileStore.shared.active {
            lines.append("active.profile.name=\(p.name) updated=\(p.lastUpdated.map { ISO8601DateFormatter().string(from: $0) } ?? "-")")
        }
        return lines.joined(separator: "\n")
    }
}
