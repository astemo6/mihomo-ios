import SwiftUI
import UIKit
import Darwin

/// fix/nc-ui-smooth: frame-hitch probe for the simulator UI performance tests (UITests/UISmoothPerfUITests.swift).
///
/// Debug builds only, and only with `-UITestSeed -UIPerfProbe`. A CADisplayLink on the main run loop (common modes, so
/// it also fires while a scroll view tracks) records every frame interval. A frame that arrives later than 1.5× the
/// display's nominal frame time is a hitch; the time past the nominal frame is the hitch time (Apple's "hitch time
/// ratio" = hitch ms per second of the window). Main-thread stalls (file IO, parsing, a big re-render) show up here as
/// late frames whether or not anything is animating.
///
/// `-UIPerfScenario` also runs a scripted sequence of transitions *inside the app* (tab switches, 出站模式 switches on
/// 策略 and 首页, offline node selection, Home layout edits) while the test process stays idle, so the numbers are not
/// polluted by XCUITest's own accessibility queries (each query runs on the app's main thread). Results are read
/// through one hidden accessibility element, `uiperf.probe`, whose label is built only when it is queried.
@MainActor
final class UIPerfProbe: NSObject {
    static let shared = UIPerfProbe()

    static var enabled: Bool {
        #if DEBUG
        return UITestSeed.enabled && UITestSeed.args.contains("-UIPerfProbe")
        #else
        return false
        #endif
    }

    struct Counters { var frames = 0; var hitches = 0; var hitchMs = 0.0; var maxMs = 0.0; var start: CFTimeInterval = 0 }
    struct StepResult { let name: String; let frames: Int; let hitches: Int; let hitchMs: Double; let maxMs: Double; let windowMs: Double; let cpuMs: Double }

    /// Main-thread CPU time (user + system) in ms: the work the step put on the main thread, independent of how the
    /// simulator happened to draw (frame hitches on shared CI runners are noisy; this is far steadier).
    private var mainThread: thread_act_t = 0
    func mainCPUms() -> Double {
        guard mainThread != 0 else { return 0 }
        var info = thread_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<thread_basic_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                thread_info(mainThread, thread_flavor_t(THREAD_BASIC_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return 0 }
        let u = Double(info.user_time.seconds) * 1000 + Double(info.user_time.microseconds) / 1000
        let sy = Double(info.system_time.seconds) * 1000 + Double(info.system_time.microseconds) / 1000
        return u + sy
    }

    private var link: CADisplayLink?
    private var last: CFTimeInterval = 0
    /// Longest frame interval since the current step started.
    private var windowMax = 0.0
    private(set) var total = Counters()
    private(set) var results: [StepResult] = []
    private(set) var state = "idle"

    func startIfNeeded() {
        guard Self.enabled, link == nil else { return }
        mainThread = mach_thread_self() // on the main thread (called from onAppear)
        let l = CADisplayLink(target: self, selector: #selector(tick(_:)))
        l.add(to: .main, forMode: .common)
        link = l
        total.start = CACurrentMediaTime()
        if UITestSeed.args.contains("-UIPerfScenario") {
            Task { @MainActor in await UIPerfScenario.run(self) }
        }
    }

    @objc private func tick(_ l: CADisplayLink) {
        let now = l.timestamp
        defer { last = now }
        guard last > 0 else { return }
        let dt = now - last
        let nominal = l.duration > 0 ? l.duration : 1.0 / 60
        total.frames += 1
        if dt > nominal * 1.5 {
            total.hitches += 1
            total.hitchMs += (dt - nominal) * 1000
        }
        total.maxMs = max(total.maxMs, dt * 1000)
        windowMax = max(windowMax, dt * 1000)
    }

    /// Measures `body` plus `settle` seconds after it (the transition / animation that follows).
    func step(_ name: String, settle: Double = 0.8, _ body: () async -> Void) async {
        let before = total
        let t0 = CACurrentMediaTime()
        let c0 = mainCPUms()
        windowMax = 0
        await body()
        try? await Task.sleep(nanoseconds: UInt64(settle * 1_000_000_000))
        let window = (CACurrentMediaTime() - t0) * 1000
        let r = StepResult(name: name, frames: total.frames - before.frames, hitches: total.hitches - before.hitches,
                           hitchMs: total.hitchMs - before.hitchMs, maxMs: windowMax, windowMs: window, cpuMs: mainCPUms() - c0)
        results.append(r)
    }

    func setState(_ s: String) { state = s }

    /// `state=done|steps=N` then one `name frames hitches hitchMs maxMs windowMs` line per step and per-group sums.
    var summary: String {
        var lines = ["state=\(state)|steps=\(results.count)|frames=\(total.frames)|hitches=\(total.hitches)|hitchMs=\(Int(total.hitchMs.rounded()))"]
        var groups: [String: (n: Int, hitches: Int, hitchMs: Double, windowMs: Double, maxMs: Double, cpuMs: Double)] = [:]
        var order: [String] = []
        for r in results {
            lines.append(String(format: "%@ f=%d h=%d hms=%.0f max=%.0f win=%.0f cpu=%.0f", r.name, r.frames, r.hitches, r.hitchMs, r.maxMs, r.windowMs, r.cpuMs))
            let g = String(r.name.split(separator: ":").first ?? Substring(r.name))
            if groups[g] == nil { order.append(g) }
            var v = groups[g] ?? (0, 0, 0, 0, 0, 0)
            v.n += 1; v.hitches += r.hitches; v.hitchMs += r.hitchMs; v.windowMs += r.windowMs; v.maxMs = max(v.maxMs, r.maxMs)
            v.cpuMs += r.cpuMs
            groups[g] = v
        }
        for g in order {
            let v = groups[g]!
            let ratio = v.windowMs > 0 ? v.hitchMs / (v.windowMs / 1000) : 0
            lines.append(String(format: "SUM %@ n=%d hitches=%d hitchMs=%.0f ratio=%.1fms/s worstFrame=%.0fms mainCPU=%.0fms (%.0f/step)", g, v.n, v.hitches, v.hitchMs, ratio, v.maxMs, v.cpuMs, v.cpuMs / Double(max(v.n, 1))))
        }
        return lines.joined(separator: "\n")
    }
}

/// The scripted transitions (model-level triggers; the real views react exactly as to a tap).
@MainActor
enum UIPerfScenario {
    static func run(_ p: UIPerfProbe) async {
        p.setState("waiting")
        // Wait for the seed, then give XCUITest time to stop polling for `uitest.ready`.
        while !UITestSeed.ready { try? await Task.sleep(nanoseconds: 200_000_000) }
        try? await Task.sleep(nanoseconds: 4_000_000_000)
        p.setState("running")
        let router = ImportRouter.shared
        let dash = DashboardModel.shared

        // 1. Tab switches (each tab root appears: .task / onAppear loads, mode mirrors, Home visibility).
        for round in 0..<3 {
            for t in [1, 2, 3, 4, 0] {
                await p.step("tab:\(round)-\(t)", settle: 0.7) { router.selectedTab = t }
            }
        }

        // 2. 出站模式 on 策略 (global hides the rule groups: a relayout of the list) and on 首页.
        let original = dash.mode
        router.selectedTab = 1
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        for m in ["global", "direct", "rule", "global", "rule"] {
            await p.step("mode-policy:\(m)", settle: 0.9) { await dash.setMode(m) }
        }
        router.selectedTab = 0
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        for m in ["global", "rule", "direct", "rule"] {
            await p.step("mode-home:\(m)", settle: 0.9) { await dash.setMode(m) }
        }
        if dash.mode != original { await dash.setMode(original) }

        // 3. Node selection while disconnected (策略 offline list; the big profile has a 3000-member select group).
        router.selectedTab = 1
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        let insp = ProfileInspector.shared
        if let g = insp.result.groups.first(where: { $0.type == "select" && insp.members(of: $0).count >= 2 }) {
            let members = insp.members(of: g)
            for i in 0..<8 {
                let node = members[(i + 1) % min(members.count, 12)]
                await p.step("select:\(i)", settle: 0.6) { insp.select(group: g.name, node: node) }
            }
            insp.select(group: g.name, node: members[0])
        }

        // 3b. Expand / collapse the biggest group on 策略 (the big profile's 3000-member select), then select while it
        //     is expanded (every member cell on screen re-renders). PolicyView listens in Debug builds only.
        if let big = insp.result.groups.filter({ insp.members(of: $0).count >= 200 }).max(by: { insp.members(of: $0).count < insp.members(of: $1).count }) {
            let members = insp.members(of: big)
            for i in 0..<3 {
                await p.step("expand:\(i)", settle: 1.0) { NotificationCenter.default.post(name: .uiPerfExpandGroup, object: big.name, userInfo: ["on": true]) }
                if big.type == "select" {
                    await p.step("select-expanded:\(i)", settle: 0.8) { insp.select(group: big.name, node: members[(i + 1) % members.count]) }
                }
                await p.step("collapse:\(i)", settle: 1.0) { NotificationCenter.default.post(name: .uiPerfExpandGroup, object: big.name, userInfo: ["on": false]) }
            }
            insp.select(group: big.name, node: members[0])
        }

        // 4. Home layout edits (half / full width, reorder) with the same animations as the menu actions.
        router.selectedTab = 0
        try? await Task.sleep(nanoseconds: 1_000_000_000)
        let pinned = PanelsModel.shared.pinned
        if let first = pinned.first {
            let wasHalf = PanelOverride.isHalf(id: first, override: PanelOverrideStore.shared.map[first])
            for i in 0..<4 {
                let half = i % 2 == 0 ? !wasHalf : wasHalf
                await p.step("home-width:\(i)", settle: 0.7) { withAnimation { PanelOverrideStore.shared.setHalf(half, for: first) } }
            }
        }
        if pinned.count >= 2 {
            for i in 0..<4 {
                let by = i % 2 == 0 ? 1 : -1
                let id = pinned[0] // down, then back up
                await p.step("home-order:\(i)", settle: 0.7) { withAnimation { HomePanelStore.shared.step(id, by: by) } }
            }
        }
        p.setState("done")
    }
}

extension Notification.Name {
    /// UIPerfScenario → PolicyView (Debug builds): expand (`userInfo["on"] == true`) or collapse the group named by `object`.
    static let uiPerfExpandGroup = Notification.Name("tern.uiperf.expandGroup")
}

/// Hidden accessibility element `uiperf.probe` (label = UIPerfProbe.summary, built when XCUITest reads it).
struct UIPerfProbeMarker: View {
    var body: some View {
        if UIPerfProbe.enabled {
            ProbeElement()
                .frame(width: 2, height: 2)
                .allowsHitTesting(false)
                .onAppear { UIPerfProbe.shared.startIfNeeded() }
        }
    }

    private struct ProbeElement: UIViewRepresentable {
        func makeUIView(context: Context) -> ProbeView { ProbeView() }
        func updateUIView(_ uiView: ProbeView, context: Context) {}
    }

    final class ProbeView: UIView {
        override init(frame: CGRect) {
            super.init(frame: frame)
            isAccessibilityElement = true
            accessibilityIdentifier = "uiperf.probe"
            alpha = 0.02
            backgroundColor = .clear
        }
        required init?(coder: NSCoder) { fatalError() }
        override var accessibilityLabel: String? {
            get { UIPerfProbe.shared.summary }
            set {}
        }
    }
}
