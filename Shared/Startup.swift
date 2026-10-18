import Foundation
import Darwin
import os

/// Startup stage log in the App Group container (Swift and Go both append). Shown in 诊断.
enum StartupLog {
    static var url: URL { AppShared.containerURL.appendingPathComponent("startup-log.txt") }
    static var previousURL: URL { AppShared.containerURL.appendingPathComponent("startup-log.prev.txt") }

    private static let fmt: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()
    private static let lock = NSLock()

    /// Keeps the previous run as .prev and starts a fresh log with a header line.
    static func begin(_ header: String) {
        lock.lock(); defer { lock.unlock() }
        let fm = FileManager.default
        try? fm.removeItem(at: previousURL)
        if fm.fileExists(atPath: url.path) { try? fm.moveItem(at: url, to: previousURL) }
        let day = ISO8601DateFormatter.string(from: Date(), timeZone: .current, formatOptions: [.withInternetDateTime])
        try? "=== \(header) \(day)\n".data(using: .utf8)?.write(to: url, options: .atomic)
    }

    static func write(_ msg: String, tag: String = "ext") {
        lock.lock(); defer { lock.unlock() }
        let line = "\(fmt.string(from: Date())) [\(tag)] \(msg)\n"
        NSLog("[Mihomo] %@", msg)
        guard let data = line.data(using: .utf8) else { return }
        if let h = try? FileHandle(forWritingTo: url) {
            h.seekToEndOfFile()
            h.write(data)
            try? h.close()
        } else {
            try? data.write(to: url, options: .atomic)
        }
    }

    static func read() -> String {
        let cur = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        let prev = (try? String(contentsOf: previousURL, encoding: .utf8)) ?? ""
        if prev.isEmpty { return cur }
        return cur + "\n--- 上一次 ---\n" + prev
    }
}

/// Process memory as iOS jetsam sees it (phys_footprint) and the remaining headroom.
enum ProcessMemory {
    static func footprintBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : 0
    }

    /// v0.18: the kernel's lifetime peak of phys_footprint for this process (task_vm_info rev 3+),
    /// 0 when the running OS does not report it.
    static func peakBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        let full = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        var count = full
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS, let off = MemoryLayout<task_vm_info_data_t>.offset(of: \.ledger_phys_footprint_peak),
              Int(count) * MemoryLayout<integer_t>.size >= off + 8 else { return 0 }
        return UInt64(max(0, info.ledger_phys_footprint_peak))
    }

    static func availableBytes() -> Int {
        if #available(iOS 13.0, *) { return Int(os_proc_available_memory()) }
        return -1
    }

    static func summary() -> String {
        let mb = { (v: Double) in String(format: "%.1f MB", v / 1_048_576) }
        let avail = availableBytes()
        return "footprint \(mb(Double(footprintBytes())))" + (avail >= 0 ? ", available \(mb(Double(avail)))" : "")
    }
}

/// Geo databases bundled in the PacketTunnel extension (Geo/ in the repo), copied into the core home
/// dir when missing or truncated so the core never downloads them at startup.
enum GeoBootstrap {
    /// ASN.mmdb is no longer bundled (v0.14 size pass): the core downloads it when a profile uses IP-ASN.
    static let files = ["geoip.metadb", "GeoSite.dat"]

    /// Bundle that carries the files: the extension itself, or the embedded PacketTunnel.appex from the app.
    static var resourceBundles: [Bundle] {
        var out: [Bundle] = [.main]
        if let plug = AppShared.mainAppBundle.builtInPlugInsURL,
           let items = try? FileManager.default.contentsOfDirectory(at: plug, includingPropertiesForKeys: nil) {
            for u in items where u.pathExtension == "appex" { if let b = Bundle(url: u) { out.append(b) } }
        }
        return out
    }

    @discardableResult
    static func install(log: ((String) -> Void)? = nil) -> Int {
        let fm = FileManager.default
        let home = AppShared.homeURL
        var copied = 0
        for name in files {
            let dst = home.appendingPathComponent(name)
            // mihomo matches these names case-insensitively; a different-case copy counts too.
            let existing = (try? fm.contentsOfDirectory(atPath: home.path))?.first { $0.caseInsensitiveCompare(name) == .orderedSame }
            let existingURL = existing.map { home.appendingPathComponent($0) }
            let size = existingURL.flatMap { (try? fm.attributesOfItem(atPath: $0.path)[.size] as? NSNumber)?.intValue } ?? 0
            if size > 64 * 1024 { continue } // present and plausibly complete
            guard let src = resourceBundles.lazy.compactMap({ $0.url(forResource: name, withExtension: nil) }).first else {
                log?("geo: \(name) 未打包")
                continue
            }
            if let e = existingURL { try? fm.removeItem(at: e) }
            do {
                try fm.copyItem(at: src, to: dst)
                copied += 1
                log?("geo: 已复制内置 \(name)")
            } catch {
                log?("geo: 复制 \(name) 失败：\(error.localizedDescription)")
            }
        }
        return copied
    }
}

/// v0.18 隧道内存: the extension's last memory snapshot (MemorySnapshot JSON from Go, with footprint / peak /
/// available measured in Swift), written to the App Group on every MemoryGuard tick and on each
/// memoryStats request, so 更多 → 诊断 still shows the last values (and the peak) after the tunnel stopped
/// or was killed.
enum TunnelMemoryFile {
    static var url: URL { AppShared.containerURL.appendingPathComponent("tunnel-memory.json") }
    static func write(_ json: String) { try? Data(json.utf8).write(to: url, options: .atomic) }
    static func read() -> Data? { try? Data(contentsOf: url) }
}
