import Foundation
import CryptoKit

/// B6 (nc-dego-rest): bridge/workbench.go ScriptSource / mitm.ScriptSource + mitm/resources.go (Get, cachePath,
/// LocalPath, fetch) in Swift — the code of a local script, or the cached copy of a remote one (downloaded and
/// cached when missing). Used by 脚本列表, 脚本调试台, 地理位置检测 and the workbench's debug runs.
///
/// Difference: Go downloaded through the core's own client (the user's rules applied in-process); the app
/// downloads with URLSession, i.e. through the VPN when it is connected, directly otherwise.
enum NCScriptSource {

    static let maxBytes = 8 << 20 // mitm maxResourceBytes

    /// mitm CachePath: <home>/engine/cache/<sha1(url) hex>.
    static func cachePath(home: String, url: String) -> String {
        let h = Insecure.SHA1.hash(data: Data(url.utf8)).ncHex
        return URL(fileURLWithPath: home).appendingPathComponent("engine/cache").appendingPathComponent(h).path
    }

    static func isRemote(_ p: String) -> Bool { p.hasPrefix("http://") || p.hasPrefix("https://") }

    /// mitm LocalPath: absolute, file://, or relative to engine/scripts (cleaned, cannot climb out).
    static func localPath(home: String, _ p0: String) -> String {
        let p = p0.hasPrefix("file://") ? String(p0.dropFirst(7)) : p0
        if p.hasPrefix("/") { return p }
        let cleaned = (("/" + p) as NSString).standardizingPath // filepath.Clean("/"+p)
        return URL(fileURLWithPath: home).appendingPathComponent("engine/scripts").path + cleaned
    }

    /// mitm Resources.Get(path, 0): a local file, else the cached remote copy, else a download.
    static func source(home: String, path: String) -> Result<String, NCOverrideOutput.InputError> {
        if !isRemote(path) {
            let lp = localPath(home: home, path)
            guard let d = FileManager.default.contents(atPath: lp) else {
                return .failure(.init(message: "读取脚本失败：\(lp)"))
            }
            return .success(String(decoding: d, as: UTF8.self))
        }
        let cp = cachePath(home: home, url: path)
        if let d = FileManager.default.contents(atPath: cp) {
            return .success(String(decoding: d, as: UTF8.self))
        }
        return fetch(home: home, url: path).map { String(decoding: $0, as: UTF8.self) }
    }

    /// The (code, error) pair the call sites used with LibmihomoScriptSource + LibmihomoLastError.
    static func codeAndError(home: String, path: String) -> (String, String) {
        switch source(home: home, path: path) {
        case .success(let s): return (s, "")
        case .failure(let e): return ("", e.message)
        }
    }

    private static func clip(_ s: String, _ n: Int) -> String { s.count <= n ? s : String(s.prefix(n)) + "…" }

    /// mitm Resources.fetch: GET (30 s, Surge UA), 200 only, ≤ 8 MB, cached atomically. Blocks the caller
    /// (the call sites run it off the main thread).
    static func fetch(home: String, url u: String) -> Result<Data, NCOverrideOutput.InputError> {
        guard let url = URL(string: u) else { return .failure(.init(message: "下载 \(clip(u, 80)) 失败：链接无效")) }
        var req = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        req.setValue("Surge iOS/3000 Tern", forHTTPHeaderField: "User-Agent")
        let sem = DispatchSemaphore(value: 0)
        var out: Result<Data, NCOverrideOutput.InputError> = .failure(.init(message: "下载 \(clip(u, 80)) 失败"))
        let task = URLSession.shared.dataTask(with: req) { data, resp, err in
            defer { sem.signal() }
            if let err {
                out = .failure(.init(message: "下载 \(clip(u, 80)) 失败：\(err.localizedDescription)"))
                return
            }
            let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
            guard code == 200 else {
                out = .failure(.init(message: "下载 \(clip(u, 80)) 失败：HTTP \(code)"))
                return
            }
            let d = data ?? Data()
            guard d.count <= maxBytes else {
                out = .failure(.init(message: "下载 \(clip(u, 80)) 失败：文件超过 \(maxBytes >> 20) MB"))
                return
            }
            out = .success(d)
        }
        task.resume()
        sem.wait()
        if case .success(let d) = out {
            let cp = cachePath(home: home, url: u)
            try? FileManager.default.createDirectory(atPath: (cp as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try? NCRuntimeFiles.writeAtomic(d, to: cp)
        }
        return out
    }
}
