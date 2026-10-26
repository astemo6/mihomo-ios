import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// fix/nc-ruleset-fast: conditional GET for every cached remote resource (tunnel rule sets, the App's rule / node
/// provider downloads, modules / rewrite sets, remote rule lists and scripts of 模块与资源) — the QuantumultX
/// 「更新」 behaviour: a resource that did not change costs one small request and no parse.
///
/// Per cache file a small JSON sidecar `.<cache file name>.etag` (hidden, next to the cache file; nothing that
/// lists a cache directory by its `set-` / `.txt` / `.js` names sees it) keeps
/// - the source URL (a sidecar of another URL is ignored),
/// - the response's `ETag` / `Last-Modified` → sent back as `If-None-Match` / `If-Modified-Since`,
/// - size + SHA-256 of the source body last stored → a 200 with a byte-identical body is not stored / parsed again
///   (servers without validators, raw.githubusercontent.com's short max-age, mirrors),
/// - the size of the cache file as written → a cache file rewritten by any other path invalidates the sidecar, so
///   a 304 can never keep a cache the validators do not describe.
struct NCFetchValidators: Codable, Equatable {
    var url: String
    var etag: String? = nil
    var lastModified: String? = nil
    var bodySize: Int = -1
    var bodyHash: String = ""
    var cacheSize: Int = -1

    static func sidecar(for cache: URL) -> URL {
        cache.deletingLastPathComponent().appendingPathComponent("." + cache.lastPathComponent + ".etag")
    }

    /// The sidecar of `cache` when it belongs to `url` and still describes the cache file on disk.
    static func load(for cache: URL, url: String) -> NCFetchValidators? {
        guard let d = try? Data(contentsOf: sidecar(for: cache)),
              let v = try? JSONDecoder().decode(NCFetchValidators.self, from: d),
              v.url == url, let size = fileSize(cache), size == v.cacheSize else { return nil }
        return v
    }

    func save(for cache: URL) {
        guard let d = try? JSONEncoder().encode(self) else { return }
        try? d.write(to: Self.sidecar(for: cache), options: .atomic)
    }

    static func remove(for cache: URL) {
        try? FileManager.default.removeItem(at: sidecar(for: cache))
    }

    /// `If-None-Match` / `If-Modified-Since` for the next request (empty when the server gave neither).
    var requestHeaders: [String: String] {
        var h: [String: String] = [:]
        if let etag, !etag.isEmpty { h["If-None-Match"] = etag }
        if let lastModified, !lastModified.isEmpty { h["If-Modified-Since"] = lastModified }
        return h
    }

    func apply(to req: inout URLRequest) {
        for (k, v) in requestHeaders { req.setValue(v, forHTTPHeaderField: k) }
    }

    func sameBody(size: Int, hash: String) -> Bool { bodySize >= 0 && bodySize == size && bodyHash == hash }

    static func headers(of resp: URLResponse?) -> (etag: String?, lastModified: String?) {
        guard let h = resp as? HTTPURLResponse else { return (nil, nil) }
        return (h.value(forHTTPHeaderField: "ETag"), h.value(forHTTPHeaderField: "Last-Modified"))
    }

    static func fileSize(_ url: URL) -> Int? {
        ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.intValue
    }

    /// A kept cache was checked just now: its modification time is the 「更新于」 time the lists show (mtime).
    static func touch(_ cache: URL) {
        try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: cache.path)
    }
}

/// Content hash for the identical-body check. Over a memory-mapped Data it reads clean file-backed pages, no heap
/// copy of the body.
enum NCContentHash {
    static func hex(_ data: Data) -> String {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        var h: UInt64 = 0xcbf29ce484222325
        data.withUnsafeBytes { raw in for b in raw { h = (h ^ UInt64(b)) &* 0x100000001b3 } }
        return String(format: "fnv-%016llx", h)
        #endif
    }

    /// (size, hash) of a file, mapped. nil when it cannot be read.
    static func file(_ url: URL) -> (size: Int, hash: String)? {
        guard let d = try? Data(contentsOf: url, options: .alwaysMapped) else { return nil }
        return (d.count, hex(d))
    }
}

/// fix/nc-ruleset-fast: the App-side conditional fetch shared by the provider / resource updaters (in-memory body,
/// the App has no extension memory cap). No URLCache (a URLCache would answer a 304 with its own stored copy as a
/// 200, hiding it, and keep a second copy of every body), no cookies.
enum NCConditionalFetch {
    enum Outcome {
        /// 304, or a 200 whose body is byte-identical to the one last stored: the cache was kept (and touched).
        case unchanged
        /// A new body: the caller stores it, then calls `commit` with the cache file it wrote.
        case body(Data, commit: (URL) -> Void)
        case failed(String)
    }

    static let session: URLSession = {
        let c = URLSessionConfiguration.ephemeral
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpCookieStorage = nil
        c.httpMaximumConnectionsPerHost = 6
        return URLSession(configuration: c)
    }()

    /// GET `urlString` for `cache` (the file the caller writes the converted / validated body to). `maxBytes` (0 = no
    /// cap) rejects an oversized body. `httpGet` is the test seam.
    static func fetch(_ urlString: String, cache: URL, userAgent: String?, maxBytes: Int = 0,
                      httpGet: ((URLRequest) async throws -> (Data, URLResponse))? = nil) async -> Outcome {
        guard let u = URL(string: urlString), u.scheme?.hasPrefix("http") == true else { return .failed("链接无效") }
        var req = URLRequest(url: u, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        if let userAgent { req.setValue(userAgent, forHTTPHeaderField: "User-Agent") }
        let prev = NCFetchValidators.load(for: cache, url: urlString)
        prev?.apply(to: &req)
        let data: Data, resp: URLResponse
        do {
            if let httpGet { (data, resp) = try await httpGet(req) } else { (data, resp) = try await session.data(for: req) }
        } catch {
            return .failed(error.localizedDescription)
        }
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        let (etag, lm) = NCFetchValidators.headers(of: resp)
        if code == 304 {
            guard var v = prev else { return .failed("HTTP 304") } // we sent no validators: not ours to keep
            if let etag { v.etag = etag }
            if let lm { v.lastModified = lm }
            NCFetchValidators.touch(cache)
            v.save(for: cache)
            return .unchanged
        }
        guard (200..<300).contains(code) else { return .failed("HTTP \(code)") }
        if maxBytes > 0, data.count > maxBytes { return .failed("文件超过 \(maxBytes >> 20) MB") }
        let hash = NCContentHash.hex(data)
        if var v = prev, v.sameBody(size: data.count, hash: hash) {
            v.etag = etag
            v.lastModified = lm
            NCFetchValidators.touch(cache)
            v.cacheSize = NCFetchValidators.fileSize(cache) ?? v.cacheSize
            v.save(for: cache)
            return .unchanged
        }
        let size = data.count
        return .body(data, commit: { written in
            guard let cs = NCFetchValidators.fileSize(written) else { return }
            NCFetchValidators(url: urlString, etag: etag, lastModified: lm, bodySize: size, bodyHash: hash,
                              cacheSize: cs).save(for: written)
        })
    }
}
