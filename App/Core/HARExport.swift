import Foundation

// v0.10: HAR 1.2 export of the MitM / rewrite engine's request capture (请求 → HTTP).
// Bodies are what the engine captured (text up to 32 KB, decoded); binary bodies are left out and
// noted in the entry's comment. Timings carry only the total duration the engine measured.

enum HARExport {
    static func iso(_ t: Double) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date(timeIntervalSince1970: t))
    }

    static func headers(_ h: [String: String]?) -> [[String: String]] {
        (h ?? [:]).keys.sorted().map { ["name": $0, "value": h?[$0] ?? ""] }
    }

    static func header(_ h: [String: String]?, _ name: String) -> String? {
        h?.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
    }

    static func entry(_ d: HTTPRequestDetail) -> [String: Any] {
        var comments: [String] = []
        let comps = URLComponents(string: d.url)
        let query = (comps?.queryItems ?? []).map { ["name": $0.name, "value": $0.value ?? ""] }
        var request: [String: Any] = [
            "method": d.method, "url": d.url, "httpVersion": "HTTP/1.1",
            "cookies": [Any](), "headers": headers(d.reqHeaders), "queryString": query,
            "headersSize": -1, "bodySize": d.reqBodyLength ?? (d.reqBody?.utf8.count ?? 0),
        ]
        if let b = d.reqBody, !b.isEmpty {
            request["postData"] = ["mimeType": header(d.reqHeaders, "Content-Type") ?? "", "text": b]
            if let full = d.reqBodyLength, full > b.utf8.count { comments.append("request body truncated to \(b.utf8.count) of \(full) bytes") }
        } else if let bin = d.reqBodyBinary, bin > 0 {
            request["postData"] = ["mimeType": header(d.reqHeaders, "Content-Type") ?? "application/octet-stream", "text": ""]
            comments.append("binary request body (\(bin) bytes) not captured")
        }
        var content: [String: Any] = [
            "size": d.respBodyLength ?? Int(d.bytes),
            "mimeType": header(d.respHeaders, "Content-Type") ?? "",
        ]
        if let b = d.respBody, !b.isEmpty {
            content["text"] = b
            if let full = d.respBodyLength, full > b.utf8.count { comments.append("response body truncated to \(b.utf8.count) of \(full) bytes") }
        } else if let bin = d.respBodyBinary, bin > 0 {
            comments.append("binary response body (\(bin) bytes\(d.respEncoding.map { ", " + $0 } ?? "")) not captured")
        }
        let response: [String: Any] = [
            "status": d.status, "statusText": HTTPURLResponse.localizedString(forStatusCode: d.status).capitalized,
            "httpVersion": "HTTP/1.1", "cookies": [Any](), "headers": headers(d.respHeaders),
            "content": content, "redirectURL": header(d.respHeaders, "Location") ?? "",
            "headersSize": -1, "bodySize": Int(d.bytes),
        ]
        let total = max(d.duration ?? 0, 0)
        if let m = d.matched, !m.isEmpty { comments.append("matched: " + m.joined(separator: "; ")) }
        if let n = d.notes, !n.isEmpty { comments.append(contentsOf: n) }
        if d.local == true { comments.append("answered locally by the engine") }
        var e: [String: Any] = [
            "startedDateTime": iso(d.time), "time": total,
            "request": request, "response": response, "cache": [String: Any](),
            "timings": ["send": 0, "wait": total, "receive": 0],
        ]
        if !comments.isEmpty { e["comment"] = comments.joined(separator: " · ") }
        return e
    }

    static func document(_ details: [HTTPRequestDetail]) throws -> Data {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        let entries = details.filter { $0.method != "TLS" }.sorted { $0.time < $1.time }.map(entry)
        let har: [String: Any] = ["log": [
            "version": "1.2",
            "creator": ["name": "Mihomo iOS", "version": version],
            "pages": [Any](),
            "entries": entries,
        ]]
        return try JSONSerialization.data(withJSONObject: har, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    }

    /// Fetches every listed request's detail from the controller and writes a .har file.
    /// progress(done, total) is called on the main actor.
    @MainActor
    static func export(ids: [Int64], progress: @escaping (Int, Int) -> Void) async throws -> URL {
        var details: [HTTPRequestDetail] = []
        for (i, id) in ids.enumerated() {
            if Task.isCancelled { break }
            if let d = try? await ControllerClient.shared.mitmRequest(id) { details.append(d) }
            progress(i + 1, ids.count)
        }
        let data = try document(details)
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Mihomo-\(f.string(from: Date())).har")
        try data.write(to: url, options: .atomic)
        return url
    }
}
