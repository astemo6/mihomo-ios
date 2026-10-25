import CryptoKit
import Foundation
import Network

/// A mihomo external-controller lookalike served by the native core, so the
/// App's Dashboard / groups / connections pages keep working while the Go core
/// is off: /version, /proxies (+ PUT/DELETE selection, delay tests),
/// /group/{name}/delay, /connections, /traffic, /app/traffic, /configs, /rules.
/// Anything else answers 404 — features that live in the Go engine (MitM,
/// providers) degrade in the App exactly like a stopped core would.
final class NCController {
    private let engine: NativeCoreEngine
    private let plane: NCDataPlane
    private let port: UInt16
    private let secret: String
    private let queue = DispatchQueue(label: "nc.controller", qos: .userInitiated)
    private var listener: NWListener?
    private var streamTimers: [ObjectIdentifier: DispatchSourceTimer] = [:]

    init(engine: NativeCoreEngine, plane: NCDataPlane, port: Int, secret: String) {
        self.engine = engine
        self.plane = plane
        self.port = UInt16(clamping: port)
        self.secret = secret
    }

    func start() {
        let params = NWParameters.tcp
        params.requiredInterfaceType = .loopback
        guard let listener = try? NWListener(using: params, on: NWEndpoint.Port(rawValue: port) ?? .any) else { return }
        listener.newConnectionHandler = { [weak self] conn in
            self?.handle(conn)
        }
        listener.start(queue: queue)
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
        for t in streamTimers.values { t.cancel() }
        streamTimers.removeAll()
    }

    // MARK: Connection handling

    private final class Request {
        var method = ""
        var path = ""
        var query: [String: String] = [:]
        var headers: [String: String] = [:]
        var body = Data()
    }

    private func handle(_ conn: NWConnection) {
        conn.start(queue: queue)
        receiveRequest(conn, buffer: Data())
    }

    private func receiveRequest(_ conn: NWConnection, buffer: Data) {
        var buffer = buffer
        conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data { buffer.append(data) }
            if let req = Self.parse(buffer) {
                self.route(conn, req)
                return
            }
            if error != nil || isComplete || buffer.count > 65536 {
                conn.cancel()
                return
            }
            self.receiveRequest(conn, buffer: buffer)
        }
    }

    /// Returns the parsed request once headers (+ body per Content-Length) are in.
    private static func parse(_ data: Data) -> Request? {
        guard let headEnd = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[data.startIndex..<headEnd.lowerBound], as: UTF8.self)
        let lines = head.components(separatedBy: "\r\n")
        guard let first = lines.first else { return nil }
        let parts = first.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        let req = Request()
        req.method = String(parts[0])
        let target = String(parts[1])
        if let q = target.firstIndex(of: "?") {
            req.path = String(target[target.startIndex..<q])
            for pair in target[target.index(after: q)...].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2 {
                    req.query[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
                }
            }
        } else {
            req.path = target
        }
        req.path = req.path.removingPercentEncoding ?? req.path
        for line in lines.dropFirst() {
            if let colon = line.firstIndex(of: ":") {
                req.headers[line[line.startIndex..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        let bodyLen = Int(req.headers["content-length"] ?? "0") ?? 0
        let bodyStart = headEnd.upperBound
        guard data.count - bodyStart >= bodyLen else { return nil }
        req.body = Data(data[bodyStart..<(bodyStart + bodyLen)])
        return req
    }

    // MARK: Routing

    private func route(_ conn: NWConnection, _ req: Request) {
        // The app's websocket streams pass the secret as ?token= (mihomo accepts both).
        if !secret.isEmpty, req.headers["authorization"] != "Bearer \(secret)", req.query["token"] != secret {
            respond(conn, status: 401, json: ["message": "Unauthorized"])
            return
        }
        let path = req.path
        if req.headers["upgrade"]?.lowercased() == "websocket", let key = req.headers["sec-websocket-key"] {
            switch path {
            case "/traffic", "/memory", "/connections", "/logs":
                streamWebSocket(conn, key: key, path: path)
            default:
                respond(conn, status: 404, json: ["message": "not available in native core"])
            }
            return
        }
        switch (req.method, path) {
        case ("GET", "/providers/proxies"), ("GET", "/providers/rules"):
            // Providers are folded into the config by the app / the rule-provider store; nothing to list yet.
            respond(conn, status: 200, json: ["providers": [String: Any]()])
        case ("GET", "/version"):
            respond(conn, status: 200, json: ["version": "native-1.0.0", "meta": true])
        case ("GET", "/proxies"):
            respond(conn, status: 200, json: ["proxies": proxiesJSON()])
        case ("GET", "/smart"):
            // 智能选择 status, same shape as the Go core's route (bridge/smart.go).
            respond(conn, status: 200, json: engine.smartStatusJSON())
        case ("GET", "/connections"):
            let snap = plane.stats.snapshot()
            respond(conn, status: 200, json: [
                "downloadTotal": snap.down,
                "uploadTotal": snap.up,
                "connections": snap.connections,
            ])
        case ("DELETE", "/connections"):
            plane.requestCloseAllConnections()
            respond(conn, status: 204, json: nil)
        case ("GET", "/configs"):
            respond(conn, status: 200, json: ["mode": engine.effectiveMode])
        case ("PATCH", "/configs"):
            if let obj = try? JSONSerialization.jsonObject(with: req.body) as? [String: Any],
               let mode = obj["mode"] as? String {
                engine.modeOverride = mode
            }
            respond(conn, status: 204, json: nil)
        case ("GET", "/rules"):
            respond(conn, status: 200, json: ["rules": rulesJSON()])
        case ("GET", "/traffic"):
            streamTraffic(conn)
        case ("GET", "/app/traffic"):
            respond(conn, status: 200, json: appTrafficJSON())
        // gap C4 (astemo6/Muse NativeCore): MitM request log + log history from NativeCore's own stores
        case ("GET", "/mitm/requests"):
            respondEncodable(conn, NativeRequestLogStore.shared.summaries(since: Int64(req.query["since"] ?? "") ?? 0))
        case ("DELETE", "/mitm/requests"):
            NativeRequestLogStore.shared.clear()
            respond(conn, status: 204, json: nil)
        case ("GET", "/mitm/hosts"):
            respond(conn, status: 200, json: NativeRequestLogStore.shared.hosts())
        case ("GET", "/mitm/logs"):
            let since = Int64(req.query["since"] ?? "") ?? 0
            let lines: [[String: Any]] = NativeLogRing.shared.scriptLines(since: since).map {
                ["id": $0.id, "time": $0.time, "script": $0.script, "level": $0.level, "msg": $0.msg]
            }
            respond(conn, status: 200, json: lines)
        case ("DELETE", "/mitm/logs"):
            NativeLogRing.shared.clearScripts()
            respond(conn, status: 204, json: nil)
        case ("GET", "/hark/logs"):
            let (seq, lines) = NativeLogRing.shared.since(UInt64(req.query["since"] ?? "") ?? 0)
            let kind = req.query["kind"] ?? "general"
            let picked = kind == "dns" ? lines.filter { $0.payload.hasPrefix("[DNS]") } : lines
            let logs: [[String: Any]] = picked.map {
                ["seq": $0.seq, "time": $0.time, "type": $0.type, "payload": $0.payload]
            }
            respond(conn, status: 200, json: ["seq": seq, "logs": logs] as [String: Any])
        // gap C3: task scripts and panels (NativeTaskRunner)
        case ("GET", "/mitm/tasks"):
            respond(conn, status: 200, json: NativeTaskRunner.shared.listJSON())
        case ("PUT", "/mitm/tasks-prefs"):
            NativeTaskRunner.shared.setPrefs(req.body)
            respond(conn, status: 204, json: nil)
        case ("GET", "/mitm/panels"):
            respond(conn, status: 200, json: NativeTaskRunner.shared.panelsJSON(markViewed: true))
        case ("PUT", "/mitm/panels-home"):
            if NativeTaskRunner.shared.setHome(req.body) {
                respond(conn, status: 200, json: NativeTaskRunner.shared.panelsJSON(markViewed: false))
            } else {
                respond(conn, status: 400, json: ["message": "invalid body"])
            }
        case ("DELETE", "/hark/logs"):
            NativeLogRing.shared.clearGeneral()
            respond(conn, status: 204, json: nil)
        default:
            routeParameterized(conn, req)
        }
    }

    private func routeParameterized(_ conn: NWConnection, _ req: Request) {
        let comps = req.path.split(separator: "/").map(String.init)
        // /proxies/{name} PUT|DELETE, /proxies/{name}/delay GET
        if comps.count >= 2, comps[0] == "proxies" {
            let name = comps[1]
            if comps.count == 2, req.method == "PUT" {
                if let obj = try? JSONSerialization.jsonObject(with: req.body) as? [String: Any],
                   let member = obj["name"] as? String {
                    engine.setSelection(group: name, member: member)
                }
                respond(conn, status: 204, json: nil)
                return
            }
            if comps.count == 2, req.method == "DELETE" {
                engine.setSelection(group: name, member: nil)
                respond(conn, status: 204, json: nil)
                return
            }
            if comps.count == 3, comps[2] == "delay", req.method == "GET" {
                let url = req.query["url"] ?? "http://www.gstatic.com/generate_204"
                let timeout = Int(req.query["timeout"] ?? "5000") ?? 5000
                measureDelay(name: name, url: url, timeoutMs: timeout) { [weak self] ms in
                    guard let self else { return }
                    if let ms {
                        self.engine.recordDelay(name: name, ms: ms)
                        self.respond(conn, status: 200, json: ["delay": ms])
                    } else {
                        self.respond(conn, status: 503, json: ["message": "Timeout"])
                    }
                }
                return
            }
        }
        // /group/{name}/delay
        if comps.count == 3, comps[0] == "group", comps[2] == "delay", req.method == "GET" {
            let name = comps[1]
            guard let group = engine.effectiveConfig?.groupMap[name] else {
                respond(conn, status: 404, json: ["message": "group not found"])
                return
            }
            let url = req.query["url"] ?? "http://www.gstatic.com/generate_204"
            let timeout = Int(req.query["timeout"] ?? "5000") ?? 5000
            measureGroupDelay(members: group.proxies, url: url, timeoutMs: timeout) { [weak self] results in
                guard let self else { return }
                for (n, ms) in results { self.engine.recordDelay(name: n, ms: ms) }
                if results.isEmpty {
                    self.respond(conn, status: 504, json: ["message": "all timed out"])
                } else {
                    self.respond(conn, status: 200, json: results)
                }
            }
            return
        }
        // /mitm/tasks/{id}/run POST, /mitm/tasks/{id}/history GET, /mitm/panels/{id}/refresh POST (gap C3) — script
        // runs block, so they answer from a background queue
        if comps.count == 4, comps[0] == "mitm", comps[1] == "tasks", comps[3] == "run", req.method == "POST" {
            let id = comps[2]
            let params = ((try? JSONSerialization.jsonObject(with: req.body)) as? [String: Any])?["params"] as? String
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let r = NativeTaskRunner.shared.run(id: id, params: params)
                var o: [String: Any] = ["ok": r.ok]
                if let e = r.error { o["error"] = e }
                if let v = r.result as? [String: Any], JSONSerialization.isValidJSONObject(v) { o["result"] = v }
                self?.queue.async { self?.respond(conn, status: 200, json: o) }
            }
            return
        }
        if comps.count == 4, comps[0] == "mitm", comps[1] == "tasks", comps[3] == "history", req.method == "GET" {
            respondRaw(conn, NativeTaskRunner.shared.history(id: comps[2]))
            return
        }
        if comps.count == 4, comps[0] == "mitm", comps[1] == "panels", comps[3] == "refresh", req.method == "POST" {
            let id = comps[2]
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let p = NativeTaskRunner.shared.refreshPanel(id)
                self?.queue.async {
                    if let p { self?.respond(conn, status: 200, json: p) } else { self?.respond(conn, status: 404, json: ["message": "面板不存在"]) }
                }
            }
            return
        }
        // /mitm/requests/{id} GET (gap C4)
        if comps.count == 3, comps[0] == "mitm", comps[1] == "requests", req.method == "GET", let id = Int64(comps[2]) {
            if let e = NativeRequestLogStore.shared.detail(id: id) {
                respondEncodable(conn, e)
            } else {
                respond(conn, status: 404, json: ["message": "request not found"])
            }
            return
        }
        // /connections/{id} DELETE
        if comps.count == 2, comps[0] == "connections", req.method == "DELETE" {
            plane.requestCloseConnection(id: comps[1])
            respond(conn, status: 204, json: nil)
            return
        }
        respond(conn, status: 404, json: ["message": "not available in native core"])
    }

    // MARK: Payload builders

    private func proxiesJSON() -> [String: Any] {
        // Gap D3: built under the engine lock (the data plane mutates the group engine while it routes).
        engine.withGroups { cfg, groups in Self.proxiesJSON(cfg: cfg, groups: groups) } ?? [:]
    }

    private static func proxiesJSON(cfg: NCConfig, groups: NCGroupEngine) -> [String: Any] {
        let snapshot = groups.statusSnapshot()
        var out: [String: Any] = [:]
        let now = ISO8601DateFormatter().string(from: Date())
        for p in cfg.proxies {
            var item: [String: Any] = [
                "name": p.name,
                "type": Self.displayType(p.type),
                "udp": p.udp,
                "alive": snapshot.alive[p.name] ?? true,
            ]
            if let d = snapshot.delays[p.name] {
                item["history"] = [["time": now, "delay": d]]
            } else {
                item["history"] = [Any]()
            }
            out[p.name] = item
        }
        for g in cfg.groups {
            out[g.name] = [
                "name": g.name,
                "type": Self.displayGroupType(g.type),
                "now": groups.currentMember(of: g) ?? "",
                "all": g.proxies,
                "udp": true,
                "alive": true,
                "history": [Any](),
                "fixed": snapshot.selections[g.name] ?? "",
            ]
        }
        out["DIRECT"] = ["name": "DIRECT", "type": "Direct", "udp": true, "alive": true, "history": [Any]()]
        out["REJECT"] = ["name": "REJECT", "type": "Reject", "udp": true, "alive": true, "history": [Any]()]
        return out
    }

    private func rulesJSON() -> [[String: Any]] {
        guard let cfg = engine.config else { return [] }
        return cfg.rules.compactMap(NCRule.parse).enumerated().map { idx, rule in
            [
                "index": idx,
                "type": rule.kind,
                "payload": rule.payload,
                "proxy": rule.policy,
                "size": -1,
            ]
        }
    }

    private static func displayType(_ t: String) -> String {
        switch t.lowercased() {
        case "ss": return "Shadowsocks"
        case "vmess": return "VMess"
        case "vless": return "VLESS"
        case "trojan": return "Trojan"
        case "socks5": return "Socks5"
        case "http": return "Http"
        case "https": return "Https"
        case "direct": return "Direct"
        default: return t
        }
    }

    private static func displayGroupType(_ t: String) -> String {
        switch t.lowercased() {
        case "select": return "Selector"
        case "url-test": return "URLTest"
        case "fallback": return "Fallback"
        case "load-balance": return "LoadBalance"
        case "relay": return "Relay"
        default: return t
        }
    }

    // MARK: Traffic streaming + app traffic

    private var appTrafficLast: (up: Int64, down: Int64, proxyUp: Int64, proxyDown: Int64, at: Date)?

    private func appTrafficJSON() -> [String: Any] {
        let snap = plane.stats.snapshot()
        let now = Date()
        var rates: (up: Int64, down: Int64, pUp: Int64, pDown: Int64) = (0, 0, 0, 0)
        if let last = appTrafficLast {
            let dt = max(now.timeIntervalSince(last.at), 0.2)
            rates = (Int64(Double(snap.up - last.up) / dt), Int64(Double(snap.down - last.down) / dt),
                     Int64(Double(snap.proxyUp - last.proxyUp) / dt), Int64(Double(snap.proxyDown - last.proxyDown) / dt))
        }
        appTrafficLast = (snap.up, snap.down, snap.proxyUp, snap.proxyDown, now)
        return [
            "up": rates.up, "down": rates.down,
            "upTotal": snap.up, "downTotal": snap.down,
            "proxyUp": rates.pUp, "proxyDown": rates.pDown,
            "proxyUpTotal": snap.proxyUp, "proxyDownTotal": snap.proxyDown,
        ]
    }

    /// RFC 6455 server side, text frames only (the app's ControllerClient.stream): one frame a second.
    private func streamWebSocket(_ conn: NWConnection, key: String, path: String) {
        let accept = Data(Insecure.SHA1.hash(data: Data((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").utf8))).base64EncodedString()
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \(accept)\r\n\r\n"
        conn.send(content: Data(head.utf8), completion: .idempotent)
        var last = plane.stats.snapshot()
        // gap C4: /logs streams NativeLogRing lines (from the moment of attaching; history is /hark/logs)
        var logSeq = NativeLogRing.shared.since(UInt64.max).seq
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: path == "/logs" ? 0.5 : 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if path == "/logs" {
                let (seq, lines) = NativeLogRing.shared.since(logSeq)
                logSeq = seq
                for l in lines.suffix(200) {
                    if let d = try? JSONSerialization.data(withJSONObject: ["type": l.type, "payload": l.payload]) {
                        conn.send(content: Self.wsTextFrame(d), completion: .idempotent)
                    }
                }
                return
            }
            let snap = self.plane.stats.snapshot()
            var obj: Any?
            switch path {
            case "/traffic":
                obj = ["up": max(0, snap.up - last.up), "down": max(0, snap.down - last.down)]
            case "/memory":
                obj = ["inuse": Int64(ProcessMemory.footprintBytes()), "oslimit": 0]
            case "/connections":
                obj = ["downloadTotal": snap.down, "uploadTotal": snap.up, "connections": snap.connections,
                       "memory": Int64(ProcessMemory.footprintBytes())]
            default:
                obj = nil
            }
            last = snap
            if let obj, let data = try? JSONSerialization.data(withJSONObject: obj) {
                conn.send(content: Self.wsTextFrame(data), completion: .idempotent)
            }
        }
        timer.resume()
        streamTimers[ObjectIdentifier(conn)] = timer
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                self?.streamTimers.removeValue(forKey: ObjectIdentifier(conn))?.cancel()
            default:
                break
            }
        }
        // Client frames (close / ping) are read and dropped; EOF ends the stream.
        func drain() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { _, _, done, err in
                if done || err != nil { conn.cancel() } else { drain() }
            }
        }
        drain()
    }

    static func wsTextFrame(_ payload: Data) -> Data {
        var f = Data([0x81])
        let n = payload.count
        if n < 126 {
            f.append(UInt8(n))
        } else if n < 65536 {
            f.append(126); f.append(UInt8(n >> 8)); f.append(UInt8(n & 0xff))
        } else {
            f.append(127)
            for i in (0..<8).reversed() { f.append(UInt8((UInt64(n) >> (UInt64(i) * 8)) & 0xff)) }
        }
        f.append(payload)
        return f
    }

    private func streamTraffic(_ conn: NWConnection) {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        conn.send(content: Data(head.utf8), completion: .idempotent)
        var lastUp: Int64 = plane.stats.snapshot().up
        var lastDown: Int64 = plane.stats.snapshot().down
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let snap = self.plane.stats.snapshot()
            let line = "{\"up\":\(snap.up - lastUp),\"down\":\(snap.down - lastDown)}\n"
            lastUp = snap.up
            lastDown = snap.down
            let chunk = "\(String(line.count, radix: 16))\r\n\(line)\r\n"
            conn.send(content: Data(chunk.utf8), completion: .idempotent)
        }
        timer.resume()
        streamTimers[ObjectIdentifier(conn)] = timer
        conn.stateUpdateHandler = { [weak self] state in
            if case .cancelled = state {
                self?.streamTimers.removeValue(forKey: ObjectIdentifier(conn))?.cancel()
            }
        }
    }

    // MARK: Delay measurement

    /// End-to-end delay through the named node (or group's current member):
    /// open a relay to the test URL and time until the first response byte.
    private func measureDelay(name: String, url: String, timeoutMs: Int, completion: @escaping (Int?) -> Void) {
        NCTunnelDelayTester.measureDelay(groupEngine: engine.groupEngine, name: name, url: url, timeoutMs: timeoutMs, completion: completion)
    }

    private func measureGroupDelay(members: [String], url: String, timeoutMs: Int,
                                   completion: @escaping ([String: Int]) -> Void) {
        NCTunnelDelayTester.measureGroup(groupEngine: engine.groupEngine, members: members, url: url, timeoutMs: timeoutMs, queue: queue) { results in
            let successes = results.compactMapValues { $0 }
            completion(successes)
        }
    }

    // MARK: Responses

    private func respondEncodable<T: Encodable>(_ conn: NWConnection, _ value: T) {
        respondRaw(conn, (try? JSONEncoder().encode(value)) ?? Data("null".utf8))
    }

    private func respondRaw(_ conn: NWConnection, _ body: Data) {
        var out = Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n".utf8)
        out.append(body)
        conn.send(content: out, completion: .contentProcessed { _ in conn.cancel() })
    }

    private func respond(_ conn: NWConnection, status: Int, json: Any?) {
        var head = "HTTP/1.1 \(status) \(Self.statusText(status))\r\n"
        var bodyData = Data()
        if let json {
            bodyData = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
            head += "Content-Type: application/json\r\n"
        }
        head += "Content-Length: \(bodyData.count)\r\nConnection: close\r\n\r\n"
        var out = Data(head.utf8)
        out.append(bodyData)
        conn.send(content: out, completion: .contentProcessed { _ in conn.cancel() })
    }

    private static func statusText(_ code: Int) -> String {
        switch code {
        case 200: return "OK"
        case 204: return "No Content"
        case 401: return "Unauthorized"
        case 404: return "Not Found"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default: return "OK"
        }
    }
}
