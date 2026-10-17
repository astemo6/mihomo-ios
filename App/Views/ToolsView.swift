import SwiftUI
import Network

// 网络工具: HTTP ping, TCP connect and DNS lookup. While connected they run inside the core
// (/tools/http, /tools/tcp, /dns/query) so results follow the rules and show the policy chain;
// while disconnected they run directly from the app.

struct ProbeResult: Decodable, Identifiable, Hashable {
    var id: Int { seq }
    var seq: Int
    var ok: Bool
    var ms: Double
    var error: String?
    var chain: String?
    var rule: String?
    var status: Int?
    var remote: String?
    var rulePayload: String?
}

struct DNSAnswerLine: Identifiable, Hashable {
    let id = UUID()
    var type: String
    var data: String
    var ttl: Int?
}

@MainActor
final class ToolsModel: ObservableObject {
    @Published var running = false
    @Published var probes: [ProbeResult] = []
    @Published var answers: [DNSAnswerLine] = []
    @Published var error: String?
    @Published var via = ""

    func clear() { probes = []; answers = []; error = nil; via = "" }

    // MARK: HTTP ping

    func httpPing(_ raw: String, count: Int = 4) async {
        clear()
        var target = raw.trimmingCharacters(in: .whitespaces)
        if !target.contains("://") { target = "https://" + target }
        guard URL(string: target) != nil else { error = "地址无效"; return }
        running = true
        defer { running = false }
        if VPNManager.shared.isConnected {
            via = "经过内核规则"
            do {
                probes = try await ControllerClient.shared.get([ProbeResult].self, "/tools/http", query: [
                    URLQueryItem(name: "url", value: target), URLQueryItem(name: "count", value: String(count)),
                ], timeout: 90)
            } catch { self.error = error.localizedDescription }
            return
        }
        via = "本机直连（未连接）"
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = 8
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.httpMaximumConnectionsPerHost = 1
        for i in 1...count {
            let session = URLSession(configuration: cfg)
            guard let targetURL = URL(string: target) else {
                probes.append(ProbeResult(seq: i, ok: false, ms: 0, error: String(localized: "地址无效")))
                session.invalidateAndCancel()
                break
            }
            var req = URLRequest(url: targetURL)
            req.httpMethod = "HEAD"
            let t0 = Date()
            do {
                let (_, resp) = try await session.data(for: req)
                let ms = Date().timeIntervalSince(t0) * 1000
                probes.append(ProbeResult(seq: i, ok: true, ms: ms, status: (resp as? HTTPURLResponse)?.statusCode))
            } catch {
                probes.append(ProbeResult(seq: i, ok: false, ms: Date().timeIntervalSince(t0) * 1000, error: error.localizedDescription))
            }
            session.invalidateAndCancel()
            if i < count { try? await Task.sleep(nanoseconds: 300_000_000) }
        }
    }

    // MARK: TCP

    func tcp(host: String, port: String, tls: Bool, count: Int = 4) async {
        clear()
        let h = host.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty, let p = UInt16(port) else { error = "请输入主机和端口"; return }
        running = true
        defer { running = false }
        if VPNManager.shared.isConnected {
            via = "经过内核规则"
            do {
                probes = try await ControllerClient.shared.get([ProbeResult].self, "/tools/tcp", query: [
                    URLQueryItem(name: "host", value: h), URLQueryItem(name: "port", value: String(p)),
                    URLQueryItem(name: "count", value: String(count)), URLQueryItem(name: "tls", value: tls ? "1" : "0"),
                ], timeout: 90)
            } catch { self.error = error.localizedDescription }
            return
        }
        via = "本机直连（未连接）"
        for i in 1...count {
            let (ok, ms, err) = await Self.directConnect(host: h, port: p, tls: tls)
            probes.append(ProbeResult(seq: i, ok: ok, ms: ms, error: err))
            if i < count { try? await Task.sleep(nanoseconds: 300_000_000) }
        }
    }

    nonisolated static func directConnect(host: String, port: UInt16, tls: Bool) async -> (Bool, Double, String?) {
        await withCheckedContinuation { (c: CheckedContinuation<(Bool, Double, String?), Never>) in
            let params: NWParameters = tls ? .tls : .tcp
            guard let nwPort = NWEndpoint.Port(rawValue: port) else {
                c.resume(returning: (false, 0, String(localized: "端口无效")))
                return
            }
            let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
            let t0 = Date()
            let lock = NSLock()
            var done = false
            func finish(_ ok: Bool, _ err: String?) {
                lock.lock()
                if done { lock.unlock(); return }
                done = true
                lock.unlock()
                conn.cancel()
                c.resume(returning: (ok, Date().timeIntervalSince(t0) * 1000, err))
            }
            conn.stateUpdateHandler = { st in
                switch st {
                case .ready: finish(true, nil)
                case .failed(let e): finish(false, e.localizedDescription)
                case .waiting(let e): finish(false, e.localizedDescription)
                default: break
                }
            }
            conn.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + 6) { finish(false, "超时") }
        }
    }

    // MARK: DNS

    func dns(_ name: String, type: String) async {
        clear()
        let n = name.trimmingCharacters(in: .whitespaces)
        guard !n.isEmpty else { return }
        running = true
        defer { running = false }
        let t0 = Date()
        if VPNManager.shared.isConnected {
            via = "内核 DNS"
            do {
                let data = try await ControllerClient.shared.send("/dns/query", query: [
                    URLQueryItem(name: "name", value: n), URLQueryItem(name: "type", value: type),
                ], timeout: 15)
                let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
                let list = obj["Answer"] as? [[String: Any]] ?? []
                answers = list.map { a in
                    DNSAnswerLine(type: Self.rrType(a["type"]), data: a["data"] as? String ?? "", ttl: (a["TTL"] as? NSNumber)?.intValue)
                }
                if answers.isEmpty { error = "没有记录（状态 \((obj["Status"] as? NSNumber)?.intValue ?? -1)）" }
            } catch { self.error = error.localizedDescription }
        } else {
            via = "系统解析（未连接）"
            let res = await Task.detached { Self.systemResolve(n, ipv6: type == "AAAA") }.value
            switch res {
            case .success(let ips): answers = ips.map { DNSAnswerLine(type: $0.contains(":") ? "AAAA" : "A", data: $0, ttl: nil) }
            case .failure(let e): error = e.localizedDescription
            }
            if answers.isEmpty && error == nil { error = "没有记录" }
        }
        via += String(format: " · %.0f ms", Date().timeIntervalSince(t0) * 1000)
    }

    nonisolated static func rrType(_ v: Any?) -> String {
        switch (v as? NSNumber)?.intValue ?? 0 {
        case 1: return "A"
        case 5: return "CNAME"
        case 28: return "AAAA"
        case 65: return "HTTPS"
        case 16: return "TXT"
        case 15: return "MX"
        default: return "\((v as? NSNumber)?.intValue ?? 0)"
        }
    }

    nonisolated static func systemResolve(_ host: String, ipv6: Bool) -> Result<[String], Error> {
        var hints = addrinfo()
        hints.ai_family = ipv6 ? AF_INET6 : AF_INET
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, nil, &hints, &res)
        guard rc == 0, let first = res else {
            let msg = String(cString: gai_strerror(rc))
            return .failure(NSError(domain: "DNS", code: Int(rc), userInfo: [NSLocalizedDescriptionKey: msg]))
        }
        defer { freeaddrinfo(first) }
        var out: [String] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                let s = String(cString: buf)
                if !out.contains(s) { out.append(s) }
            }
            p = ai.pointee.ai_next
        }
        return .success(out)
    }
}

struct ToolsView: View {
    @EnvironmentObject var vpn: VPNManager
    @StateObject private var model = ToolsModel()
    @State private var tool = 0
    @State private var url = "www.google.com"
    @State private var host = "www.google.com"
    @State private var port = "443"
    @State private var tls = false
    @State private var domain = "www.apple.com"
    @State private var rrType = "A"

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                Picker("", selection: $tool) {
                    Text("Ping").tag(0)
                    Text("TCP").tag(1)
                    Text("DNS").tag(2)
                }
                .pickerStyle(.segmented)
                .onChange(of: tool) { _ in model.clear() }

                Card {
                    VStack(alignment: .leading, spacing: 12) {
                        switch tool {
                        case 0:
                            field("网址", text: $url, keyboard: .URL)
                            Text("HTTP(S) 往返时间（到收到响应头）").font(.caption2).foregroundStyle(.secondary)
                        case 1:
                            field("主机", text: $host, keyboard: .URL)
                            HStack {
                                field("端口", text: $port, keyboard: .numberPad).frame(minWidth: 80, maxWidth: 110)
                                Toggle(isOn: $tls) {
                                    Text("TLS 握手").lineLimit(2).minimumScaleFactor(0.8)
                                }
                                .tint(Theme.accent)
                            }
                        default:
                            field("域名", text: $domain, keyboard: .URL)
                            Picker("类型", selection: $rrType) {
                                Text("A").tag("A")
                                Text("AAAA").tag("AAAA")
                            }
                            .pickerStyle(.segmented)
                        }
                        Button {
                            Task {
                                switch tool {
                                case 0: await model.httpPing(url)
                                case 1: await model.tcp(host: host, port: port, tls: tls)
                                default: await model.dns(domain, type: rrType)
                                }
                            }
                        } label: {
                            HStack {
                                Spacer()
                                if model.running { ProgressView().tint(Theme.onAccent) } else { Text("开始").bold() }
                                Spacer()
                            }
                            .padding(.vertical, 10)
                            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.accent.opacity(model.running ? 0.4 : 0.9)))
                            .foregroundStyle(Theme.onAccent)
                        }
                        .buttonStyle(.plain)
                        .disabled(model.running)
                    }
                }

                if !model.via.isEmpty || model.error != nil { resultCard }
            }
            .padding(16)
        }
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("网络工具")
    }

    func field(_ title: String, text: Binding<String>, keyboard: UIKeyboardType) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
            TextField(LocalizedStringKey(title), text: text)
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .font(.system(.body, design: .monospaced))
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
        }
    }

    static func routeText(chain: String, rule: String?, payload: String?) -> String {
        var s = chain
        if let r = rule, !r.isEmpty { s += " · " + r }
        if let p = payload, !p.isEmpty { s += "(" + p + ")" }
        return s
    }

    var summary: String? {
        let ok = model.probes.filter(\.ok)
        guard !model.probes.isEmpty else { return nil }
        let loss = Double(model.probes.count - ok.count) / Double(model.probes.count) * 100
        guard !ok.isEmpty else { return String(localized: "全部失败 · 丢失 100%") }
        let ms = ok.map(\.ms)
        return String(format: "最小 %.0f / 平均 %.0f / 最大 %.0f ms · 丢失 %.0f%%", ms.min() ?? 0, ms.reduce(0, +) / Double(ms.count), ms.max() ?? 0, loss)
    }

    var resultCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("结果").font(.headline)
                    Spacer()
                    Text(model.via).font(.caption2).foregroundStyle(.secondary)
                }
                if let e = model.error { Label(e, systemImage: "xmark.octagon.fill").font(.footnote).foregroundStyle(Theme.bad) }
                if let s = summary { Text(s).font(.caption.monospacedDigit()).foregroundStyle(Theme.accent) }
                ForEach(model.probes) { p in
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text("#\(p.seq)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            Image(systemName: p.ok ? "checkmark.circle.fill" : "xmark.circle.fill").foregroundStyle(p.ok ? Theme.good : Theme.bad)
                            if let st = p.status, st > 0 { Text("HTTP \(st)").font(.caption2) }
                            Spacer()
                            Text(String(format: "%.0f ms", p.ms)).font(.caption.monospacedDigit().weight(.semibold))
                                .foregroundStyle(p.ok ? Theme.delayColor(Int(p.ms)) : .secondary)
                        }
                        if let e = p.error, !e.isEmpty { Text(e).font(.caption2).foregroundStyle(Theme.bad).lineLimit(3) }
                        if let c = p.chain, !c.isEmpty {
                            Text(Self.routeText(chain: c, rule: p.rule, payload: p.rulePayload))
                                .font(.caption2).foregroundStyle(.secondary).lineLimit(2)
                        }
                        if let r = p.remote, !r.isEmpty { Text(r).scaledFont(10, design: .monospaced).foregroundStyle(.secondary) }
                    }
                    .padding(.vertical, 2)
                }
                ForEach(model.answers) { a in
                    HStack {
                        Text(a.type).scaledFont(10, weight: .bold)
                            .padding(.horizontal, 5).padding(.vertical, 2)
                            .background(Capsule().fill(Theme.accent.opacity(0.18))).foregroundStyle(Theme.accent)
                        Text(a.data).font(.system(.footnote, design: .monospaced)).textSelection(.enabled)
                        Spacer()
                        if let t = a.ttl { Text("TTL \(t)").font(.caption2).foregroundStyle(.secondary) }
                    }
                }
            }
        }
    }
}
