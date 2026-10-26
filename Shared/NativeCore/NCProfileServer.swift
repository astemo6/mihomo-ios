import Foundation
import Network

/// Lightweight loopback HTTP server to serve the MitM CA configuration profile to Safari.
/// Replaces Go's `CAServeProfile` (`bridge/engine.go`).
/// Serves `/ca.mobileconfig`, `/ca.cer`, and `/` for ~3 minutes on `127.0.0.1:<ephemeral-port>`.
public final class NCCAProfileServer {
    public static let shared = NCCAProfileServer()

    private let lock = NSLock()
    private var listener: NWListener?
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "com.astemo6.tern.ca-profile-server")

    public init() {}

    public func start(home: String) throws -> Int {
        lock.lock()
        defer { lock.unlock() }

        stopLocked()

        guard let mcData = NCCAManager.mobileConfig(home: home),
              let cerData = NCCAManager.caCertDER(home: home) else {
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "请先生成 CA 证书"])
        }

        let htmlString = """
        <!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><title>安装 Tern CA</title>
        <body style="font-family:-apple-system;padding:24px;background:#0a0b10;color:#eee">
        <h2>安装 Tern MitM 证书</h2><p><a style="color:#4ac7f5;font-size:20px" href="/ca.mobileconfig">点此下载描述文件</a></p>
        <ol><li>点「允许」下载描述文件</li><li>打开 设置 → 已下载描述文件 → 安装</li><li>设置 → 通用 → 关于本机 → 证书信任设置 → 打开该证书的完全信任</li></ol></body>
        """
        let htmlData = Data(htmlString.utf8)

        let tcpOpts = NWProtocolTCP.Options()
        let params = NWParameters(tls: nil, tcp: tcpOpts)
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        params.allowLocalEndpointReuse = true

        let listener = try NWListener(using: params)
        let ready = DispatchSemaphore(value: 0)
        var boundPort: UInt16 = 0

        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                boundPort = listener.port?.rawValue ?? 0
                ready.signal()
            case .failed, .cancelled:
                ready.signal()
                self?.stop()
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn, mcData: mcData, cerData: cerData, htmlData: htmlData)
        }

        listener.start(queue: queue)

        guard ready.wait(timeout: .now() + 1.0) == .success, boundPort != 0 else {
            listener.cancel()
            throw NSError(domain: "TernCA", code: -1, userInfo: [NSLocalizedDescriptionKey: "无法启动描述文件下载服务"])
        }

        self.listener = listener

        // Auto-stop after 3 minutes (matching Go)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 180.0)
        timer.setEventHandler { [weak self] in
            self?.stop()
        }
        timer.resume()
        self.timer = timer

        return Int(boundPort)
    }

    public func stop() {
        lock.lock()
        defer { lock.unlock() }
        stopLocked()
    }

    private func stopLocked() {
        timer?.cancel()
        timer = nil
        listener?.cancel()
        listener = nil
    }

    private func handleConnection(_ conn: NWConnection, mcData: Data, cerData: Data, htmlData: Data) {
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, err in
                    guard let data, !data.isEmpty,
                          let req = String(data: data, encoding: .utf8) else {
                        conn.cancel()
                        return
                    }
                    let line = req.components(separatedBy: "\r\n").first ?? ""
                    let parts = line.split(separator: " ")
                    let path = parts.count > 1 ? String(parts[1]) : "/"

                    let response: Data
                    if path.starts(with: "/ca.mobileconfig") {
                        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/x-apple-aspen-config\r\nContent-Disposition: attachment; filename=\"Tern-CA.mobileconfig\"\r\nContent-Length: \(mcData.count)\r\nConnection: close\r\n\r\n"
                        response = Data(header.utf8) + mcData
                    } else if path.starts(with: "/ca.cer") {
                        let header = "HTTP/1.1 200 OK\r\nContent-Type: application/x-x509-ca-cert\r\nContent-Length: \(cerData.count)\r\nConnection: close\r\n\r\n"
                        response = Data(header.utf8) + cerData
                    } else {
                        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(htmlData.count)\r\nConnection: close\r\n\r\n"
                        response = Data(header.utf8) + htmlData
                    }

                    conn.send(content: response, completion: .contentProcessed { _ in
                        conn.cancel()
                    })
                }
            case .failed, .cancelled:
                conn.cancel()
            default:
                break
            }
        }
        conn.start(queue: queue)
    }
}
