import Foundation

/// feat/nc-lua S2: a Shadowrocket-style Lua custom backend as an
/// NCRelayStream. The session owns the raw stream to the proxy server and
/// one `NCLuaEngine`; the user's Lua script drives the wire protocol
/// through the wa_lua_on_* callbacks:
///
/// - connect: `wa_lua_on_flags_cb` must return 0. The script emits its
///   handshake bytes through `backend.write`; inbound bytes are fed to
///   `wa_lua_on_read_cb` (any plaintext it returns is buffered) until
///   `wa_lua_on_handshake_cb` reports completion.
/// - data: outbound plaintext goes through `wa_lua_on_write_cb`, inbound
///   wire bytes through `wa_lua_on_read_cb`. A callback status of
///   backend.RESULT.ERROR (or a Lua error / deadline trip) fails the
///   stream; the script only ever kills its own connection.
/// - close: `wa_lua_on_close_cb` runs best-effort.
///
/// All engine calls are confined to the connection queue. Script source
/// resolution: an inline `script` field wins; otherwise `file` names a
/// script inside the app-group container's `LuaScripts/` directory. A
/// missing script is a loud handshake failure, never a silent pass-through.
final class NCLuaSession: NCRelayStream {
    private enum Phase { case handshaking, open, closed, failed }

    private let raw: NCRelayStream
    private let engine: NCLuaEngine
    private let hostContext: NCLuaHostContext
    private let queue: DispatchQueue

    private var phase: Phase = .handshaking
    private var failure: Error?
    private var bufferedPlaintext = Data()
    private var pendingReceive: ((Data?, Error?) -> Void)?
    private var readInFlight = false
    private var handshakeSteps = 0
    private var connectCompletion: ((NCRelayStream?, Error?) -> Void)?
    private var handshakeTimeout: DispatchWorkItem?

    private init(raw: NCRelayStream, engine: NCLuaEngine, hostContext: NCLuaHostContext, queue: DispatchQueue) {
        self.raw = raw
        self.engine = engine
        self.hostContext = hostContext
        self.queue = queue
    }

    // MARK: - Connect

    static func connect(raw: NCRelayStream, proxy: NCProxy, target: NCTarget, queue: DispatchQueue,
                        completion: @escaping (NCRelayStream?, Error?) -> Void) {
        let source: String
        switch scriptSource(proxy) {
        case .failure(let error):
            queue.async { completion(nil, error) }
            return
        case .success(let text):
            source = text
        }
        var initError: String?
        guard let engine = NCLuaEngine(source: source,
                                       chunkName: proxy.fields["file"]?.string ?? proxy.name,
                                       initError: &initError) else {
            queue.async { completion(nil, NCConnector.Failure.handshake("lua: \(initError ?? "engine init failed")")) }
            return
        }
        let context = NCLuaHostContext(target: target)
        let session = NCLuaSession(raw: raw, engine: engine, hostContext: context, queue: queue)
        context.onWrite = { [weak session] data in
            // backend.write: straight onto the wire (handshake bytes during
            // setup, DIRECT_WRITE payloads afterwards).
            session?.raw.send(data)
        }
        context.onDebug = { message in
            FileHandle.standardError.write(Data("[lua] \(message)\n".utf8))
        }
        engine.attach(context: context, settings: settingsTable(proxy))
        session.connectCompletion = completion
        let timeout = DispatchWorkItem { [weak session] in session?.handshakeTimedOut() }
        session.handshakeTimeout = timeout
        queue.asyncAfter(deadline: .now() + 15, execute: timeout)
        ncOnSessionQueue(queue) { session.beginHandshake() }
    }

    static func scriptSource(_ proxy: NCProxy) -> Result<String, NCConnector.Failure> {
        if let inline = proxy.fields["script"]?.string, !inline.isEmpty {
            return .success(inline)
        }
        guard let file = proxy.fields["file"]?.string, !file.isEmpty else {
            return .failure(.handshake("lua backend '\(proxy.name)' has no script (missing file/script field)"))
        }
        // Only the basename is honored: a subscription must not be able to
        // make the tunnel read arbitrary paths.
        let base = (file as NSString).lastPathComponent
        guard !base.isEmpty,
              let container = AppShared.containerURL(forGroup: AppShared.appGroup) else {
            return .failure(.handshake("lua script '\(file)' unavailable (no app-group container)"))
        }
        let url = container.appendingPathComponent("LuaScripts").appendingPathComponent(base)
        guard let text = try? String(contentsOf: url, encoding: .utf8) else {
            return .failure(.handshake("lua script '\(file)' not found in LuaScripts/"))
        }
        return .success(text)
    }

    static func settingsTable(_ proxy: NCProxy) -> [(String, NCLuaSettingValue)] {
        var out: [(String, NCLuaSettingValue)] = []
        if let server = proxy.server { out.append(("host", .string(server))) }
        if let port = proxy.port { out.append(("port", .int(port))) }
        if let user = proxy.fields["username"]?.string { out.append(("username", .string(user))) }
        if let password = proxy.password { out.append(("password", .string(password))) }
        if let method = proxy.cipher { out.append(("method", .string(method))) }
        let named: Set<String> = ["server", "port", "username", "password", "cipher", "file", "script", "lua-status", "name", "type"]
        for (key, value) in proxy.fields where !named.contains(key) {
            switch value {
            case .string(let s): out.append((key, .string(s)))
            case .bool(let b): out.append((key, .bool(b)))
            case .number(let n) where n == n.rounded(): out.append((key, .int(Int(n))))
            default: break
            }
        }
        return out
    }

    // MARK: - Handshake state machine (on queue)

    private func beginHandshake() {
        guard phase == .handshaking else { return }
        switch engine.callFlags() {
        case .failure(let e):
            failConnect("lua on_flags: \(e)")
        case .success(let rc) where rc != 0:
            failConnect("lua on_flags returned \(rc)")
        case .success:
            attemptHandshake()
        }
    }

    private func attemptHandshake() {
        guard phase == .handshaking else { return }
        handshakeSteps += 1
        guard handshakeSteps <= 64 else {
            failConnect("lua handshake did not complete after 64 rounds")
            return
        }
        switch engine.callHandshake() {
        case .failure(let e):
            failConnect("lua on_handshake: \(e)")
        case .success(true):
            phase = .open
            handshakeTimeout?.cancel()
            let completion = connectCompletion
            connectCompletion = nil
            completion?(self, nil)
        case .success(false):
            raw.receive { [weak self] data, err in
                guard let self else { return }
                ncOnSessionQueue(self.queue) {
                    guard self.phase == .handshaking else { return }
                    guard let data, !data.isEmpty else {
                        self.failConnect("lua handshake: peer closed (\(err?.localizedDescription ?? "eof"))")
                        return
                    }
                    switch self.engine.callRead(data) {
                    case .failure(let e):
                        self.failConnect("lua on_read during handshake: \(e)")
                    case .success(let (status, out)):
                        if status == NCLuaEngine.resultError {
                            self.failConnect("lua on_read reported ERROR during handshake")
                            return
                        }
                        if let out, !out.isEmpty { self.bufferedPlaintext.append(out) }
                        self.attemptHandshake()
                    }
                }
            }
        }
    }

    private func handshakeTimedOut() {
        guard phase == .handshaking else { return }
        failConnect("lua handshake timeout (15s)")
    }

    private func failConnect(_ message: String) {
        phase = .failed
        failure = NCConnector.Failure.handshake(message)
        handshakeTimeout?.cancel()
        raw.cancel()
        let completion = connectCompletion
        connectCompletion = nil
        completion?(nil, failure)
        if let handler = pendingReceive {
            pendingReceive = nil
            handler(nil, failure)
        }
    }

    // MARK: - NCRelayStream (data phase)

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        let once = NCCallOnce(completion)
        ncOnSessionQueue(queue) {
            guard self.phase == .open else { once.call(); return }
            switch self.engine.callWrite(data) {
            case .failure(let e):
                once.call()
                self.failStream("lua on_write: \(e)")
            case .success(let (status, out)):
                if status == NCLuaEngine.resultError {
                    once.call()
                    self.failStream("lua on_write reported ERROR")
                    return
                }
                if let out, !out.isEmpty {
                    self.raw.send(out) { once.call() }
                } else {
                    once.call()
                }
            }
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        ncOnSessionQueue(queue) {
            if !self.bufferedPlaintext.isEmpty {
                let data = self.bufferedPlaintext
                self.bufferedPlaintext = Data()
                handler(data, nil)
                return
            }
            switch self.phase {
            case .failed:
                handler(nil, self.failure)
            case .closed:
                handler(nil, nil)
            case .handshaking, .open:
                self.pendingReceive = handler
                self.pumpRead()
            }
        }
    }

    private func pumpRead() {
        guard pendingReceive != nil, !readInFlight, phase == .open || phase == .handshaking else { return }
        readInFlight = true
        raw.receive { [weak self] data, err in
            guard let self else { return }
            ncOnSessionQueue(self.queue) {
                self.readInFlight = false
                guard let handler = self.pendingReceive else { return }
                guard let data, !data.isEmpty else {
                    self.pendingReceive = nil
                    if self.phase != .closed { self.phase = .closed }
                    handler(nil, err)
                    return
                }
                switch self.engine.callRead(data) {
                case .failure(let e):
                    self.pendingReceive = nil
                    self.failStream("lua on_read: \(e)")
                    handler(nil, self.failure)
                case .success(let (status, out)):
                    if status == NCLuaEngine.resultError {
                        self.pendingReceive = nil
                        self.failStream("lua on_read reported ERROR")
                        handler(nil, self.failure)
                        return
                    }
                    if let out, !out.isEmpty {
                        self.pendingReceive = nil
                        handler(out, nil)
                    } else {
                        self.pumpRead()
                    }
                }
            }
        }
    }

    private func failStream(_ message: String) {
        guard phase != .failed, phase != .closed else { return }
        phase = .failed
        failure = NCConnector.Failure.handshake(message)
        raw.cancel()
    }

    func cancel() {
        ncOnSessionQueue(queue) {
            guard self.phase != .closed else { return }
            let wasHandshaking = self.phase == .handshaking
            self.phase = .closed
            self.handshakeTimeout?.cancel()
            self.engine.callClose()
            self.raw.cancel()
            if wasHandshaking, let completion = self.connectCompletion {
                self.connectCompletion = nil
                completion(nil, NCConnector.Failure.handshake("lua connect cancelled"))
            }
            if let handler = self.pendingReceive {
                self.pendingReceive = nil
                handler(nil, nil)
            }
        }
    }
}
