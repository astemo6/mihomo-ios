import XCTest
@testable import Tern

final class NativeCoreLuaTests: XCTestCase {

    // MARK: - S1 import surface, updated for the S2 live status

    func testShadowrocketConfLuaNodeImport() {
        let text = """
        [Proxy]
        Direct = direct
        MyLua = lua, 192.0.2.1, 1080, file=backend.lua, username=alice, password=secret
        """
        let c = NCConfImport.surge(text)
        XCTAssertEqual(c.nodes.count, 2)

        let node = c.nodeMap["MyLua"]
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.server, "192.0.2.1")
        XCTAssertEqual(node?.port, 1080)
        XCTAssertEqual(node?.fields["file"]?.string, "backend.lua")
        XCTAssertEqual(node?.fields["username"]?.string, "alice")
        XCTAssertEqual(node?.password, "secret")
        XCTAssertEqual(node?.isLua, true)
        // S2: proxy backends are live — no pending marker anymore.
        XCTAssertEqual(node?.isLuaPendingS2, false)
        XCTAssertNil(node?.fields["lua-status"])

        XCTAssertTrue(c.report.warnings.contains { $0.contains("lua proxy backend recognized") })

        // The node carries a script file, so the support layer accepts it.
        if let node {
            XCTAssertNil(NCSupport.unsupportedReason(node))
            XCTAssertTrue(NCSupport.types.contains("lua"))
        }
    }

    func testShadowrocketConfLuaScriptImport() {
        let text = """
        [Script]
        script1 = type=http-response,pattern=^https?://api\\.example\\.com,script-path=rule.lua,requires-body=true
        script2 = type=http-request,pattern=^https?://api2\\.example\\.com,script-path=handler.js,engine=lua
        """
        let c = NCConfImport.surge(text)
        XCTAssertEqual(c.scripts.count, 2)

        // HTTP-layer Lua scripts stay explicitly unsupported in S2: the Lua
        // engine serves proxy backends (L4/L5), the HTTP script layer is JSC.
        let s1 = c.scripts.first { $0.name == "script1" }
        XCTAssertNotNil(s1)
        XCTAssertEqual(s1?.isLua, true)
        XCTAssertEqual(s1?.isPendingS2, false)
        XCTAssertEqual(s1?.extra["engine"], "lua")
        XCTAssertEqual(s1?.extra["status"], "unsupported")

        let s2 = c.scripts.first { $0.name == "script2" }
        XCTAssertNotNil(s2)
        XCTAssertEqual(s2?.isLua, true)
        XCTAssertEqual(s2?.isPendingS2, false)
        XCTAssertEqual(s2?.extra["status"], "unsupported")

        XCTAssertTrue(c.report.warnings.contains { $0.contains("script 'script1': lua script recognized") })
        XCTAssertTrue(c.report.warnings.contains { $0.contains("script 'script2': lua script recognized") })
    }

    func testQuantumultXServerLocalAndRewriteLuaImport() {
        let text = """
        [server_local]
        lua = 10.0.0.1:8888, file=custom.lua, user=bob, password=pwd, tag=QX-Lua

        [rewrite_local]
        ^https?://example\\.com url script-response-body test_rewrite.lua
        """
        let c = NCQXImport.quantumultx(text)

        let node = c.nodeMap["QX-Lua"]
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.server, "10.0.0.1")
        XCTAssertEqual(node?.port, 8888)
        XCTAssertEqual(node?.fields["file"]?.string, "custom.lua")
        XCTAssertEqual(node?.fields["username"]?.string, "bob")
        XCTAssertEqual(node?.password, "pwd")
        XCTAssertEqual(node?.isLua, true)
        XCTAssertEqual(node?.isLuaPendingS2, false)

        let script = c.scripts.first { $0.scriptPath == "test_rewrite.lua" }
        XCTAssertNotNil(script)
        XCTAssertEqual(script?.isLua, true)
        XCTAssertEqual(script?.isPendingS2, false)
        XCTAssertEqual(script?.extra["status"], "unsupported")
        XCTAssertEqual(script?.extra["engine"], "lua")

        XCTAssertTrue(c.report.warnings.contains { $0.contains("quantumultx [server_local]: lua proxy backend 'QX-Lua' recognized") })
        XCTAssertTrue(c.report.warnings.contains { $0.contains("quantumultx rewrite: lua script 'test_rewrite.lua' recognized") })
    }

    func testClashYAMLLuaNodeImport() {
        let root: [String: NCJSONValue] = [
            "proxies": .array([
                .object([
                    "name": .string("ClashLua"),
                    "type": .string("lua"),
                    "server": .string("203.0.113.5"),
                    "port": .number(9090),
                    "file": .string("client.lua")
                ])
            ])
        ]
        let cfg = NCConfig.decode(root: root)
        let c = NCCanonicalConfig.from(clash: cfg)

        XCTAssertEqual(c.nodes.count, 1)
        let node = c.nodes.first
        XCTAssertEqual(node?.name, "ClashLua")
        XCTAssertEqual(node?.type, "lua")
        XCTAssertEqual(node?.isLua, true)
        XCTAssertEqual(node?.isLuaPendingS2, false)
        XCTAssertNil(node?.fields["lua-status"])
        XCTAssertTrue(c.report.warnings.contains { $0.contains("node 'ClashLua': lua proxy backend recognized") })

        if let node {
            XCTAssertNil(NCSupport.unsupportedReason(node))
        }
    }

    func testLuaNodeWithoutScriptIsUnsupported() {
        let bare = NCProxy(name: "Bare", type: "lua", fields: [
            "server": .string("192.0.2.9"), "port": .number(1080)
        ])
        XCTAssertEqual(NCSupport.unsupportedReason(bare), "Lua 后端缺少脚本 (file/script)")
    }

    // MARK: - S2 engine: load / call / host modules

    private func makeEngine(_ source: String, target: NCTarget = NCTarget(host: "example.com", port: 443),
                            settings: [(String, NCLuaSettingValue)] = []) -> NCLuaEngine {
        var err: String?
        // Same order as NCLuaSession: context + settings are wired before the top level runs.
        let context = NCLuaHostContext(target: target)
        contexts.append(context) // the Lua state never retains its context
        let engine = NCLuaEngine(source: source, chunkName: "test.lua", context: context, settings: settings,
                                 initError: &err)
        return try! XCTUnwrap(engine, "engine init failed: \(err ?? "?")")
    }

    private var contexts: [NCLuaHostContext] = []

    private static let identityScript = """
    function wa_lua_on_flags_cb(ctx)
      _G.seen_host = backend.get_address_host(ctx)
      _G.seen_atype = tostring(backend.get_address_type(ctx))
      _G.seen_port = tostring(backend.get_address_port(ctx))
      _G.seen_user = settings.username or ""
      return 0
    end
    function wa_lua_on_handshake_cb(ctx) return true end
    function wa_lua_on_read_cb(ctx, buf) return backend.RESULT.SUCCESS, buf end
    function wa_lua_on_write_cb(ctx, buf) return backend.RESULT.SUCCESS, buf end
    function wa_lua_on_close_cb(ctx) return 0 end
    """

    func testEngineCallbacksAndHostModules() throws {
        let engine = makeEngine(Self.identityScript,
                                settings: [("username", .string("alice"))])
        XCTAssertEqual(engine.callFlags(), .success(0))
        XCTAssertEqual(engine.globalString("seen_host"), "example.com")
        XCTAssertEqual(engine.globalString("seen_atype"), "3") // DOMAIN
        XCTAssertEqual(engine.globalString("seen_port"), "443")
        XCTAssertEqual(engine.globalString("seen_user"), "alice")
        XCTAssertEqual(engine.callHandshake(), .success(true))
        let payload = Data([0, 1, 2, 250, 251, 0, 99])
        XCTAssertEqual(engine.callWrite(payload).map { $0.out }, .success(payload))
        XCTAssertEqual(engine.callRead(payload).map { $0.out }, .success(payload))
    }

    func testEngineIPv4AddressType() throws {
        let engine = makeEngine(Self.identityScript, target: NCTarget(host: "192.0.2.7", port: 80))
        XCTAssertEqual(engine.callFlags(), .success(0))
        XCTAssertEqual(engine.globalString("seen_atype"), "1") // IPV4
    }

    func testEngineLoadFailureIsClean() {
        var err: String?
        let engine = NCLuaEngine(source: "this is not lua (((", chunkName: "bad.lua", initError: &err)
        XCTAssertNil(engine)
        XCTAssertNotNil(err)
    }

    func testEngineErrorIsolation() throws {
        let source = """
        function wa_lua_on_flags_cb(ctx) return 0 end
        function wa_lua_on_handshake_cb(ctx) return true end
        function wa_lua_on_write_cb(ctx, buf) error("boom from script") end
        function wa_lua_on_read_cb(ctx, buf) return backend.RESULT.SUCCESS, buf end
        """
        let engine = makeEngine(source)
        let writeResult = engine.callWrite(Data([1, 2, 3]))
        guard case .failure(.luaError(let message)) = writeResult else {
            return XCTFail("expected luaError, got \(writeResult)")
        }
        XCTAssertTrue(message.contains("boom from script"), message)
        // The same state survives a script error (pcall caught it)…
        XCTAssertEqual(engine.callHandshake(), .success(true))
        // …and a second engine is entirely unaffected.
        let other = makeEngine(Self.identityScript)
        XCTAssertEqual(other.callWrite(Data([9])).map { $0.out }, .success(Data([9])))
    }

    func testEngineDeadlineStopsInfiniteLoop() throws {
        let source = """
        function wa_lua_on_write_cb(ctx, buf) while true do end end
        """
        let engine = makeEngine(source)
        let start = Date()
        let result = engine.callWrite(Data([1]), deadline: 1)
        let elapsed = Date().timeIntervalSince(start)
        guard case .failure(.luaError(let message)) = result else {
            return XCTFail("expected deadline luaError, got \(result)")
        }
        XCTAssertTrue(message.contains("deadline"), message)
        XCTAssertLessThan(elapsed, 10)
    }

    func testEngineMemoryCapStopsAllocationBomb() throws {
        let source = """
        function wa_lua_on_write_cb(ctx, buf)
          local t = {}
          for i = 1, 1000000 do t[i] = string.rep("x", 512) end
          return backend.RESULT.SUCCESS, buf
        end
        """
        let engine = makeEngine(source)
        let result = engine.callWrite(Data([1]), deadline: 10)
        guard case .failure = result else {
            return XCTFail("expected memory-cap failure, got \(result)")
        }
        XCTAssertLessThanOrEqual(engine.peakBytes, 2 * 1024 * 1024)
    }

    // MARK: - S2 crypto / network modules (driven through Lua itself)

    func testCryptoAESCFBRoundTripThroughLua() throws {
        let source = """
        local key = string.rep(string.char(7), 32)
        local iv = string.rep(string.char(9), 16)
        local enc = crypto.encrypt.new("aes-256-cfb", key, iv)
        local dec = crypto.decrypt.new("aes-256-cfb", key, iv)
        function wa_lua_on_flags_cb(ctx)
          if enc == nil or dec == nil then return 1 end
          return 0
        end
        function wa_lua_on_handshake_cb(ctx) return true end
        function wa_lua_on_write_cb(ctx, buf) return backend.RESULT.SUCCESS, enc:update(buf) end
        function wa_lua_on_read_cb(ctx, buf) return backend.RESULT.SUCCESS, dec:update(buf) end
        """
        let engine = makeEngine(source)
        XCTAssertEqual(engine.callFlags(), .success(0))
        // Two chunks on purpose: CFB state must carry across update() calls.
        guard case .success(let first) = engine.callWrite(Data("hello ".utf8)),
              case .success(let second) = engine.callWrite(Data("lua world".utf8)) else {
            return XCTFail("encrypt failed")
        }
        let ciphertext = (first.out ?? Data()) + (second.out ?? Data())
        XCTAssertEqual(ciphertext.count, 17)
        XCTAssertNotEqual(ciphertext, Data("hello lua world".utf8))
        guard case .success(let back) = engine.callRead(ciphertext) else {
            return XCTFail("decrypt failed")
        }
        XCTAssertEqual(back.out, Data("hello lua world".utf8))
    }

    func testCryptoChaChaPolyRejectsGarbageThroughLua() throws {
        let source = """
        local key = string.rep(string.char(3), 32)
        local iv = string.rep(string.char(5), 12)
        local enc = crypto.encrypt.new("chacha20-poly1305", key, iv)
        local dec = crypto.decrypt.new("chacha20-poly1305", key, iv)
        function wa_lua_on_flags_cb(ctx)
          if enc == nil or dec == nil then return 1 end
          return 0
        end
        function wa_lua_on_handshake_cb(ctx) return true end
        function wa_lua_on_write_cb(ctx, buf)
          enc:update(buf)
          return backend.RESULT.SUCCESS, ""
        end
        function wa_lua_on_read_cb(ctx, buf)
          dec:update(buf)
          local plain = dec:final()
          if plain == nil then return backend.RESULT.ERROR, nil end
          return backend.RESULT.SUCCESS, plain
        end
        """
        let engine = makeEngine(source)
        XCTAssertEqual(engine.callFlags(), .success(0))
        _ = engine.callWrite(Data("authenticated payload".utf8))
        // AEAD failure path: garbage into the decryptor must surface the
        // script's ERROR status, not a crash or a bogus plaintext.
        let bad = engine.callRead(Data(repeating: 0xaa, count: 40))
        guard case .success(let (status, _)) = bad else {
            return XCTFail("expected success tuple, got \(bad)")
        }
        XCTAssertEqual(status, NCLuaEngine.resultError)
    }

    func testCryptoUnsupportedAlgorithmReturnsNil() throws {
        let source = """
        function wa_lua_on_flags_cb(ctx)
          _G.bad = crypto.encrypt.new("des-cbc", string.rep("k", 8), string.rep("i", 8)) == nil and "nil" or "obj"
          return 0
        end
        """
        let engine = makeEngine(source)
        XCTAssertEqual(engine.callFlags(), .success(0))
        XCTAssertEqual(engine.globalString("bad"), "nil")
    }

    func testNetworkModuleThroughLua() throws {
        let source = """
        function wa_lua_on_flags_cb(ctx)
          _G.h = network.htons(0x1234)
          _G.p = tostring(network.ntohs(_G.h))
          _G.ip = network.inet_ntop(2, network.inet_pton(2, "203.0.113.9"))
          return 0
        end
        """
        let engine = makeEngine(source)
        XCTAssertEqual(engine.callFlags(), .success(0))
        XCTAssertEqual(engine.globalString("h"), "\u{12}\u{34}")
        XCTAssertEqual(engine.globalString("p"), "4660")
        XCTAssertEqual(engine.globalString("ip"), "203.0.113.9")
    }

    // MARK: - S2 cipher vectors (Swift level)

    func testRC4KnownVector() {
        // RFC 6229: key "Key", keystream over "Plaintext" -> BBF316E8D940AF0AD3
        let cipher = NCLuaCipher.make(algorithm: "rc4", key: Data("Key".utf8), iv: Data(), decrypt: false)
        XCTAssertNotNil(cipher)
        let out = cipher?.update(Data("Plaintext".utf8))
        XCTAssertEqual(out?.map { String(format: "%02x", $0) }.joined(), "bbf316e8d940af0ad3")
    }

    func testChaCha20RoundTripAndChunking() {
        let key = Data((0..<32).map { UInt8($0) })
        let nonce = Data((0..<12).map { UInt8(0xa0 + $0) })
        let enc = NCLuaCipher.make(algorithm: "chacha20", key: key, iv: nonce, decrypt: false)
        let dec = NCLuaCipher.make(algorithm: "chacha20", key: key, iv: nonce, decrypt: true)
        XCTAssertNotNil(enc); XCTAssertNotNil(dec)
        let plain = Data((0..<200).map { UInt8(($0 * 13 + 7) & 0xff) })
        // Chunked encryption must equal one-shot (keystream continuity).
        var ct = Data()
        ct.append(enc!.update(Data(plain.prefix(3)))!)
        ct.append(enc!.update(Data(plain.dropFirst(3)))!)
        XCTAssertNotEqual(ct, plain)
        XCTAssertEqual(dec!.update(ct), plain)
    }

    // MARK: - S2 end-to-end: NCLuaSession over an in-memory transport

    /// The test backend script: a 2-byte handshake ("HE" -> "HO") and then a
    /// XOR transform in both directions — the smallest honest Shadowrocket
    /// backend shape (flags/handshake/read/write/close all exercised).
    private static let xorBackendScript = """
    local KEY = 0x5A
    local function xorBytes(s)
      return (s:gsub(".", function(c) return string.char(string.byte(c) ~ KEY) end))
    end
    function wa_lua_on_flags_cb(ctx)
      backend.write(ctx, "HE")
      return 0
    end
    function wa_lua_on_handshake_cb(ctx) return _G.hs_done == true end
    function wa_lua_on_read_cb(ctx, buf)
      if _G.hs_done ~= true then
        if buf == "HO" then
          _G.hs_done = true
          return backend.RESULT.HANDSHAKE, nil
        end
        return backend.RESULT.ERROR, nil
      end
      return backend.RESULT.SUCCESS, xorBytes(buf)
    end
    function wa_lua_on_write_cb(ctx, buf) return backend.RESULT.SUCCESS, xorBytes(buf) end
    function wa_lua_on_close_cb(ctx) _G.closed = "yes" return 0 end
    """

    func testSessionEndToEndXORBackend() {
        let queue = DispatchQueue(label: "nc.lua.test")
        let clientRaw = MemoryStream()
        let serverRaw = MemoryStream()
        clientRaw.peer = serverRaw
        serverRaw.peer = clientRaw

        // Fake peer: answer "HE" with "HO", then echo with the XOR transform
        // applied (so the client's on_read XOR restores the plaintext).
        let server = XORPeer(stream: serverRaw)
        server.start()

        let proxy = NCProxy(name: "xorlua", type: "lua", fields: [
            "server": .string("127.0.0.1"), "port": .number(18016),
            "script": .string(Self.xorBackendScript)
        ])
        let connectExp = expectation(description: "lua connect")
        var session: NCRelayStream?
        var connectError: Error?
        NCLuaSession.connect(raw: clientRaw, proxy: proxy,
                             target: NCTarget(host: "example.com", port: 443), queue: queue) { stream, err in
            session = stream
            connectError = err
            connectExp.fulfill()
        }
        wait(for: [connectExp], timeout: 10)
        XCTAssertNil(connectError)
        XCTAssertNotNil(session)

        let payload = Data("lua session echo round trip".utf8)
        let echoExp = expectation(description: "lua echo")
        var echoed: Data?
        session?.receive { data, _ in
            echoed = data
            echoExp.fulfill()
        }
        session?.send(payload)
        wait(for: [echoExp], timeout: 10)
        XCTAssertEqual(echoed, payload)

        session?.cancel()
    }

    // MARK: - fix/nc-proto-lua-int: Shadowrocket script compatibility + sandbox

    /// Shadowrocket/lua-backend trojan-backend.lua (MIT, github.com/Shadowrocket/lua-backend), verbatim:
    /// `require` at the top, `settings.password` and a crypto.digest object used at LOAD time, on_flags
    /// returning 0x01, no on_read / on_write (pass-through).
    static let shadowrocketTrojanBackend = #"""
    -- file: lua/trojan-http.lua

    local http = require 'http'
    local backend = require 'backend'
    local network = require 'network'

    local char = string.char
    local byte = string.byte

    local ADDRESS = backend.ADDRESS
    local PROXY = backend.PROXY
    local SUCCESS = backend.RESULT.SUCCESS

    local ctx_uuid = backend.get_uuid
    local ctx_proxy_type = backend.get_proxy_type
    local ctx_address_type = backend.get_address_type
    local ctx_address_host = backend.get_address_host
    local ctx_address_bytes = backend.get_address_bytes
    local ctx_address_port = backend.get_address_port
    local ctx_write = backend.write
    local ctx_free = backend.free
    local htons = network.htons

    local digest = crypto.digest
    local sha224 = digest.new('SHA224')
    sha224:update(settings.password)
    local hash224 = sha224:final()
    local flags = {}

    function wa_lua_on_flags_cb(settings)
        return 0x01
    end

    function wa_lua_on_handshake_cb(ctx)
        local port = ctx_address_port(ctx)
        local atype = ctx_address_type(ctx)
        local res = hash224 .. char(0x0d, 0x0a, 0x01, atype)

        if atype == ADDRESS.DOMAIN then
            local host = ctx_address_host(ctx)
            res = res .. char(#host) .. host
        else
            local addr = ctx_address_bytes(ctx)
            res = res .. addr
        end

        res = res .. htons(port) .. char(0x0d, 0x0a)
        ctx_write(ctx, res)

        return true
    end

    function wa_lua_on_close_cb(ctx)
        ctx_free(ctx)
        return SUCCESS
    end
    """#

    func testShadowrocketTrojanBackendLoadsAndBuildsHeader() throws {
        var written = Data()
        let context = NCLuaHostContext(target: NCTarget(host: "example.com", port: 443))
        context.onWrite = { written.append($0) }
        var err: String?
        let engine = try XCTUnwrap(NCLuaEngine(source: Self.shadowrocketTrojanBackend, chunkName: "trojan-backend.lua",
                                               context: context, settings: [("password", .string("nc-loop-pw"))],
                                               initError: &err), "load failed: \(err ?? "?")")
        XCTAssertEqual(engine.callFlags(), .success(1))
        XCTAssertEqual(engine.callHandshake(), .success(true))
        // hex(SHA224("nc-loop-pw")) CRLF CMD=1 ATYP=3 len host port(be) CRLF
        var want = Data("9aef0fe4a4afe19fc0c6e159c34ebc3f196d9f6ba76943d4bc954700".utf8)
        want.append(contentsOf: [0x0d, 0x0a, 0x01, 0x03, UInt8("example.com".utf8.count)])
        want.append(Data("example.com".utf8))
        want.append(contentsOf: [0x01, 0xbb, 0x0d, 0x0a])
        XCTAssertEqual(written, want)
        // No on_read / on_write in this script: the engine reports them missing (the session passes through).
        guard case .failure(.missingCallback) = engine.callWrite(Data([1])) else {
            return XCTFail("on_write should be reported missing")
        }
    }

    func testSandboxBlocksFileAccessAndBytecode() throws {
        let source = #"""
        _G.r_dofile = tostring(dofile)
        _G.r_loadfile = tostring(loadfile)
        local f, why = load(string.dump(function() return 1 end))
        _G.r_bytecode = tostring(f) .. "|" .. tostring(why)
        _G.r_text = tostring(load("return 40 + 2")())
        _G.r_backend = type(require("backend").write)
        local ok, e = pcall(require, "io")
        _G.r_io = tostring(ok)
        """#
        let engine = makeEngine(source)
        XCTAssertEqual(engine.globalString("r_dofile"), "nil")
        XCTAssertEqual(engine.globalString("r_loadfile"), "nil")
        XCTAssertTrue(engine.globalString("r_bytecode")?.hasPrefix("nil|") ?? false, engine.globalString("r_bytecode") ?? "")
        XCTAssertEqual(engine.globalString("r_text"), "42")
        XCTAssertEqual(engine.globalString("r_backend"), "function")
        XCTAssertEqual(engine.globalString("r_io"), "false")
    }

    func testFlagsBitmaskAndDirectResult() throws {
        let source = """
        local backend = require 'backend'
        function wa_lua_on_flags_cb(ctx) return backend.SUPPORT.DIRECT_WRITE end
        function wa_lua_on_read_cb(ctx, buf) return backend.RESULT.DIRECT, buf end
        """
        let engine = makeEngine(source)
        XCTAssertEqual(engine.callFlags(), .success(1))
        XCTAssertEqual(engine.callRead(Data([7, 8])).map { $0.status }, .success(NCLuaEngine.resultDirect))
        XCTAssertEqual(engine.callRead(Data([7, 8])).map { $0.out }, .success(Data([7, 8])))
        guard case .failure(.missingCallback) = engine.callHandshake() else {
            return XCTFail("on_handshake should be reported missing")
        }
    }

    func testAESGCMRoundTripSwiftLevel() {
        let key = Data(repeating: 0x11, count: 32)
        let nonce = Data(repeating: 0x22, count: 12)
        let enc = NCLuaCipher.make(algorithm: "aes-256-gcm", key: key, iv: nonce, decrypt: false)
        let dec = NCLuaCipher.make(algorithm: "aes-256-gcm", key: key, iv: nonce, decrypt: true)
        XCTAssertNotNil(enc); XCTAssertNotNil(dec)
        let message = Data("gcm message".utf8)
        _ = enc!.update(message)
        let sealed = enc!.final()
        XCTAssertEqual(sealed?.count, message.count + 16)
        _ = dec!.update(sealed!)
        XCTAssertEqual(dec!.final(), message)
    }
}

// MARK: - In-memory transport for the session test

/// A paired in-memory NCRelayStream: bytes sent on one side are delivered
/// to the other side's pending (or next) receive. Delivery is synchronous,
/// which keeps the session test deterministic.
private final class MemoryStream: NCRelayStream {
    var peer: MemoryStream?
    private var waiter: ((Data?, Error?) -> Void)?
    private var queued: [Data] = []
    private let lock = NSLock()

    func send(_ data: Data) { send(data, completion: {}) }

    func send(_ data: Data, completion: @escaping () -> Void) {
        peer?.deliver(data)
        completion()
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        lock.lock()
        if !queued.isEmpty {
            let data = queued.removeFirst()
            lock.unlock()
            handler(data, nil)
            return
        }
        waiter = handler
        lock.unlock()
    }

    func deliver(_ data: Data) {
        lock.lock()
        if let w = waiter {
            waiter = nil
            lock.unlock()
            w(data, nil)
            return
        }
        queued.append(data)
        lock.unlock()
    }

    func cancel() {}
}

/// The peer side of the XOR backend protocol: expects "HE", answers "HO",
/// then echoes every chunk verbatim — the wire bytes are already the
/// client's on_write output, and the client's on_read applies the same
/// XOR to restore the plaintext (the transform is symmetric).
private final class XORPeer {
    private let stream: MemoryStream
    private var handshaken = false

    init(stream: MemoryStream) { self.stream = stream }

    func start() { arm() }

    private func arm() {
        stream.receive { [weak self] data, _ in
            guard let self, let data else { return }
            if !self.handshaken {
                if data == Data("HE".utf8) {
                    self.handshaken = true
                    self.stream.send(Data("HO".utf8))
                }
            } else {
                self.stream.send(data)
            }
            self.arm()
        }
    }
}
