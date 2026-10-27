import Foundation
import CommonCrypto
import CryptoKit
import Security

/// feat/nc-lua S2: the Swift side of the vendored Lua 5.4 bridge
/// (PacketTunnel/NativeCore/Lua/nc_lua_bridge.c).
///
/// One `NCLuaEngine` owns one `lua_State` created through the tracked
/// allocator (hard memory ceiling, 2 MB by default) and drives the
/// Shadowrocket custom-backend callbacks (`wa_lua_on_flags_cb`,
/// `wa_lua_on_handshake_cb`, `wa_lua_on_read_cb`, `wa_lua_on_write_cb`,
/// `wa_lua_on_close_cb`) under the bridge's execution deadline — the Lua
/// counterpart of the JSC engine's execution-time limit: a runaway script
/// errors out of its own pcall and kills only its own connection.
///
/// Threading: an engine is NOT thread-safe. `NCLuaSession` confines every
/// call to the connection's serial queue; the unit tests confine theirs to
/// the test thread.
///
/// Host functions never raise Lua errors from Swift (lua_error longjmps
/// through Swift frames); on bad input they return nil/false instead, so a
/// malformed script call degrades into a script-visible failure, never a
/// tunnel crash.
final class NCLuaEngine {

    enum CallFailure: Error, Equatable, CustomStringConvertible {
        case missingCallback(String)
        case luaError(String)
        var description: String {
            switch self {
            case .missingCallback(let n): return "lua callback \(n) is not defined by the script"
            case .luaError(let m): return "lua error: \(m)"
            }
        }
    }

    /// Shadowrocket backend.RESULT codes (design doc §5.2).
    static let resultSuccess = 0
    static let resultHandshake = 1
    static let resultError = -1
    static let resultIgnore = 2
    /// backend.RESULT.DIRECT: pass the returned bytes through unchanged (Shadowrocket http-backend.lua).
    static let resultDirect = 3

    let state: OpaquePointer
    private let tracker: UnsafeMutablePointer<NCLuaMemTracker>
    private(set) var lastError: String?

    var currentBytes: Int { Int(tracker.pointee.current_bytes) }
    var peakBytes: Int { Int(tracker.pointee.peak_bytes) }

    /// Create a state, load `source` and run its top level (which must only
    /// define the wa_lua_on_* globals). Returns nil with `initError` set on
    /// any failure.
    ///
    /// fix/nc-proto-lua-int: the host modules exist and (when `context` is given) the context and `settings`
    /// are wired BEFORE the top level runs — Shadowrocket scripts do `require 'backend'`, read
    /// `settings.password` and build `crypto.digest` objects at load time (trojan-backend.lua).
    init?(source: String, chunkName: String, memoryCap: Int = 2 * 1024 * 1024,
          context: NCLuaHostContext? = nil, settings: [(String, NCLuaSettingValue)] = [],
          initError: inout String?) {
        let tracker = UnsafeMutablePointer<NCLuaMemTracker>.allocate(capacity: 1)
        tracker.initialize(to: NCLuaMemTracker(current_bytes: 0, peak_bytes: 0, max_bytes: 0))
        self.tracker = tracker
        guard let L = nc_lua_newstate(tracker, memoryCap) else {
            initError = "lua state allocation failed"
            tracker.deinitialize(count: 1)
            tracker.deallocate()
            return nil
        }
        state = L
        nc_lua_init_context(L)
        Self.registerModules(L)
        if let context { attach(context: context, settings: settings) }
        let bytes = Array(source.utf8)
        let rc: Int32
        if bytes.isEmpty {
            rc = nc_lua_load_string(L, "", 0, chunkName)
        } else {
            rc = bytes.withUnsafeBufferPointer { buf in
                buf.baseAddress!.withMemoryRebound(to: CChar.self, capacity: buf.count) {
                    nc_lua_load_string(L, $0, buf.count, chunkName)
                }
            }
        }
        guard rc == LUA_OK else {
            initError = String(cString: nc_lua_get_error(L))
            // Every stored property is initialised here, so returning nil runs deinit, which closes the
            // state and frees the tracker. Closing here too was a double lua_close (SIGSEGV in
            // testEngineLoadFailureIsClean, CI 40450028930).
            return nil
        }
        nc_lua_set_deadline(L, 5)
        let runRC = nc_lua_pcall(L, 0, 0)
        nc_lua_set_deadline(L, 0)
        guard runRC == LUA_OK else {
            initError = String(cString: nc_lua_get_error(L))
            // Every stored property is initialised here, so returning nil runs deinit, which closes the
            // state and frees the tracker. Closing here too was a double lua_close (SIGSEGV in
            // testEngineLoadFailureIsClean, CI 40450028930).
            return nil
        }
    }

    deinit {
        nc_lua_close(state)
        tracker.deinitialize(count: 1)
        tracker.deallocate()
    }

    /// Wire the host modules (`backend`, `crypto`, `network`, `http`) and the
    /// global `settings` table to a live connection context. Must be called
    /// before any wa_lua_on_* callback runs.
    /// Host modules (`backend`, `crypto`, `network`, `http`): functions and constants only, no context.
    private static func registerModules(_ L: OpaquePointer) {
        nc_lua_register_fn(L, "backend", "get_uuid", ncLuaBackendGetUUID)
        nc_lua_register_fn(L, "backend", "get_proxy_type", ncLuaBackendGetProxyType)
        nc_lua_register_fn(L, "backend", "get_address_type", ncLuaBackendGetAddressType)
        nc_lua_register_fn(L, "backend", "get_address_host", ncLuaBackendGetAddressHost)
        nc_lua_register_fn(L, "backend", "get_address_bytes", ncLuaBackendGetAddressBytes)
        nc_lua_register_fn(L, "backend", "get_address_port", ncLuaBackendGetAddressPort)
        nc_lua_register_fn(L, "backend", "write", ncLuaBackendWrite)
        nc_lua_register_fn(L, "backend", "free", ncLuaBackendFree)
        nc_lua_register_fn(L, "backend", "debug", ncLuaBackendDebug)
        nc_lua_set_table_int(L, "backend", "ADDRESS", "IPV4", 1)
        nc_lua_set_table_int(L, "backend", "ADDRESS", "IPV6", 4)
        nc_lua_set_table_int(L, "backend", "ADDRESS", "DOMAIN", 3)
        nc_lua_set_table_int(L, "backend", "RESULT", "SUCCESS", Int64(Self.resultSuccess))
        nc_lua_set_table_int(L, "backend", "RESULT", "HANDSHAKE", Int64(Self.resultHandshake))
        nc_lua_set_table_int(L, "backend", "RESULT", "ERROR", Int64(Self.resultError))
        nc_lua_set_table_int(L, "backend", "RESULT", "IGNORE", Int64(Self.resultIgnore))
        nc_lua_set_table_int(L, "backend", "RESULT", "DIRECT", Int64(Self.resultDirect))
        nc_lua_set_table_int(L, "backend", "SUPPORT", "DIRECT_WRITE", 1)

        nc_lua_register_nested(L, "crypto", "rand", "bytes", ncLuaCryptoRandBytes)
        nc_lua_register_nested(L, "crypto", "encrypt", "new", ncLuaCryptoEncryptNew)
        nc_lua_register_nested(L, "crypto", "decrypt", "new", ncLuaCryptoDecryptNew)
        nc_lua_register_nested(L, "crypto", "digest", "new", ncLuaCryptoDigestNew)
        nc_lua_register_fn(L, "network", "htons", ncLuaNetworkHtons)
        nc_lua_register_fn(L, "network", "ntohs", ncLuaNetworkNtohs)
        nc_lua_register_fn(L, "network", "inet_pton", ncLuaNetworkInetPton)
        nc_lua_register_fn(L, "network", "inet_ntop", ncLuaNetworkInetNtop)
        nc_lua_register_fn(L, "http", "parse_headers", ncLuaHTTPParseHeaders)
        nc_lua_register_fn(L, "http", "build_header", ncLuaHTTPBuildHeader)

    }

    /// Wire the live connection context and the global `settings` table. The session passes both to `init`
    /// (so the script's top level sees them); tests may attach after init.
    func attach(context: NCLuaHostContext, settings: [(String, NCLuaSettingValue)]) {
        let L = state
        nc_lua_set_context_ptr(L, Unmanaged.passUnretained(context).toOpaque())
        // Shadowrocket always exposes `settings` (scripts read settings.x unguarded): an empty table when the
        // node carries no extra fields.
        let missing = lua_getglobal(L, "settings") != LUA_TTABLE
        lua_settop(L, -2)
        if missing { lua_createtable(L, 0, 0); lua_setglobal(L, "settings") }
        for (key, value) in settings {
            switch value {
            case .string(let s): nc_lua_set_table_string(L, "settings", nil, key, s)
            case .int(let n): nc_lua_set_table_int(L, "settings", nil, key, Int64(n))
            case .bool(let b): nc_lua_set_table_bool(L, "settings", nil, key, b ? 1 : 0)
            }
        }
    }

    // MARK: - Callback invocation

    /// Push fn + args and pcall. On LUA_OK the `nresults` values stay on the
    /// stack for the result readers; on any failure the stack is restored
    /// and a CallFailure is returned.
    /// fn(ctx[, data]) through nc_lua_call_cb: name lookup, argument pushes and the call itself all run under
    /// lua_pcall, so a memory-cap failure while pushing is a caught error, never an unprotected one (abort).
    /// On LUA_OK the `nresults` values stay on the stack for the result readers.
    private func call(_ name: String, data: Data?, nresults: Int32, deadline: TimeInterval) -> Result<Void, CallFailure> {
        let L = state
        let savedTop = lua_gettop(L)
        var missing: Int32 = 0
        nc_lua_set_deadline(L, deadline)
        let rc: Int32 = name.withCString { fname in
            guard let data else { return nc_lua_call_cb(L, fname, nil, 0, 0, nresults, &missing) }
            return data.withUnsafeBytes { raw in
                nc_lua_call_cb(L, fname, raw.baseAddress?.assumingMemoryBound(to: CChar.self), raw.count, 1,
                               nresults, &missing)
            }
        }
        nc_lua_set_deadline(L, 0)
        guard rc == LUA_OK else {
            let message = String(cString: nc_lua_get_error(L))
            lastError = message
            lua_settop(L, savedTop)
            return .failure(.luaError(message))
        }
        if missing != 0 {
            lua_settop(L, savedTop)
            return .failure(.missingCallback(name))
        }
        return .success(())
    }

    private func popResults(_ n: Int32) { lua_settop(state, lua_gettop(state) - n) }

    func callFlags(deadline: TimeInterval = 2) -> Result<Int, CallFailure> {
        switch call("wa_lua_on_flags_cb", data: nil, nresults: 1, deadline: deadline) {
        case .failure(let e): return .failure(e)
        case .success:
            let value = Int(lua_tointegerx(state, -1, nil))
            popResults(1)
            return .success(value)
        }
    }

    func callHandshake(deadline: TimeInterval = 5) -> Result<Bool, CallFailure> {
        switch call("wa_lua_on_handshake_cb", data: nil, nresults: 1, deadline: deadline) {
        case .failure(let e): return .failure(e)
        case .success:
            let value = lua_toboolean(state, -1) != 0
            popResults(1)
            return .success(value)
        }
    }

    /// Shared shape of on_read / on_write: (ctx, bytes) -> (status, bytes?).
    private func callTransform(_ name: String, data: Data, deadline: TimeInterval) -> Result<(status: Int, out: Data?), CallFailure> {
        switch call(name, data: data, nresults: 2, deadline: deadline) {
        case .failure(let e): return .failure(e)
        case .success:
            let status = Int(lua_tointegerx(state, -2, nil))
            var out: Data?
            if lua_type(state, -1) == LUA_TSTRING {
                var len = 0
                if let ptr = nc_lua_get_bytes(state, -1, &len) {
                    out = Data(bytes: ptr, count: len)
                }
            }
            popResults(2)
            return .success((status, out))
        }
    }

    func callRead(_ data: Data, deadline: TimeInterval = 2) -> Result<(status: Int, out: Data?), CallFailure> {
        callTransform("wa_lua_on_read_cb", data: data, deadline: deadline)
    }

    func callWrite(_ data: Data, deadline: TimeInterval = 2) -> Result<(status: Int, out: Data?), CallFailure> {
        callTransform("wa_lua_on_write_cb", data: data, deadline: deadline)
    }

    /// Read a global string (diagnostics and tests: scripts stash results in
    /// globals, e.g. `_G.result = ...`).
    func globalString(_ name: String) -> String? {
        let L = state
        let savedTop = lua_gettop(L)
        defer { lua_settop(L, savedTop) }
        guard lua_getglobal(L, name) == LUA_TSTRING else { return nil }
        var len = 0
        guard let ptr = nc_lua_get_bytes(L, -1, &len) else { return nil }
        return String(decoding: Data(bytes: ptr, count: len), as: UTF8.self)
    }

    /// Best effort: a missing or failing on_close never propagates.
    func callClose() {
        let top = lua_gettop(state)
        if case .success = call("wa_lua_on_close_cb", data: nil, nresults: 1, deadline: 1) {
            lua_settop(state, top)
        }
    }
}

enum NCLuaSettingValue {
    case string(String)
    case int(Int)
    case bool(Bool)
}

/// Per-connection host context the `backend` / `crypto` modules operate on.
/// Owned by the session (or by a unit test); the Lua state reaches it
/// through the bridge's context pointer and never retains it.
final class NCLuaHostContext {
    let uuid: String
    let target: NCTarget
    /// backend.get_proxy_type: 0 = custom Lua backend (no Shadowrocket
    /// numeric type is assigned to user backends).
    let proxyTypeCode = 0
    let addressType: Int
    let addressBytes: Data
    var onWrite: (Data) -> Void = { _ in }
    var onDebug: (String) -> Void = { _ in }
    private(set) var freed = false

    private var ciphers: [Int: NCLuaCipher] = [:]
    private var nextCipherID = 1

    init(uuid: String = UUID().uuidString, target: NCTarget) {
        self.uuid = uuid
        self.target = target
        if let ip = target.ip {
            switch ip {
            case .v4(let v):
                addressType = 1
                addressBytes = Data([UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)])
            case .v6(let bytes):
                addressType = 4
                addressBytes = Data(bytes)
            }
        } else {
            addressType = 3
            addressBytes = Data(target.host.utf8)
        }
    }

    func free() { freed = true }

    func registerCipher(_ cipher: NCLuaCipher) -> Int {
        let id = nextCipherID
        nextCipherID += 1
        ciphers[id] = cipher
        return id
    }

    func cipher(_ id: Int) -> NCLuaCipher? { ciphers[id] }

    /// A finished cipher / digest is unusable: drop it so a script building one per packet cannot grow the map.
    func removeCipher(_ id: Int) { ciphers[id] = nil }
}

// MARK: - Host function plumbing (C-callable, no captures)

private func ncLuaContext(_ L: OpaquePointer?) -> NCLuaHostContext? {
    guard let L, let raw = nc_lua_get_context_ptr(L) else { return nil }
    return Unmanaged<NCLuaHostContext>.fromOpaque(raw).takeUnretainedValue()
}

private func ncLuaStringArg(_ L: OpaquePointer, _ idx: Int32) -> String? {
    guard let data = ncLuaBytesArg(L, idx) else { return nil }
    return String(decoding: data, as: UTF8.self)
}

private func ncLuaBytesArg(_ L: OpaquePointer, _ idx: Int32) -> Data? {
    guard lua_type(L, idx) == LUA_TSTRING else { return nil }
    var len = 0
    guard let ptr = nc_lua_get_bytes(L, idx, &len) else { return nil }
    return Data(bytes: ptr, count: len)
}

private func ncLuaPushBytes(_ L: OpaquePointer, _ data: Data) {
    data.withUnsafeBytes { raw in
        nc_lua_push_bytes(L, raw.baseAddress?.assumingMemoryBound(to: CChar.self), data.count)
    }
}

// MARK: backend module

private func ncLuaBackendGetUUID(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    _ = lua_pushstring(L, ctx.uuid)
    return 1
}

private func ncLuaBackendGetProxyType(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    lua_pushinteger(L, lua_Integer(ctx.proxyTypeCode))
    return 1
}

private func ncLuaBackendGetAddressType(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    lua_pushinteger(L, lua_Integer(ctx.addressType))
    return 1
}

private func ncLuaBackendGetAddressHost(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    _ = lua_pushstring(L, ctx.target.host)
    return 1
}

private func ncLuaBackendGetAddressBytes(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    ncLuaPushBytes(L, ctx.addressBytes)
    return 1
}

private func ncLuaBackendGetAddressPort(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    lua_pushinteger(L, lua_Integer(ctx.target.port))
    return 1
}

private func ncLuaBackendWrite(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L), !ctx.freed, let data = ncLuaBytesArg(L, 2) else { return 0 }
    ctx.onWrite(data)
    return 0
}

private func ncLuaBackendFree(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L) else { return 0 }
    ctx.free()
    return 0
}

private func ncLuaBackendDebug(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L), let message = ncLuaStringArg(L, 1) else { return 0 }
    ctx.onDebug(message)
    return 0
}

// MARK: crypto module

private func ncLuaCryptoRandBytes(_ L: OpaquePointer?) -> Int32 {
    guard let L else { return 0 }
    let count = Int(lua_tointegerx(L, 1, nil))
    guard count > 0, count <= 65536 else { lua_pushnil(L); return 1 }
    var data = Data(count: count)
    let rc = data.withUnsafeMutableBytes { raw in
        SecRandomCopyBytes(kSecRandomDefault, count, raw.baseAddress!)
    }
    guard rc == errSecSuccess else { lua_pushnil(L); return 1 }
    ncLuaPushBytes(L, data)
    return 1
}

private func ncLuaCryptoNew(_ L: OpaquePointer?, decrypt: Bool) -> Int32 {
    guard let L, let ctx = ncLuaContext(L),
          let algorithm = ncLuaStringArg(L, 1)?.lowercased(),
          let key = ncLuaBytesArg(L, 2) else { return 0 }
    let iv = ncLuaBytesArg(L, 3) ?? Data()
    guard let cipher = NCLuaCipher.make(algorithm: algorithm, key: key, iv: iv, decrypt: decrypt) else {
        lua_pushnil(L)
        return 1
    }
    let id = ctx.registerCipher(cipher)
    lua_createtable(L, 0, 3)
    lua_pushinteger(L, lua_Integer(id))
    lua_setfield(L, -2, "__id")
    lua_pushcclosure(L, ncLuaCipherUpdate, 0)
    lua_setfield(L, -2, "update")
    lua_pushcclosure(L, ncLuaCipherFinal, 0)
    lua_setfield(L, -2, "final")
    return 1
}

private func ncLuaCryptoEncryptNew(_ L: OpaquePointer?) -> Int32 { ncLuaCryptoNew(L, decrypt: false) }
private func ncLuaCryptoDecryptNew(_ L: OpaquePointer?) -> Int32 { ncLuaCryptoNew(L, decrypt: true) }

private func ncLuaCipherSelf(_ L: OpaquePointer) -> NCLuaCipher? {
    guard let ctx = ncLuaContext(L), lua_type(L, 1) == LUA_TTABLE else { return nil }
    lua_getfield(L, 1, "__id")
    let id = Int(lua_tointegerx(L, -1, nil))
    lua_settop(L, lua_gettop(L) - 1)
    return ctx.cipher(id)
}

private func ncLuaCipherUpdate(_ L: OpaquePointer?) -> Int32 {
    guard let L, let cipher = ncLuaCipherSelf(L), let data = ncLuaBytesArg(L, 2),
          let out = cipher.update(data) else {
        if let L { lua_pushnil(L) }
        return 1
    }
    ncLuaPushBytes(L, out)
    return 1
}

private func ncLuaCipherFinal(_ L: OpaquePointer?) -> Int32 {
    guard let L, let cipher = ncLuaCipherSelf(L) else {
        if let L { lua_pushnil(L) }
        return 1
    }
    let out = cipher.final()
    if let ctx = ncLuaContext(L), lua_type(L, 1) == LUA_TTABLE {
        lua_getfield(L, 1, "__id")
        let id = Int(lua_tointegerx(L, -1, nil))
        lua_settop(L, lua_gettop(L) - 1)
        ctx.removeCipher(id)
    }
    guard let out else { lua_pushnil(L); return 1 }
    ncLuaPushBytes(L, out)
    return 1
}

/// crypto.digest.new(name): update(data) / final() -> lowercase hex string (trojan-backend.lua concatenates
/// `sha224:final()` straight into the Trojan header, which carries hex(SHA224(password))).
private func ncLuaCryptoDigestNew(_ L: OpaquePointer?) -> Int32 {
    guard let L, let ctx = ncLuaContext(L), let name = ncLuaStringArg(L, 1)?.lowercased(),
          let digest = NCLuaDigest(algorithm: name) else {
        if let L { lua_pushnil(L) }
        return 1
    }
    let id = ctx.registerCipher(digest)
    lua_createtable(L, 0, 3)
    lua_pushinteger(L, lua_Integer(id))
    lua_setfield(L, -2, "__id")
    lua_pushcclosure(L, ncLuaCipherUpdate, 0)
    lua_setfield(L, -2, "update")
    lua_pushcclosure(L, ncLuaCipherFinal, 0)
    lua_setfield(L, -2, "final")
    return 1
}

// MARK: network module

private func ncLuaNetworkHtons(_ L: OpaquePointer?) -> Int32 {
    guard let L else { return 0 }
    let port = UInt16(truncatingIfNeeded: lua_tointegerx(L, 1, nil))
    ncLuaPushBytes(L, Data([UInt8(port >> 8), UInt8(port & 0xff)]))
    return 1
}

private func ncLuaNetworkNtohs(_ L: OpaquePointer?) -> Int32 {
    guard let L, let data = ncLuaBytesArg(L, 1), data.count >= 2 else {
        if let L { lua_pushnil(L) }
        return 1
    }
    lua_pushinteger(L, lua_Integer(data[data.startIndex]) << 8 | lua_Integer(data[data.startIndex + 1]))
    return 1
}

private func ncLuaNetworkInetPton(_ L: OpaquePointer?) -> Int32 {
    guard let L else { return 0 }
    let af = Int(lua_tointegerx(L, 1, nil))
    guard let text = ncLuaStringArg(L, 2) else { lua_pushnil(L); return 1 }
    if af == AF_INET {
        let parts = text.split(separator: ".")
        var bytes = [UInt8]()
        var ok = parts.count == 4
        for part in parts {
            if let v = UInt8(part) { bytes.append(v) } else { ok = false; break }
        }
        if ok { ncLuaPushBytes(L, Data(bytes)); return 1 }
        lua_pushnil(L)
        return 1
    }
    var buf = [UInt8](repeating: 0, count: 16)
    let rc = inet_pton(AF_INET6, text, &buf)
    if rc == 1 { ncLuaPushBytes(L, Data(buf)) } else { lua_pushnil(L) }
    return 1
}

private func ncLuaNetworkInetNtop(_ L: OpaquePointer?) -> Int32 {
    guard let L else { return 0 }
    let af = Int(lua_tointegerx(L, 1, nil))
    guard let data = ncLuaBytesArg(L, 2) else { lua_pushnil(L); return 1 }
    if af == AF_INET, data.count == 4 {
        let b = [UInt8](data)
        _ = lua_pushstring(L, "\(b[0]).\(b[1]).\(b[2]).\(b[3])")
        return 1
    }
    if data.count == 16 {
        var bytes = [UInt8](data)
        var out = [CChar](repeating: 0, count: 46)
        let rc = inet_ntop(AF_INET6, &bytes, &out, socklen_t(out.count))
        if rc != nil {
            _ = lua_pushstring(L, String(cString: out))
            return 1
        }
    }
    lua_pushnil(L)
    return 1
}

// MARK: http module (minimal: header block parse/format for obfuscation backends)

private func ncLuaHTTPParseHeaders(_ L: OpaquePointer?) -> Int32 {
    guard let L, let data = ncLuaBytesArg(L, 1),
          let text = String(data: data, encoding: .utf8) else {
        if let L { lua_pushnil(L) }
        return 1
    }
    lua_createtable(L, 0, 0)
    for line in text.components(separatedBy: "\r\n") {
        if line.isEmpty { break }
        guard let colon = line.firstIndex(of: ":") else { continue }
        let name = line[..<colon].lowercased().trimmingCharacters(in: .whitespaces)
        let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        if !name.isEmpty {
            _ = lua_pushstring(L, value)
            lua_setfield(L, -2, name)
        }
    }
    return 1
}

private func ncLuaHTTPBuildHeader(_ L: OpaquePointer?) -> Int32 {
    guard let L, let name = ncLuaStringArg(L, 1), let value = ncLuaStringArg(L, 2) else {
        if let L { lua_pushnil(L) }
        return 1
    }
    _ = lua_pushstring(L, "\(name): \(value)\r\n")
    return 1
}
