// App/Core/NCScriptManifest.swift
// E-B1b stage 3: Port of ExportScriptManifest (bridge/mitm/exportsnap.go) to Swift.
//
// Sources:
//   - bridge/mitm/exportsnap.go (ExportScriptManifest, ScriptManifestEntry, scriptManifest, ScriptManifestFile, ScriptManifestDir)
//   - bridge/mitm/script.go (scriptCode :325, scriptTimeout :1111, runCtx.setupJSON :1422, jsSetup, jsArg, jsEnv)
//   - bridge/mitm/tasks.go (Task :36, Panel :52, stableID, withLineOpts, disabledByParam)
//   - bridge/mitm/egernadapter.go (adaptEgern, isEgernNative, egernPrelude)
//   - App/Core/NCRewriteSnapshot.swift (NCResources.get)
//   - PacketTunnel/NativeMitM/Script/ (NativeScriptHost.ManifestEntry, NativeTaskRunner.TaskDef, NativeTaskRunner.PanelDef)
//
// DIVERGENCES:
//   1. Setup JSON Derivation (Stateless Baseline vs Runtime Execution Context):
//      - Go behavior: Go executes `rc := &runCtx{script: sc, name: sc.Name, e: e, wantExport: task}` and calls
//        `rc.setupJSON(nil, nil)`. The method `setupJSON` belongs to Go's live script execution context (`runCtx`),
//        which at runtime in the tunnel also manages request/response HTTP bodies, header clones, and memory blobs.
//      - Swift behavior: `NCScriptManifest` implements a pure, stateless `setupJSON` generator creating `NCJSSetup`.
//        Because export-time invocations always pass `req = nil, resp = nil`, `NCJSSetup` emits the exact baseline schema
//        (`phase: "task"`, `arg`, `env`, `egernEnv`, `egernCron`, `hasParams: false`, without req/resp/globals/params).
//      - Impact: Zero divergence in the exported `nativecore-scripts.json`. The native script host in PacketTunnel
//        (`NativeScriptHost.swift` / `NativeScriptRun.swift`) consumes this static baseline (`e.setupJSON = ss`) and
//        augments HTTP headers/bodies natively during runtime request/response phases.
//
//   2. Resource Management & Script Loading:
//      - Go behavior: Go uses `e.res = NewResources(home, e)` and calls `e.res.Get(sc.Path, sc.UpdateInterval)` to read
//        local script files from `<home>/engine/scripts/` or download remote scripts via Go `net/http` to `<home>/engine/cache/<sha1>`.
//      - Swift behavior: Reuses `NCResources` from `NCRewriteSnapshot.swift` (`res.get(path:maxAge:)`), which reads local
//        files from `<home>/engine/scripts/` or retrieves pre-cached files from `<home>/engine/cache/<sha1>`, fetching
//        via synchronous `URLSession` if absent. Interval overrides from `cfg.scriptResources` are honored.
//      - Impact: Completely equivalent caching and download semantics across all script resources.
//
//   3. Atomic File Persistence:
//      - Go behavior: Writes `*.tmp` and renames using `os.WriteFile` and `os.Rename`.
//      - Swift behavior: Writes data to `*.tmp`, removes existing target file if present, and invokes `FileManager.default.moveItem`.
//      - Impact: Fully atomic write replacement without race conditions or partial file reads on crash.
//
//   4. Error Message Formats:
//      - Go behavior: Formats load failures as `fmt.Errorf("加载脚本失败：%w", err).Error()`.
//      - Swift behavior: Formats as `"加载脚本失败：\(error.localizedDescription)"`.
//      - Impact: Preserves the standard `"加载脚本失败："` prefix expected by UI and tunnel error checkers;
//        records errors on entry (`ent.err`) and increments the `bad` counter while allowing valid scripts to export.
//

import Foundation
import CommonCrypto

// MARK: - Setup Models (mirrors bridge/mitm/script.go jsSetup / jsArg / jsEnv)

struct NCJSArg: Codable, Equatable {
    var has: Bool
    var obj: Bool
    var s: String
}

struct NCJSEnv: Codable, Equatable {
    var surgeVersion: String
    var surgeBuild: String
    var language: String
    var system: String
    var mihomoIOS: Bool

    enum CodingKeys: String, CodingKey {
        case surgeVersion = "surge-version"
        case surgeBuild = "surge-build"
        case language
        case system
        case mihomoIOS = "mihomo-ios"
    }
}

struct NCJSSetup: Codable, Equatable {
    var name: String
    var type: String
    var path: String
    var phase: String
    var echo: Bool
    var binary: Bool
    var export: Bool
    var arg: NCJSArg
    var env: NCJSEnv
    var egernEnv: [String: String]
    var egernCron: String
    var hasParams: Bool

    enum CodingKeys: String, CodingKey {
        case name, type, path, phase, echo, binary, export
        case arg, env, egernEnv, egernCron, hasParams
    }
}

// MARK: - Manifest Entry & Root Models (mirrors bridge/mitm/exportsnap.go)

struct NCScriptManifestEntry: Encodable {
    var i: Int
    var key: String? = nil
    var name: String
    var type: String
    var file: String? = nil
    var timeoutMs: Int64
    var maxSize: Int? = nil
    var setup: NCJSSetup? = nil
    var err: String? = nil

    // Task fields (i = -1 - k)
    var taskId: String? = nil
    var kind: String? = nil
    var cron: String? = nil
    var event: String? = nil
    var off: Bool? = nil
    var format: String? = nil
    var source: String? = nil
    var line: String? = nil
    var path: String? = nil
    var icon: String? = nil

    enum CodingKeys: String, CodingKey {
        case i, key, name, type, file, timeoutMs, maxSize, setup, err
        case taskId, kind, cron, event, off, format, source, line, path, icon
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(i, forKey: .i)
        if let key, !key.isEmpty { try c.encode(key, forKey: .key) }
        try c.encode(name, forKey: .name)
        try c.encode(type, forKey: .type)
        if let file, !file.isEmpty { try c.encode(file, forKey: .file) }
        try c.encode(timeoutMs, forKey: .timeoutMs)
        if let maxSize, maxSize > 0 { try c.encode(maxSize, forKey: .maxSize) }
        if let setup { try c.encode(setup, forKey: .setup) }
        if let err, !err.isEmpty { try c.encode(err, forKey: .err) }
        if let taskId, !taskId.isEmpty { try c.encode(taskId, forKey: .taskId) }
        if let kind, !kind.isEmpty { try c.encode(kind, forKey: .kind) }
        if let cron, !cron.isEmpty { try c.encode(cron, forKey: .cron) }
        if let event, !event.isEmpty { try c.encode(event, forKey: .event) }
        if let off, off { try c.encode(off, forKey: .off) }
        if let format, !format.isEmpty { try c.encode(format, forKey: .format) }
        if let source, !source.isEmpty { try c.encode(source, forKey: .source) }
        if let line, !line.isEmpty { try c.encode(line, forKey: .line) }
        if let path, !path.isEmpty { try c.encode(path, forKey: .path) }
        if let icon, !icon.isEmpty { try c.encode(icon, forKey: .icon) }
    }
}

struct NCScriptManifestRoot: Encodable {
    var version: Int = 1
    var scripts: [NCScriptManifestEntry] = []
    var tasks: [NCScriptManifestEntry] = []
    var panels: [NCEnginePanel] = []

    enum CodingKeys: String, CodingKey {
        case version, scripts, tasks, panels
    }
}

// MARK: - NCScriptManifest

enum NCScriptManifest {
    static let scriptManifestFile = "nativecore-scripts.json"
    static let scriptManifestDir = "nativecore-scripts"

    /// Regex for detecting native Egern scripts (export default async function(ctx)).
    static let egernExportRe = try! NSRegularExpression(pattern: #"^[ \t]*export[ \t]+default[ \t]+"#, options: [.anchorsMatchLines])
    /// Regex for detecting disallowed Egern syntax (import or multiple exports).
    static let egernImportRe = try! NSRegularExpression(pattern: #"^[ \t]*(import[ \t{*'"]|export[ \t]+(const|let|var|function|class|\{))"#, options: [.anchorsMatchLines])

    /// Checks if code uses Egern native module syntax.
    static func isEgernNative(_ code: String) -> Bool {
        let range = NSRange(code.startIndex..., in: code)
        return egernExportRe.firstMatch(in: code, range: range) != nil
    }

    /// Adapts an Egern native script into a Surge-compatible script.
    static func adaptEgern(_ code: String) throws -> String {
        let range = NSRange(code.startIndex..., in: code)
        if egernImportRe.firstMatch(in: code, range: range) != nil {
            throw NSError(domain: "NCScriptManifest", code: -1, userInfo: [NSLocalizedDescriptionKey: "Egern 脚本使用了 import 或多个 export，只支持单文件 export default 函数"])
        }
        guard let m = egernExportRe.firstMatch(in: code, range: range),
              let r = Range(m.range, in: code) else {
            throw NSError(domain: "NCScriptManifest", code: -1, userInfo: [NSLocalizedDescriptionKey: "没有找到 export default"])
        }
        let prefix = String(code[..<r.lowerBound])
        let suffix = String(code[r.upperBound...])
        return prefix + "var __egernMain = " + suffix + "\n;\n" + egernPrelude
    }

    /// Strips BOM and adapts Egern scripts (bridge/mitm/script.go scriptCode).
    static func scriptCode(_ src: Data) throws -> String {
        var code = String(decoding: src, as: UTF8.self)
        if code.hasPrefix("\u{FEFF}") {
            code.removeFirst()
        }
        if isEgernNative(code) {
            return try adaptEgern(code)
        }
        return code
    }

    /// Computes timeout in milliseconds (bridge/mitm/script.go scriptTimeout).
    static func scriptTimeout(sc: NCEngineScript, maxTimeoutMs: Int64, defTimeoutMs: Int64) -> Int64 {
        var timeoutMs = Int64(sc.timeout) * 1000
        if timeoutMs <= 0 {
            timeoutMs = defTimeoutMs
        }
        if timeoutMs > maxTimeoutMs {
            timeoutMs = maxTimeoutMs
        }
        return timeoutMs
    }

    /// Generates static base setup for __tern_begin (bridge/mitm/script.go setupJSON(nil, nil)).
    static func setupJSON(script sc: NCEngineScript, cfg: NCEngineConfig?, isTask: Bool) -> (setup: NCJSSetup?, err: String?) {
        let arg = NCJSArg(has: sc.hasArgument, obj: sc.argObject, s: sc.argument)
        let env = NCJSEnv(
            surgeVersion: "5.20.0",
            surgeBuild: "3000",
            language: cfg?.scriptLanguage ?? "zh-Hans",
            system: "iOS",
            mihomoIOS: true
        )
        let setup = NCJSSetup(
            name: sc.name,
            type: sc.type,
            path: sc.path,
            phase: "task",
            echo: sc.echo,
            binary: sc.binaryBody,
            export: isTask,
            arg: arg,
            env: env,
            egernEnv: sc.env,
            egernCron: sc.cron,
            hasParams: false
        )
        return (setup, nil)
    }

    /// Writes nativecore-scripts.json + the code files for rs (removing code files no rule uses any more).
    /// Returns (scripts count, unloadable scripts count); throws on manifest or script write failure.
    /// When cfg or rs is nil, writes an empty manifest and cleans up stale code files.
    public static func export(home: String, cfg: NCEngineConfig?, rs: NCEngineRuleset?) throws -> (scripts: Int, bad: Int) {
        let built = try buildManifest(home: home, cfg: cfg, rs: rs)
        try NCRuntimeFiles.writeAtomic(built.data, to: (home as NSString).appendingPathComponent(scriptManifestFile))
        removeObsoleteCode(home: home, keep: built.keep)
        return (scripts: built.scripts, bad: built.bad)
    }

    /// rv2 (transactional native prep): builds the manifest bytes WITHOUT writing nativecore-scripts.json and
    /// without deleting code files. Content-addressed code files (`nativecore-scripts/nc-<sha>.js`) are still
    /// written here — they are additive (a new hash never replaces a file the live manifest uses). The caller
    /// commits the manifest and then calls `removeObsoleteCode(home:keep:)` once the new manifest is live; doing
    /// the cleanup earlier deleted code files the still-live old manifest referenced when a later step failed.
    static func buildManifest(home: String, cfg: NCEngineConfig?, rs: NCEngineRuleset?) throws -> (data: Data, keep: Set<String>, scripts: Int, bad: Int) {
        let dir = (home as NSString).appendingPathComponent(scriptManifestDir)
        var man = NCScriptManifestRoot()
        var keep = Set<String>()
        var bad = 0
        let fm = FileManager.default

        if let cfg, let rs {
            let res = NCResources(home: home)

            func build(i: Int, sc: NCEngineScript, isTask: Bool) throws -> NCScriptManifestEntry {
                let maxT: Int64 = isTask ? 300_000 : 120_000
                let defT: Int64 = isTask ? 30_000 : 10_000
                let timeoutMs = scriptTimeout(sc: sc, maxTimeoutMs: maxT, defTimeoutMs: defT)
                var ent = NCScriptManifestEntry(
                    i: i,
                    name: sc.name,
                    type: sc.type,
                    timeoutMs: timeoutMs,
                    maxSize: sc.maxSize > 0 ? sc.maxSize : nil
                )

                let (setup, setupErr) = setupJSON(script: sc, cfg: cfg, isTask: isTask)
                if let setup {
                    ent.setup = setup
                } else if let setupErr {
                    ent.err = setupErr
                }

                var src = sc.source
                if src == nil && (ent.err == nil || ent.err!.isEmpty) {
                    do {
                        let interval = cfg.scriptResources?[sc.path]?.interval
                        let updateInterval = (interval != nil && interval! > 0) ? interval! : sc.updateInterval
                        src = try res.get(path: sc.path, maxAge: updateInterval)
                    } catch {
                        ent.err = "加载脚本失败：\(error.localizedDescription)"
                    }
                }

                if ent.err == nil || ent.err!.isEmpty {
                    if let src {
                        do {
                            let code = try scriptCode(src)
                            var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
                            let codeBytes = Array(code.utf8)
                            CC_SHA256(codeBytes, CC_LONG(codeBytes.count), &hash)
                            let hex12 = hash.prefix(12).map { String(format: "%02x", $0) }.joined()
                            let key = "nc-" + hex12
                            ent.key = key
                            let relFile = (scriptManifestDir as NSString).appendingPathComponent("\(key).js")
                            ent.file = relFile

                            if !keep.contains(key) {
                                try fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: nil)
                                let p = (home as NSString).appendingPathComponent(relFile)
                                if !fm.fileExists(atPath: p) {
                                    try NCRuntimeFiles.writeAtomic(Data(code.utf8), to: p)
                                }
                                keep.insert(key)
                            }
                        } catch {
                            ent.err = error.localizedDescription
                        }
                    } else {
                        ent.err = "加载脚本失败：无脚本内容"
                    }
                }

                if let err = ent.err, !err.isEmpty {
                    bad += 1
                }
                return ent
            }

            for (i, r) in rs.rules.enumerated() {
                guard r.kind == "script", let sc = r.script else { continue }
                let ent = try build(i: i, sc: sc, isTask: false)
                man.scripts.append(ent)
            }

            for (k, tk) in rs.tasks.enumerated() {
                guard let sc = tk.script else { continue }
                var ent = try build(i: -1 - k, sc: sc, isTask: true)
                ent.taskId = tk.id.isEmpty ? nil : tk.id
                ent.kind = tk.kind.isEmpty ? nil : tk.kind
                ent.cron = tk.cron
                ent.event = tk.event
                ent.off = tk.disabledByLine ? true : nil
                ent.format = tk.format.isEmpty ? nil : tk.format
                ent.source = tk.source.isEmpty ? nil : tk.source
                ent.line = tk.line.isEmpty ? nil : tk.line
                ent.path = (sc.path.isEmpty ? (tk.path.isEmpty ? nil : tk.path) : sc.path)
                ent.icon = tk.icon.isEmpty ? nil : tk.icon
                man.tasks.append(ent)
            }

            for p in rs.panels {
                man.panels.append(p)
            }
        }

        let b = try JSONEncoder().encode(man)
        return (data: b, keep: keep, scripts: man.scripts.count, bad: bad)
    }

    /// Removes code files in `nativecore-scripts/` that `keep` (the live manifest's keys) does not reference.
    static func removeObsoleteCode(home: String, keep: Set<String>) {
        let fm = FileManager.default
        let dir = (home as NSString).appendingPathComponent(scriptManifestDir)
        if let items = try? fm.contentsOfDirectory(atPath: dir) {
            for n in items {
                if n.hasSuffix(".js") {
                    let key = String(n.dropLast(".js".count))
                    if !keep.contains(key) {
                        let full = (dir as NSString).appendingPathComponent(n)
                        _ = try? fm.removeItem(atPath: full)
                    }
                }
            }
        }
    }

    // MARK: - Egern Prelude (bridge/mitm/egernadapter.go egernPrelude)

    static let egernPrelude: String = #"""
(function () {
  var hasReq = typeof $request !== 'undefined' && $request;
  var hasResp = typeof $response !== 'undefined' && $response;
  function lc(k) { return String(k).toLowerCase(); }
  var TO_OBJECT = typeof Symbol === 'function' ? Symbol('toObject') : '__egernToObject';
  function makeHeaders(src) {
    var map = {};
    function put(k, v) {
      var e = map[lc(k)];
      if (!e) { e = map[lc(k)] = { name: String(k), values: [] }; }
      e.values.push(String(v));
    }
    if (src) {
      var keys = Object.keys(src);
      for (var i = 0; i < keys.length; i++) {
        var v = src[keys[i]];
        if (v === undefined || v === null) continue;
        if (Array.isArray(v)) { for (var j = 0; j < v.length; j++) put(keys[i], v[j]); } else put(keys[i], v);
      }
    }
    var api = {
      get: function (n) { var e = map[lc(n)]; return e ? e.values.join(', ') : null; },
      getAll: function (n) { var e = map[lc(n)]; return e ? e.values.slice() : []; },
      has: function (n) { return !!map[lc(n)]; },
      set: function (n, v) { map[lc(n)] = { name: String(n), values: [String(v)] }; },
      append: function (n, v) { put(n, v); },
      delete: function (n) { delete map[lc(n)]; },
      forEach: function (fn) { for (var k in map) fn(map[k].values.join(', '), map[k].name); },
      toObject: function () {
        var o = {};
        for (var k in map) { var e = map[k]; o[e.name] = e.values.length > 1 ? e.values.slice() : e.values[0]; }
        return o;
      }
    };
    // r7 B30: a header named like a method (get / set / has / append / delete / forEach / toObject) is
    // what property access returns; the methods are what is left when no such header exists. The adapter
    // itself reaches toObject through a symbol, so such a header never breaks the conversion back.
    api[TO_OBJECT] = api.toObject;
    return new Proxy(api, {
      get: function (t, p) {
        if (typeof p !== 'string') return t[p];
        var e = map[lc(p)];
        if (e) return e.values.length > 1 ? e.values.slice() : e.values[0];
        return p in t ? t[p] : undefined;
      },
      set: function (t, p, v) { api.set(p, v); return true; },
      deleteProperty: function (t, p) { api.delete(p); return true; },
      has: function (t, p) { return (p in t) || !!map[lc(p)]; },
      ownKeys: function () { return Object.keys(map).map(function (k) { return map[k].name; }); },
      getOwnPropertyDescriptor: function (t, p) {
        var e = map[lc(p)];
        if (!e) return undefined;
        return { value: e.values.length > 1 ? e.values.slice() : e.values[0], enumerable: true, configurable: true, writable: true };
      }
    });
  }
  function toBytes(b) {
    if (b === undefined || b === null) return new Uint8Array(0);
    if (typeof b === 'string') return new TextEncoder().encode(b);
    if (b instanceof ArrayBuffer) return new Uint8Array(b);
    return b;
  }
  function withBody(target, raw) {
    target.body = raw === undefined ? null : raw;
    target.text = function () {
      if (raw === undefined || raw === null) return Promise.resolve('');
      if (typeof raw === 'string') return Promise.resolve(raw);
      return Promise.resolve(new TextDecoder().decode(toBytes(raw)));
    };
    target.json = function () { return target.text().then(function (t) { return JSON.parse(t); }); };
    target.arrayBuffer = function () { var u = toBytes(raw); return Promise.resolve(u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength)); };
    target.bytes = function () { return Promise.resolve(toBytes(raw)); };
    return target;
  }
  function plainHeaders(h) {
    if (!h) return undefined;
    if (typeof h[TO_OBJECT] === 'function') return h[TO_OBJECT]();
    if (typeof h.toObject === 'function') return h.toObject();
    return h;
  }
  // v0.19.22: Egern scripts build request headers with the Fetch API's global Headers constructor
  // (new Headers({...}), also an array of pairs or another Headers); it was missing.
  if (typeof globalThis.Headers === 'undefined') {
    globalThis.Headers = function Headers(init) {
      if (init && typeof init[TO_OBJECT] === 'function') return makeHeaders(init[TO_OBJECT]());
      if (Array.isArray(init)) {
        var h = makeHeaders(null);
        for (var i = 0; i < init.length; i++) h.append(init[i][0], init[i][1]);
        return h;
      }
      return makeHeaders(init);
    };
  }
  function bodyOut(b) {
    if (b === undefined || b === null) return undefined;
    if (typeof b === 'string' || b instanceof Uint8Array || b instanceof ArrayBuffer) return b;
    return JSON.stringify(b);
  }
  function http(method) {
    return function (url, opts) {
      opts = opts || {};
      return new Promise(function (resolve, reject) {
        var req = { url: url, headers: plainHeaders(opts.headers) || {}, 'binary-mode': true };
        var b = opts.body;
        if (b !== undefined && b !== null) {
          if (typeof b === 'object' && !(b instanceof Uint8Array) && !(b instanceof ArrayBuffer)) {
            b = JSON.stringify(b);
            var ct = false;
            for (var k in req.headers) if (lc(k) === 'content-type') ct = true;
            if (!ct) req.headers['Content-Type'] = 'application/json';
          }
          req.body = b;
        }
        if (opts.timeout) req.timeout = opts.timeout / 1000;
        if (opts.policy) req.policy = opts.policy;
        if (opts.redirect === 'manual' || opts.redirect === 'error') req['auto-redirect'] = false;
        if (opts.insecureTls) req.insecure = true;
        $httpClient[method](req, function (err, resp, data) {
          if (err) { reject(new Error(String(err))); return; }
          var status = resp ? (resp.status || resp.statusCode) : 0;
          if (opts.redirect === 'error' && status >= 300 && status < 400) { reject(new Error('redirect')); return; }
          resolve(withBody({ status: status, headers: makeHeaders(resp ? resp.headers : {}) }, data));
        });
      });
    };
  }
  var device = { cellular: { carrier: null, radio: null }, wifi: { ssid: null, bssid: null },
    ipv4: { address: null, gateway: null, interface: null }, ipv6: { address: null, interface: null }, dnsServers: [] };
  if (typeof $network !== 'undefined' && $network) {
    var v4 = $network.v4 || {}, v6 = $network.v6 || {};
    device.ipv4 = { address: v4.primaryAddress || null, gateway: v4.primaryRouter || null, interface: v4.primaryInterface || null };
    device.ipv6 = { address: v6.primaryAddress || null, interface: v6.primaryInterface || null };
    device.dnsServers = $network.dns || [];
  }
  var ctx = {
    script: { name: (typeof $script !== 'undefined' && $script) ? $script.name : '' },
    env: __egernEnv,
    app: { version: '0.6', language: 'zh-Hans' },
    device: device,
    cron: __egernCron || undefined,
    http: {
      get: http('get'), post: http('post'), put: http('put'), delete: http('delete'),
      head: http('head'), options: http('options'), patch: http('patch')
    },
    storage: {
      get: function (k) { var v = $persistentStore.read(k); return v === undefined ? null : v; },
      set: function (k, v) { $persistentStore.write(String(v), k); },
      getJSON: function (k) { var v = $persistentStore.read(k); if (v === undefined || v === null || v === '') return null; try { return JSON.parse(v); } catch (e) { return null; } },
      setJSON: function (k, v) { $persistentStore.write(JSON.stringify(v), k); },
      delete: function (k) { $persistentStore.write(null, k); }
    },
    notify: function (o) {
      o = o || {};
      var opts;
      if (o.action && o.action.type === 'openUrl') opts = { url: o.action.url };
      $notification.post(o.title || '', o.subtitle || '', o.body || '', opts);
    },
    lookupIP: function (ip) {
      var c = $utils.geoip(ip), a = $utils.ipasn(ip), org = $utils.ipaso(ip);
      if (!c && !a && !org) return null;
      return { country: c || '', asn: a ? Number(a) : 0, organization: org || '' };
    },
    compress: {
      gzip: function (d) { return Promise.resolve(__egernCompress('gzip', d)); },
      gunzip: function (d) { return Promise.resolve(__egernCompress('gunzip', d)); },
      deflate: function (d) { return Promise.resolve(__egernCompress('deflate', d)); },
      inflate: function (d) { return Promise.resolve(__egernCompress('inflate', d)); },
      brotli: function (d) { return Promise.resolve(__egernCompress('brotli', d)); },
      unbrotli: function (d) { return Promise.resolve(__egernCompress('unbrotli', d)); }
    },
    ssh: { connect: function () { return Promise.reject(new Error('ctx.ssh 不支持')); } },
    respond: function (r) { return { __egernRespond: r || {} }; },
    abort: function () { return { __egernAbort: true }; }
  };
  if (hasReq) {
    ctx.request = withBody({ method: $request.method, url: $request.url, headers: makeHeaders($request.headers) }, hasResp ? undefined : $request.body);
  }
  if (hasResp) {
    ctx.response = withBody({ status: $response.status, headers: makeHeaders($response.headers) }, $response.body);
  }
  function texts(node, out) {
    if (!node || typeof node !== 'object') return out;
    if (typeof node.text === 'string' && node.text !== '') out.push(node.text);
    var ch = node.children || [];
    for (var i = 0; i < ch.length; i++) texts(ch[i], out);
    return out;
  }
  function finish(ret) {
    if (ret && ret.__egernAbort) { $done({ __egernAbort: true }); return; }
    if (hasReq && !hasResp) {
      if (ret && ret.__egernRespond) {
        var r = ret.__egernRespond;
        $done({ response: { status: r.status || 200, headers: plainHeaders(r.headers) || {}, body: bodyOut(r.body) } });
        return;
      }
      if (!ret) { $done({}); return; }
      var o = {};
      if (ret.url) o.url = ret.url;
      if (ret.method) o.method = ret.method;
      if (ret.headers) o.headers = plainHeaders(ret.headers);
      if (ret.body !== undefined) o.body = bodyOut(ret.body);
      $done(o);
      return;
    }
    if (hasResp) {
      if (!ret) { $done({}); return; }
      // v0.19.4: ctx.respond() in a response script replaces the response (was ignored).
      if (ret.__egernRespond) {
        var rr = ret.__egernRespond, q = { status: rr.status || 200 };
        if (rr.headers) q.headers = plainHeaders(rr.headers);
        q.body = rr.body === undefined || rr.body === null ? '' : bodyOut(rr.body);
        $done(q);
        return;
      }
      var p = {};
      if (ret.status) p.status = ret.status;
      if (ret.headers) p.headers = plainHeaders(ret.headers);
      if (ret.body !== undefined) p.body = bodyOut(ret.body);
      $done(p);
      return;
    }
    // generic (panel): widget DSL -> title / content; schedule / network: nothing
    if (ret && ret.type === 'widget') {
      var t = texts(ret, []);
      var pn = { title: t[0] || '', content: t.slice(1).join('\n') };
      if (ret.backgroundColor) pn.backgroundColor = ret.backgroundColor;
      $done(pn);
      return;
    }
    $done(ret && typeof ret === 'object' ? ret : {});
  }
  var run;
  try { run = Promise.resolve(__egernMain(ctx)); } catch (e) { run = Promise.reject(e); }
  run.then(finish, function (e) {
    console.error('Egern 脚本异常：' + (e && e.stack ? e.stack : String(e)));
    $done({});
  });
})();
"""#
}
