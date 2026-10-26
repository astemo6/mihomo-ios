import Foundation

/// B10 (nc-dego-rest): bridge/diagbundle.go WriteDiagnosticBundle + diagnosticFiles in Swift. Builds the same
/// redacted file set (configs first so every secret is known, then the logs) and writes it as one zip with
/// NCZipWriter, entries under "mihomo-diagnostics/", sorted by name, DEFLATE.
///
/// Not included compared with Go: resources.json (bridge ResourceList, B4 — no Swift port yet).
extension DiagnosticSummary {

    enum BundleError: Error, LocalizedError {
        case noHome
        var errorDescription: String? { "没有工作目录" }
    }

    /// bridge diagnosticFiles: name → redacted content.
    static func bundleFiles(home: String, profilePath: String, appInfo: String,
                            cachedModuleInfo: [String: ParsedEngineText]? = nil) throws -> [String: String] {
        guard !home.isEmpty else { throw BundleError.noHome }
        let container = (home as NSString).deletingLastPathComponent
        let r = DiagnosticRedactor()
        r.collectConfigs(home: home, profilePath: profilePath)
        var out: [String: String] = [:]

        // 1. configs (also teach the redactor every secret)
        let runtimeURL = URL(fileURLWithPath: home).appendingPathComponent("runtime.yaml")
        var effective = "（还没有成功启动过：runtime.yaml 不存在）\n"
        if let b = try? Data(contentsOf: runtimeURL) {
            let mod = (try? FileManager.default.attributesOfItem(atPath: runtimeURL.path)[.modificationDate]) as? Date ?? Date()
            effective = "# 上次启动时实际使用的配置（\(rfc3339(mod))），已脱敏\n" + yamlText(r, b)
        }
        let nextRun: String
        if !profilePath.isEmpty {
            if let prof = NCRuntimeFiles.readRuntimeProfile(home: home, path: profilePath, safe: false) {
                let req = NCRuntimeBuilder.Request.load(home: home, profilePath: profilePath)
                do {
                    let built = try NCRuntimeBuilder.build(profile: prof, req: req, fd: 0)
                    nextRun = "# 当前配置 + 覆写在下次连接时生成的配置（不含 tun 与 MitM 注入），已脱敏\n"
                        + NCYAMLEmitter.emit(NCJSONValue.object(r.config(built.raw)))
                } catch let e as NCRuntimeBuilder.BuildError {
                    nextRun = "生成运行配置失败：" + e.message
                } catch {
                    nextRun = "生成运行配置失败：" + error.localizedDescription
                }
            } else {
                nextRun = "读取配置失败：" + (profilePath as NSString).lastPathComponent
            }
        } else {
            nextRun = "（没有选中的配置）"
        }
        out["config-effective.yaml"] = effective
        out["config-next-start.yaml"] = nextRun
        for f in ["overrides.json", "dns.json", "localdns.json", "group-icons.json", "rules.json", "subscriptions.json",
                  "groups.json", "resources-state.json"] {
            if let b = try? Data(contentsOf: URL(fileURLWithPath: home).appendingPathComponent(f)) {
                out["settings/" + f] = jsonText(r, b, section: "")
            }
        }
        if let b = try? Data(contentsOf: URL(fileURLWithPath: container).appendingPathComponent("profiles.json")) {
            out["settings/profiles.json"] = jsonText(r, b, section: "profiles")
        }
        out["geo.json"] = NCGeoStore.info(homeDir: home)

        // 2. logs + info + modules (after the configs so every secret is known)
        for (k, v) in sectionFiles(home: home, appInfo: appInfo, cachedModuleInfo: cachedModuleInfo, redactor: r) {
            out[k] = v
        }
        out["README.txt"] = "Mihomo iOS 诊断包\n\n" +
            "selfcheck.txt         最近一次「一键自检」的结果（有才包含）\n" +
            "info.txt              App / 扩展 / 内核版本、App Group、VPN 状态\n" +
            "startup-log.txt       启动阶段日志（本次 + 上一次）\n" +
            "last-error.txt        扩展最近一次写下的错误\n" +
            "core-log.txt          内核最近日志（最多 400 行）\n" +
            "memory.txt            扩展内存采样（每 10 秒，最多 30 分钟）\n" +
            "modules.txt           模块、重写、脚本、MitM 开关与数量\n" +
            "config-effective.yaml 上次启动实际使用的配置\n" +
            "config-next-start.yaml 下次连接会使用的配置\n" +
            "settings/             覆写、DNS、自定义规则、订阅处理等设置\n\n" +
            "已脱敏：服务器地址、密码、UUID、密钥、订阅链接、令牌、公网 IP 后两段。\n"
        return out
    }

    /// bridge WriteDiagnosticBundle: the redacted files as a zip at outPath.
    static func writeBundle(home: String, profilePath: String, appInfo: String, outPath: String,
                            cachedModuleInfo: [String: ParsedEngineText]? = nil) throws {
        let files = try bundleFiles(home: home, profilePath: profilePath, appInfo: appInfo, cachedModuleInfo: cachedModuleInfo)
        var zip = NCZipWriter()
        let now = Date()
        for name in files.keys.sorted() {
            zip.add(name: "mihomo-diagnostics/" + name, contents: Data((files[name] ?? "").utf8), modified: now)
        }
        let url = URL(fileURLWithPath: outPath)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try zip.finish().write(to: url, options: .atomic)
    }

    // MARK: helpers

    private static func rfc3339(_ d: Date) -> String {
        let f = ISO8601DateFormatter()
        f.timeZone = .current
        return f.string(from: d)
    }

    /// bridge redactor.yamlText.
    private static func yamlText(_ r: DiagnosticRedactor, _ b: Data) -> String {
        let text = String(decoding: b, as: UTF8.self)
        guard case .object(let raw)? = NCYAML.parse(text) else {
            return "# YAML 解析失败，按文本脱敏\n" + r.text(text)
        }
        return NCYAMLEmitter.emit(NCJSONValue.object(r.config(raw)))
    }

    /// bridge redactor.jsonText: values redacted, indented JSON (sorted keys), then the text pass.
    private static func jsonText(_ r: DiagnosticRedactor, _ b: Data, section: String) -> String {
        guard let obj = try? JSONSerialization.jsonObject(with: b, options: [.fragmentsAllowed]) else {
            return r.text(String(decoding: b, as: UTF8.self))
        }
        let red = r.value(NCJSONValue(obj), key: "", section: section)
        guard let d = try? JSONSerialization.data(withJSONObject: red.anyTree,
                                                  options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes, .fragmentsAllowed]) else {
            return r.text(String(decoding: b, as: UTF8.self))
        }
        return r.text(String(decoding: d, as: UTF8.self) + "\n")
    }
}
