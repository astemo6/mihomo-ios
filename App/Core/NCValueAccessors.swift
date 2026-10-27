import CryptoKit
import Foundation

/// nc-integrate: the bridge's loose accessors
/// over NCJSONValue, for the ports that read YAML trees the way the old code read map[string]any.
/// str(): default text of a scalar (YAML ints print without a fraction); intOf(): number or numeric string;
/// boolOf(): a bool or a truthy string ("1", "true", "yes", "on").

func ncStr(_ v: NCJSONValue?) -> String {
    switch v {
    case .string(let s)?: return s
    case .bool(let b)?: return b ? "true" : "false"
    case .number(let d)?:
        if d.isFinite, d == d.rounded(), abs(d) < 1e15 { return String(Int64(d)) }
        return String(d)
    default: return ""
    }
}

func ncTruthy(_ s: String) -> Bool {
    switch s.trimmingCharacters(in: .whitespaces).lowercased() {
    case "1", "true", "yes", "on": return true
    default: return false
    }
}

func ncBool(_ v: NCJSONValue?) -> Bool {
    switch v {
    case .bool(let b)?: return b
    case .string(let s)?: return ncTruthy(s)
    default: return false
    }
}

func ncInt(_ v: NCJSONValue?) -> Int {
    switch v {
    // the old core's int(float64) never traps; Swift's Int(Double) does at |d| ≥ 2^63 (Double(Int.max) is 2^63, so `<`).
    case .number(let d)?: return d.isFinite && d >= Double(Int.min) && d < Double(Int.max) ? Int(d) : 0
    case .string(let s)?: return Int(s.trimmingCharacters(in: .whitespaces)) ?? 0
    default: return 0
    }
}

/// bridge strList: the non-empty scalar entries of a list.
func ncStrList(_ v: NCJSONValue?) -> [String] {
    guard case .array(let a)? = v else { return [] }
    return a.compactMap { let s = ncStr($0); return s.isEmpty ? nil : s }
}

/// bridge proxiesOf: the map entries of raw["proxies"].
func ncProxiesOf(_ raw: [String: NCJSONValue]) -> [[String: NCJSONValue]] {
    guard case .array(let a)? = raw["proxies"] else { return [] }
    return a.compactMap { $0.object }
}

/// JSON text of a JSON-shaped value (sorted keys so outputs are stable); "" when it cannot be encoded.
func ncJSONString(_ any: Any) -> String {
    guard JSONSerialization.isValidJSONObject(any),
          let d = try? JSONSerialization.data(withJSONObject: any, options: [.sortedKeys]) else { return "" }
    return String(decoding: d, as: UTF8.self)
}

/// bridge providerCache — the file Clash.Meta reads for a provider: `path` resolved against the home
/// (C.Path.Resolve), else C.Path.GetPathByHash(prefix, url) = <home>/<rules|proxies>/<hex md5(url)> (Clash.Meta
/// utils.MakeHash(...).String() is the MD5 hex). The url is the runtime one (mirrored / convert URL), as in the old core.
func ncProviderCachePath(home: String, kind: String, _ m: [String: NCJSONValue]) -> String {
    let p = ncStr(m["path"])
    if !p.isEmpty {
        if p.hasPrefix("/") {
            // fix/nc-0.20.2: an absolute path from an older install's container (delete + reinstall, re-signed build)
            // is rebased under the current home; one already inside home is kept.
            if let r = NCPathContainment.rebaseForeignAbsolute(home: home, p, fallbackDir: kind == "rule" ? "rules" : "proxies") {
                return (home as NSString).appendingPathComponent(r)
            }
            return p
        }
        return (home as NSString).appendingPathComponent(p)
    }
    let u = ncStr(m["url"])
    if !u.isEmpty {
        let hex = Insecure.MD5.hash(data: Data(u.utf8)).ncHex
        return (home as NSString).appendingPathComponent(kind == "rule" ? "rules" : "proxies") + "/" + hex
    }
    return ""
}
