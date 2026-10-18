import Foundation

/// test/selftest: the Go side (bridge/mitm describe(), bridge/resources.go details, provider summaries) builds
/// its short descriptions in Chinese. This maps those fixed shapes to the UI language; anything unknown is
/// shown as it came (user-written names, rule text).
enum GoText {
    private static func re(_ p: String) -> NSRegularExpression { try! NSRegularExpression(pattern: "^" + p + "$") }
    private static func groups(_ r: NSRegularExpression, _ s: String) -> [String]? {
        let ns = s as NSString
        guard let m = r.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (1..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }

    private static let redirect = re("(30[27]) 重定向 → (.*)")
    private static let rewriteURL = re("改写 URL → (.*)")
    private static let header = re("(请求头|响应头)(添加|删除|替换|正则替换|设置) (.*)")
    private static let body = re("(请求体|响应体)替换（(\\d+) 组）")
    private static let json = re("JSON 改写（(\\d+) 项）")
    private static let mapLocal = re("本地映射（(.*)）")
    private static let core = re("内核规则：(.*)")
    private static let rulesHosts = re("(\\d+) 条规则/脚本 · (\\d+) 个主机")
    private static let rulesOnly = re("(\\d+) 条规则/脚本")
    private static let hostsOnly = re("(\\d+) 个主机")
    private static let rulesHostsComma = re("(\\d+) 条规则/脚本，(\\d+) 个主机")
    private static let nodes = re("(\\d+) 个节点")
    private static let entries = re("(\\d+) 条")

    /// One whole description; " · " separated parts are translated one by one.
    static func localize(_ s: String) -> String {
        if s.contains(" · ") {
            return s.components(separatedBy: " · ").map(part).joined(separator: " · ")
        }
        return part(s)
    }

    private static func part(_ s: String) -> String {
        if let g = groups(redirect, s) { return String(localized: "\(g[0]) 重定向 → \(g[1])") }
        if let g = groups(rewriteURL, s) { return String(localized: "改写 URL → \(g[0])") }
        if let g = groups(header, s) {
            let resp = g[0] == "响应头"
            switch g[1] {
            case "添加": return resp ? String(localized: "响应头添加 \(g[2])") : String(localized: "请求头添加 \(g[2])")
            case "删除": return resp ? String(localized: "响应头删除 \(g[2])") : String(localized: "请求头删除 \(g[2])")
            case "替换": return resp ? String(localized: "响应头替换 \(g[2])") : String(localized: "请求头替换 \(g[2])")
            case "正则替换": return resp ? String(localized: "响应头正则替换 \(g[2])") : String(localized: "请求头正则替换 \(g[2])")
            default: return resp ? String(localized: "响应头设置 \(g[2])") : String(localized: "请求头设置 \(g[2])")
            }
        }
        if let g = groups(body, s), let n = Int(g[1]) {
            return g[0] == "响应体" ? String(localized: "响应体替换（\(n) 组）") : String(localized: "请求体替换（\(n) 组）")
        }
        if let g = groups(json, s), let n = Int(g[0]) { return String(localized: "JSON 改写（\(n) 项）") }
        if let g = groups(mapLocal, s) { return String(localized: "本地映射（\(g[0])）") }
        if let g = groups(core, s) { return String(localized: "内核规则：\(g[0])") }
        if let g = groups(rulesHosts, s), let a = Int(g[0]), let b = Int(g[1]) {
            return String(localized: "\(a) 条规则/脚本") + " · " + String(localized: "\(b) 个主机")
        }
        // localize() splits on " · " first, so the halves of "n 条规则/脚本 · m 个主机" arrive one by one.
        if let g = groups(rulesOnly, s), let n = Int(g[0]) { return String(localized: "\(n) 条规则/脚本") }
        if let g = groups(hostsOnly, s), let n = Int(g[0]) { return String(localized: "\(n) 个主机") }
        if let g = groups(rulesHostsComma, s), let a = Int(g[0]), let b = Int(g[1]) {
            return String(localized: "\(a) 条规则/脚本") + ", " + String(localized: "\(b) 个主机")
        }
        if let g = groups(nodes, s), let n = Int(g[0]) { return String(localized: "\(n) 个节点") }
        if let g = groups(entries, s), let n = Int(g[0]) { return String(localized: "\(n) 条") }
        // v0.18 Tailscale guard messages (numbers vary; the detailed readout is in 诊断 → 隧道内存).
        if s.hasPrefix("Tailscale 未启动：") { return String(localized: "Tailscale 未启动：隧道扩展可用内存不足，继续启动可能让系统直接终止 VPN。详见 更多 → 诊断 → 隧道内存。") }
        if s.hasPrefix("Tailscale 已停止：") { return String(localized: "Tailscale 已停止：隧道扩展可用内存过低，为避免 VPN 被系统终止已关闭 Tailscale。重新连接后可再次使用。") }
        // v0.19 覆写脚本: the core's prefix in Chinese, mihomo's own message (English) after it.
        if s.hasPrefix("脚本输出的配置校验失败: ") { return String(localized: "脚本输出的配置校验失败：\(String(s.dropFirst("脚本输出的配置校验失败: ".count)))") }
        if s.hasPrefix("脚本返回的不是配置对象: ") { return String(localized: "脚本返回的不是配置对象：\(String(s.dropFirst("脚本返回的不是配置对象: ".count)))") }
        if s.hasPrefix("读取配置失败: ") { return String(localized: "读取配置失败：\(String(s.dropFirst("读取配置失败: ".count)))") }
        // feat/group-order reorder errors (bridge/grouporder.go groupsSeq / seqNames).
        if s.hasPrefix("策略组「"), s.hasSuffix("」重名") {
            let name = String(s.dropFirst("策略组「".count).dropLast("」重名".count))
            return String(localized: "策略组「\(name)」重名")
        }
        switch s {
        case "配置文件不是 YAML 映射": return String(localized: "配置文件不是 YAML 映射")
        case "策略组条目格式无法识别（锚点或非映射条目）": return String(localized: "策略组条目格式无法识别（锚点或非映射条目）")
        case "有策略组缺少名称": return String(localized: "有策略组缺少名称")
        case "副本已手动修改": return String(localized: "副本已手动修改")
        case "配置在脚本运行期间已改变，请重新运行": return String(localized: "配置在脚本运行期间已改变，请重新运行")
        case "脚本返回了空配置": return String(localized: "脚本返回了空配置")
        case "Tailscale 节点只能在连接后测速": return String(localized: "Tailscale 节点只能在连接后测速")
        case "拒绝（404）": return String(localized: "拒绝（404）")
        case "拒绝（空 200）": return String(localized: "拒绝（空 200）")
        case "拒绝（1×1 GIF）": return String(localized: "拒绝（1×1 GIF）")
        case "拒绝（{}）": return String(localized: "拒绝（{}）")
        case "拒绝（[]）": return String(localized: "拒绝（[]）")
        case "拒绝（断开）": return String(localized: "拒绝（断开）")
        case "请求头正则改写": return String(localized: "请求头正则改写")
        case "响应头正则改写": return String(localized: "响应头正则改写")
        case "响应体 jq": return String(localized: "响应体 jq")
        case "请求体 jq": return String(localized: "请求体 jq")
        case "请求脚本": return String(localized: "请求脚本")
        case "响应脚本": return String(localized: "响应脚本")
        case "含 body": return String(localized: "含 body")
        case "本地": return String(localized: "本地")
        case "未下载": return String(localized: "未下载")
        case "已缓存": return String(localized: "已缓存")
        case "二进制格式": return String(localized: "二进制格式")
        case "MitM 主机名": return String(localized: "MitM 主机名")
        case "脚本任务": return String(localized: "脚本任务")
        case "分享链接": return String(localized: "分享链接")
        case "Base64 分享链接": return String(localized: "Base64 分享链接")
        case "未识别": return String(localized: "未识别")
        case "不可用": return String(localized: "不可用")
        case "没有可以撤销的修改": return String(localized: "没有可以撤销的修改")
        case "配置文件里没有这个节点": return String(localized: "配置文件里没有这个节点")
        case "已有同名的节点或策略组": return String(localized: "已有同名的节点或策略组")
        case "名称、类型、服务器不能为空": return String(localized: "名称、类型、服务器不能为空")
        case "无法安全地重排策略组（配置使用了 YAML 锚点或特殊格式）": return String(localized: "无法安全地重排策略组（配置使用了 YAML 锚点或特殊格式）")
        case "配置文件中没有可排序的策略组": return String(localized: "配置文件中没有可排序的策略组")
        default: return s
        }
    }
}
