import Foundation

// feat/more-search: the search field at the top of 更多 (Settings-app style). A static, hand-kept index of every
// page and the settings worth finding, each pointing at a `SearchDestination`. The destination registry
// (SettingsSearchView.swift, `SearchDestination.page`) is the ONE place that maps a destination to a view, so an
// entry follows a page that moves (e.g. the 工具 tab restructuring 模块 / 重写 / 脚本) by changing one line there.
//
// Titles and breadcrumb segments are zh-Hans catalog keys (shown localized). Keywords are search aids only, never
// shown: zh-Hans synonyms plus English / technical terms, so they need no translation. The matcher also compares the
// title's localized, zh-Hans and English text, Traditional input (converted to Simplified), and pinyin / initials.

/// Where a search result goes. One case per reachable page; several index entries may share one.
enum SearchDestination: String, CaseIterable, Hashable {
    // 更多
    case profiles, sampleProfile, stats, snapshots, backup, webdav, syncFolder, updateResources, storage
    case appearance, liveActivity, appIcon, launchTab, trafficScope
    case advanced, connection, networkPolicy, geo, coreSettings, speedTestSettings, geoChecker
    case onboarding, diagnostics, about, systemLanguage
    // 工具
    case nodes, rules, modules, moduleGallery, allRewrites, rewrites, scripts, scriptLogs, scriptNotices, scriptStore
    case tasks, mitm, dns, logs, dnsLog, analytics, netDiagnostics, netTest, unlock, lanInfo, panels
    // 首页 / 策略
    case homePanels, homeGroups, homeTab, policyTab

    enum Presentation: Equatable {
        /// Pushed onto 更多's NavigationStack.
        case push
        /// Presented as a sheet (the page brings its own NavigationStack and 完成 button).
        case sheet
        /// Switches to a tab (AppSection raw value); the setting lives on that tab's own page.
        case tab(Int)
        /// 新手引导 (full-screen cover owned by 更多).
        case onboarding
        /// iOS Settings → Tern (per-app language).
        case systemSettings
    }

    var presentation: Presentation {
        switch self {
        case .homePanels, .homeGroups: return .sheet
        case .homeTab: return .tab(AppSection.home.rawValue)
        case .policyTab: return .tab(AppSection.policy.rawValue)
        case .onboarding: return .onboarding
        case .systemLanguage: return .systemSettings
        default: return .push
        }
    }
}

/// One searchable item: a page, or a setting on a page (then `destination` opens that page).
struct SearchEntry: Identifiable, Hashable {
    /// Stable id (accessibility `search.result.<id>`).
    let id: String
    /// zh-Hans catalog key shown as the result title.
    let title: String
    /// Breadcrumb of the page that holds it, as zh-Hans catalog keys, starting with the tab (更多 / 工具 / 首页 / 策略).
    let path: [String]
    let symbol: String
    let tone: TileTone
    let destination: SearchDestination
    /// Never shown; zh-Hans synonyms and English / technical terms.
    let keywords: [String]

    var section: String { path.first ?? "更多" }
}

enum SettingsSearchIndex {
    static let more = "更多", tools = "工具", home = "首页", policy = "策略"
    static let adv = [more, "高级设置"]
    static let conn = [more, "高级设置", "连接方式"]

    static func e(_ id: String, _ title: String, _ path: [String], _ symbol: String, _ tone: TileTone,
                  _ dest: SearchDestination, _ keywords: [String] = []) -> SearchEntry {
        SearchEntry(id: id, title: title, path: path, symbol: symbol, tone: tone, destination: dest, keywords: keywords)
    }

    /// Order inside a section = order shown for equally good matches.
    static let entries: [SearchEntry] = [
        // MARK: 更多
        e("profiles", "配置", [more], "doc.text.fill", .blue, .profiles,
          ["配置管理", "配置文件", "切换配置", "导入配置", "订阅", "profile", "config", "yaml", "clash", "import", "subscription"]),
        e("sampleProfile", "示例配置", [more, "配置"], "doc.richtext", .blue, .sampleProfile, ["模板", "sample", "example", "template"]),
        e("stats", "流量统计", [more], "chart.bar.fill", .red, .stats, ["流量", "用量", "每日", "历史", "traffic", "usage", "statistics", "data usage"]),
        e("snapshots", "配置快照", [more], "clock.arrow.circlepath", .purple, .snapshots, ["快照", "历史版本", "回滚", "snapshot", "history", "rollback"]),
        e("backup", "备份与恢复", [more], "externaldrive.badge.icloud", .blue, .backup,
          ["备份", "恢复", "导出", "导入", "加密的备份", "iCloud", "backup", "restore", "export"]),
        e("webdav", "WebDAV 备份", [more, "备份与恢复"], "server.rack", .blue, .webdav, ["webdav", "云备份", "坚果云", "nextcloud", "cloud"]),
        e("syncFolder", "同步文件夹", [more, "备份与恢复"], "folder", .blue, .syncFolder, ["同步", "iCloud Drive", "文件", "sync", "folder"]),
        e("updateResources", "更新资源", [more], "arrow.triangle.2.circlepath", .green, .updateResources,
          ["更新", "订阅", "模块", "规则集", "脚本", "全部更新", "update", "refresh", "subscription", "rule set", "Sub-Store"]),
        e("storage", "存储空间", [more], "internaldrive", .neutral, .storage, ["缓存", "清理", "空间", "storage", "cache", "clean"]),
        e("appearance", "深色与浅色", [more, "外观"], "circle.lefthalf.filled", .accent, .appearance,
          ["外观", "深色", "浅色", "深色模式", "主题", "dark mode", "light", "theme", "appearance"]),
        e("liveActivity", "实时活动与灵动岛", [more, "外观"], "platter.filled.top.iphone", .purple, .liveActivity,
          ["实时活动", "灵动岛", "锁屏", "锁定屏幕", "小组件", "Live Activity", "Dynamic Island", "lock screen", "widget"]),
        e("appIcon", "App 图标", [more, "外观"], "app.badge", .orange, .appIcon, ["图标", "换图标", "icon", "app icon"]),
        e("launchTab", "开始标签页", [more, "外观"], "rectangle.stack", .green, .launchTab, ["启动", "默认标签", "打开时", "launch", "start tab", "default tab"]),
        e("trafficScope", "首页流量统计", [more, "外观"], "arrow.up.arrow.down", .teal, .trafficScope,
          ["仅代理", "全部流量", "网速", "proxy only", "traffic", "speed"]),
        e("advanced", "高级设置", [more], "gearshape.2", .neutral, .advanced, ["高级", "advanced", "settings"]),
        e("connection", "连接方式", adv, "point.3.filled.connected.trianglepath.dotted", .blue, .connection,
          ["TUN", "VPN 混合", "仅代理", "代理模式", "增强模式", "阻止 QUIC", "QUIC", "重置 VPN 配置", "proxy only", "mixed", "VPN", "connection mode"]),
        e("lanSharing", "局域网共享", conn, "wifi", .teal, .connection,
          ["局域网", "共享", "热点", "HTTP 代理", "SOCKS", "端口", "认证", "LAN", "share", "allow lan", "hotspot", "proxy port"]),
        e("tunnelScope", "隧道范围", conn, "scope", .blue, .connection,
          ["接管所有网络流量", "排除局域网", "排除", "APNs", "includeAllNetworks", "exclude", "tunnel"]),
        e("routes", "路由", conn, "arrow.triangle.turn.up.right.diamond", .blue, .connection, ["路由表", "route", "routes", "CIDR"]),
        e("ipv6", "IPv6", conn, "6.circle", .blue, .connection, ["ipv6", "v6"]),
        e("onDemand", "按需连接", conn, "wifi.exclamationmark", .blue, .connection,
          ["自动连接", "信任的 Wi-Fi", "SSID", "蜂窝", "on demand", "trusted wifi", "auto connect"]),
        e("networkPolicy", "按网络切换策略", conn, "wifi.router", .blue, .networkPolicy,
          ["SSID", "Wi-Fi", "蜂窝网络", "运行模式", "网络切换", "network policy", "ssid policy", "cellular"]),
        e("geo", "地理数据库", adv, "globe.asia.australia", .green, .geo,
          ["GeoIP", "GeoSite", "MMDB", "ASN", "地理", "IP 库", "数据库", "规则库", "geo", "database", "geodata"]),
        e("coreSettings", "内核设置", adv, "slider.horizontal.3", .neutral, .coreSettings,
          ["内核", "mihomo", "clash", "日志级别", "性能", "断开连接", "core", "kernel", "log level"]),
        e("controller", "外部控制器", [more, "高级设置", "内核设置"], "antenna.radiowaves.left.and.right", .neutral, .coreSettings,
          ["控制器", "external controller", "API", "secret", "dashboard", "面板", "yacd", "metacubexd", "9090"]),
        e("sniffer", "域名嗅探（Sniffer）", [more, "高级设置", "内核设置"], "eye", .neutral, .coreSettings, ["嗅探", "sniffer", "SNI", "sniff"]),
        e("speedTestSettings", "测速设置", adv, "bolt.horizontal", .orange, .speedTestSettings,
          ["测速", "延迟", "测速地址", "超时", "url-test", "latency", "delay", "ping", "test url", "timeout"]),
        e("geoChecker", "出口信息来源", adv, "mappin.and.ellipse", .pink, .geoChecker,
          ["出口", "IP 查询", "落地", "ASN", "运营商", "geo checker", "exit ip", "ip info", "isp"]),
        e("onboarding", "新手引导", [more, "帮助"], "sparkles", .accent, .onboarding, ["引导", "教程", "入门", "onboarding", "tutorial", "help"]),
        e("diagnostics", "诊断与反馈", [more, "帮助"], "waveform.path.ecg", .red, .diagnostics,
          ["诊断", "反馈", "崩溃", "错误", "日志导出", "共享容器", "diagnostics", "feedback", "bug", "report", "crash"]),
        e("about", "关于", [more, "帮助"], "info.circle", .neutral, .about, ["版本", "开源许可", "许可", "致谢", "about", "version", "license"]),
        e("language", "语言", [more], "globe", .neutral, .systemLanguage,
          ["语言", "简体中文", "繁體中文", "English", "language", "日本語", "한국어", "Русский"]),

        // MARK: 工具
        e("nodes", "节点与订阅", [tools], "server.rack", .blue, .nodes,
          ["节点", "订阅", "机场", "节点订阅", "配置订阅", "添加节点", "手动节点", "节点集", "筛选节点", "proxy", "node", "server",
           "subscription", "provider", "proxy-provider", "vmess", "vless", "trojan", "hysteria", "shadowsocks", "ss", "wireguard", "tuic"]),
        e("rules", "分流规则", [tools], "arrow.triangle.branch", .orange, .rules,
          ["规则", "分流", "自定义规则", "规则集", "规则命中", "rule", "rules", "rule set", "rule-provider", "routing", "DOMAIN", "GEOIP", "MATCH"]),
        e("modules", "模块", [tools, "重写"], "puzzlepiece.extension", .green, .modules,
          ["模块", "订阅", "重写订阅", "插件", "覆写", "Sub-Store", "BoxJS", "Surge 模块", "Loon 插件", "module", "plugin", "sgmodule", "override", "Egern"]),
        e("moduleGallery", "模块库", [tools, "重写"], "square.grid.2x2", .green, .moduleGallery, ["模块库", "插件库", "gallery", "library", "store"]),
        e("allRewrites", "全部重写规则", [tools, "重写"], "list.bullet.rectangle", .red, .allRewrites, ["重写规则", "all rewrites", "rewrite rules"]),
        e("rewrites", "重写", [tools], "arrow.triangle.swap", .red, .rewrites,
          ["重写", "我的重写", "本地重写", "本地模块", "复写", "Map Local", "302", "307", "reject", "header", "请求头", "rewrite", "url rewrite", "body rewrite", "mock"]),
        e("scripts", "本地脚本", [tools, "重写"], "curlybraces", .purple, .scripts,
          ["脚本", "我的脚本", "JavaScript", "JS", "http-request", "http-response", "script", "$httpClient"]),
        e("scriptLogs", "脚本日志", [tools, "重写", "脚本工具"], "text.alignleft", .purple, .scriptLogs, ["console", "script log"]),
        e("scriptNotices", "脚本通知记录", [tools, "重写", "脚本工具"], "bell", .purple, .scriptNotices, ["通知", "notification", "$notification"]),
        e("scriptStore", "持久化存储", [tools, "重写", "脚本工具"], "externaldrive", .purple, .scriptStore,
          ["存储", "$persistentStore", "$prefs", "BoxJS", "persistent store", "key value"]),
        e("tasks", "定时任务", [tools], "clock.arrow.circlepath", .teal, .tasks, ["任务", "cron", "定时", "签到", "task", "schedule", "event"]),
        e("mitm", "HTTPS 解密", [tools], "lock.open", .accent, .mitm,
          ["MitM", "解密", "HTTPS", "证书", "CA 证书", "根证书", "信任证书", "主机名", "QUIC", "HTTP/2", "certificate", "ca", "decrypt", "hostname", "ssl", "tls"]),
        e("dns", "DNS", [tools], "network", .orange, .dns,
          ["域名解析", "解析服务器", "DoH", "DoT", "DoQ", "Fake-IP", "fakeip", "nameserver", "nameserver-policy", "hosts", "本地 DNS 映射",
           "真实 IP 域名", "缓存", "respect-rules", "国内", "国外", "resolver"]),
        e("logs", "运行日志", [tools, "运行状态"], "text.alignleft", .neutral, .logs, ["日志", "log", "logs", "debug", "调试"]),
        e("dnsLog", "域名解析记录", [tools, "运行状态"], "globe", .blue, .dnsLog, ["DNS 日志", "解析记录", "拦截", "dns log", "query log", "blocked"]),
        e("analytics", "连接分析", [tools, "运行状态"], "chart.pie", .teal, .analytics, ["分析", "流量分析", "连接", "主机名", "analytics", "connections"]),
        e("netDiagnostics", "网络诊断", [tools, "网络"], "stethoscope", .green, .netDiagnostics,
          ["网络工具", "Ping", "TCP", "DNS 查询", "nslookup", "dig", "traceroute", "diagnose"]),
        e("netTest", "网速测试", [tools, "网络"], "speedometer", .orange, .netTest, ["测速", "带宽", "NAT", "NAT 类型", "speedtest", "bandwidth", "nat type"]),
        e("unlock", "流媒体解锁", [tools, "网络"], "play.tv", .pink, .unlock,
          ["解锁", "解锁检测", "Netflix", "YouTube", "ChatGPT", "Disney", "流媒体", "streaming", "unlock"]),
        e("lanInfo", "局域网信息", [tools, "网络"], "wifi.router", .teal, .lanInfo, ["内网 IP", "路由器", "网关", "LAN", "router", "gateway", "local ip"]),
        e("panels", "面板", [home], "square.grid.2x2", .blue, .panels, ["面板", "Surge 面板", "Stash 磁贴", "panel", "tile", "info panel"]),

        // MARK: 首页 / 策略
        e("homePanels", "编辑首页面板", [home], "rectangle.3.group", .blue, .homePanels,
          ["首页卡片", "添加首页卡片", "卡片", "排序", "流量分析", "小组件", "home tiles", "cards", "widget", "dashboard"]),
        e("homeGroups", "编辑首页策略", [home], "square.stack.3d.up", .orange, .homeGroups, ["首页策略组", "策略组", "home groups", "policy groups"]),
        e("outboundMode", "出站模式", [home], "arrow.triangle.branch", .accent, .homeTab,
          ["规则", "全局", "直连", "模式", "rule", "global", "direct", "mode"]),
        e("policyGroups", "策略", [policy], "paperplane", .blue, .policyTab,
          ["策略组", "选择节点", "切换节点", "编辑排序", "测速后自动排序", "proxy group", "policy", "select", "url-test", "fallback", "load-balance"]),
    ]

    // MARK: Matching

    struct Hit: Hashable {
        let entry: SearchEntry
        let score: Int
        /// Character offsets of the matched part in the shown (localized) title, when it matched there.
        let titleRange: Range<Int>?
    }

    /// Lowercased, width / diacritic folded, Traditional → Simplified, without spaces.
    static func normalize(_ s: String) -> String {
        cacheLock.lock()
        if let c = normCache[s] { cacheLock.unlock(); return c }
        cacheLock.unlock()
        let v = computeNormalized(s)
        cacheLock.lock(); if normCache.count > 4000 { normCache.removeAll() }; normCache[s] = v; cacheLock.unlock()
        return v
    }

    private static var normCache: [String: String] = [:]

    private static func computeNormalized(_ s: String) -> String {
        var t = s.applyingTransform(StringTransform("Hant-Hans"), reverse: false) ?? s
        t = t.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
        return t.lowercased().filter { !$0.isWhitespace }
    }

    /// Readings the transliterator gets wrong in this app's vocabulary (重写 = chóng xiě; ICU reads 地 as de, here it is
    /// always dì as in 地理 / 本地). Replaced by a same-length character with the wanted reading before transliteration.
    static let readings: [String: String] = ["重写": "崇写", "重置": "崇置", "重新": "崇新", "地": "第"]

    /// Per character: full pinyin syllable and its initial (letters / digits stay themselves; others are dropped).
    static func syllables(_ s: String) -> [(char: Int, full: String, initial: String)] {
        cacheLock.lock()
        if let c = cache[s] { cacheLock.unlock(); return c }
        cacheLock.unlock()
        let v = computeSyllables(s)
        cacheLock.lock(); if cache.count > 4000 { cache.removeAll() }; cache[s] = v; cacheLock.unlock()
        return v
    }

    private static var cache: [String: [(char: Int, full: String, initial: String)]] = [:]
    private static let cacheLock = NSLock()

    static func isHan(_ ch: Character) -> Bool {
        ch.unicodeScalars.contains { (0x4E00...0x9FFF).contains($0.value) || (0x3400...0x4DBF).contains($0.value) }
    }

    static func latin(_ s: String) -> String {
        ((s.applyingTransform(.mandarinToLatin, reverse: false) ?? s).applyingTransform(.stripDiacritics, reverse: false) ?? s).lowercased()
    }

    /// Han runs are transliterated as a whole (ICU picks the reading from the neighbouring characters, e.g. 地理 = di li,
    /// while 地 alone reads de), then split into one syllable per character; per character as a fallback.
    private static func computeSyllables(_ s: String) -> [(char: Int, full: String, initial: String)] {
        var src = s
        for (w, r) in readings { src = src.replacingOccurrences(of: w, with: r) }
        let chars = Array(src)
        var out: [(char: Int, full: String, initial: String)] = []
        var i = 0
        while i < chars.count {
            let ch = chars[i]
            if isHan(ch) {
                var j = i
                while j < chars.count, isHan(chars[j]) { j += 1 }
                let run = String(chars[i..<j])
                var parts = latin(run).split(whereSeparator: { !$0.isLetter }).map(String.init)
                if parts.count != j - i { parts = chars[i..<j].map { latin(String($0)).filter(\.isLetter) } }
                for (k, p) in parts.enumerated() {
                    if let f = p.first { out.append((char: i + k, full: p, initial: String(f))) }
                }
                i = j
                continue
            }
            if ch.isLetter || ch.isNumber {
                let l = normalize(String(ch))
                if let f = l.first { out.append((char: i, full: l, initial: String(f))) }
            }
            i += 1
        }
        return out
    }

    /// Range (character offsets in `text`) that `q` matches as pinyin initials or full pinyin syllables; nil if none.
    static func pinyinRange(_ q: String, in text: String) -> Range<Int>? {
        let syl = syllables(text)
        guard !syl.isEmpty, q.count >= 2, q.allSatisfy({ $0.isASCII }) else { return nil }
        // Initials: "dlsjk" → 地理数据库.
        let initials = syl.map { $0.initial }.joined()
        if let r = initials.range(of: q) {
            let a = initials.distance(from: initials.startIndex, to: r.lowerBound)
            let b = initials.distance(from: initials.startIndex, to: r.upperBound)
            return syl[a].char..<(syl[b - 1].char + 1)
        }
        // Full pinyin from a syllable boundary, the last syllable may be partial: "dili", "dilis".
        for start in syl.indices {
            var rest = Substring(q)
            var k = start
            while k < syl.count, !rest.isEmpty {
                let f = syl[k].full
                if rest.hasPrefix(f) { rest = rest.dropFirst(f.count); k += 1 }
                else if f.hasPrefix(rest) { rest = ""; k += 1 }
                else { break }
            }
            if rest.isEmpty, k > start, q.count >= 2 { return syl[start].char..<(syl[k - 1].char + 1) }
        }
        return nil
    }

    /// The title text in the app's language (what the row shows).
    static func shown(_ key: String) -> String { Bundle.main.localizedString(forKey: key, value: key, table: "Localizable") }

    static let english: Bundle? = Bundle.main.path(forResource: "en", ofType: "lproj").flatMap(Bundle.init(path:))
    static func inEnglish(_ key: String) -> String { english?.localizedString(forKey: key, value: key, table: "Localizable") ?? key }

    /// Results for a query, best first; empty for a blank query.
    static func search(_ raw: String, in list: [SearchEntry] = entries,
                       display: (String) -> String = SettingsSearchIndex.shown) -> [Hit] {
        let q = normalize(raw)
        guard !q.isEmpty else { return [] }
        var hits: [Hit] = []
        for (order, e) in list.enumerated() {
            let title = display(e.title)
            let nTitle = normalize(title)
            var score = 0
            var range: Range<Int>?
            if nTitle == q { score = 1000 }
            else if nTitle.hasPrefix(q) { score = 900 }
            else if nTitle.contains(q) { score = 800 }
            if score > 0 { range = textRange(of: raw, in: title) }
            if score == 0 {
                let others = [e.title, inEnglish(e.title)].map(normalize)
                if others.contains(where: { $0 == q || $0.hasPrefix(q) }) { score = 760 }
                else if others.contains(where: { $0.contains(q) }) { score = 700 }
            }
            if score == 0 {
                let kws = e.keywords.map(normalize)
                if kws.contains(q) { score = 650 }
                else if kws.contains(where: { $0.hasPrefix(q) }) { score = 600 }
                else if q.count >= 2, kws.contains(where: { $0.contains(q) }) { score = 500 }
            }
            if score == 0, let r = pinyinRange(q, in: title) { score = 450; range = r }
            if score == 0, pinyinRange(q, in: e.title) != nil { score = 420 }
            if score == 0, q.count >= 2, e.keywords.contains(where: { pinyinRange(q, in: $0) != nil }) { score = 380 }
            if score == 0, q.count >= 2, e.path.dropFirst().contains(where: { normalize(display($0)).contains(q) }) { score = 300 }
            if score > 0 { hits.append(Hit(entry: e, score: score * 1000 - order, titleRange: range)) }
        }
        return hits.sorted { $0.score > $1.score }
    }

    /// Character offsets of `raw` inside `text` (case / width / diacritic / Traditional-insensitive).
    static func textRange(of raw: String, in text: String) -> Range<Int>? {
        let q = raw.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return nil }
        let opts: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive, .widthInsensitive]
        if let r = text.range(of: q, options: opts) {
            return text.distance(from: text.startIndex, to: r.lowerBound)..<text.distance(from: text.startIndex, to: r.upperBound)
        }
        // Traditional input against a Simplified title (or the reverse): compare char-aligned converted texts.
        let tq = q.applyingTransform(StringTransform("Hant-Hans"), reverse: false) ?? q
        let tt = text.applyingTransform(StringTransform("Hant-Hans"), reverse: false) ?? text
        if tt.count == text.count, let r = tt.range(of: tq, options: opts) {
            return tt.distance(from: tt.startIndex, to: r.lowerBound)..<tt.distance(from: tt.startIndex, to: r.upperBound)
        }
        return nil
    }

    struct ResultGroup: Identifiable {
        let section: String
        let hits: [Hit]
        var id: String { section }
    }

    /// Hits grouped by section (更多 / 工具 / 首页 / 策略), sections in the order of their best hit.
    static func grouped(_ hits: [Hit]) -> [ResultGroup] {
        var order: [String] = []
        var map: [String: [Hit]] = [:]
        for h in hits {
            if map[h.entry.section] == nil { order.append(h.entry.section) }
            map[h.entry.section, default: []].append(h)
        }
        return order.map { ResultGroup(section: $0, hits: map[$0] ?? []) }
    }
}
