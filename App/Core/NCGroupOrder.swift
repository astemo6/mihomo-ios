import Foundation
import CryptoKit

/// Pure Swift implementation of policy group reordering and profile copying/regeneration (去 Go 第 B5 批).
/// Replaces bridge/grouporder.go functions:
/// - GroupOrderCopy
/// - GroupOrderRegenerate
/// - GroupOrderRegenerateForced
enum NCGroupOrder {

    struct ReorderTextResult {
        var text: String
        var changed: Bool
        var method: String?
        var order: [String]
        var error: String?
    }

    // MARK: - Group Order Copy

    /// Writes the source profile with its groups in `want` order to copyPath.
    /// Preserves existing user edits on existing copies by reordering in place (`modified: true`).
    /// Keeps previous content as `<copyPath>.bak`.
    /// Records SHA-256 hash in `<copyPath>.gen` to detect subsequent manual edits.
    static func copy(home: URL, sourcePath: String, copyPath: String, want: [String]) -> GroupOrder.Result {
        let fm = FileManager.default
        if fm.fileExists(atPath: copyPath) && !copyGenerated(copyPath) {
            var r = reorderFile(path: copyPath, want: want)
            if (r.error ?? "").isEmpty {
                r.modified = true
            }
            return r
        }

        guard let srcData = try? Data(contentsOf: URL(fileURLWithPath: sourcePath)) else {
            return GroupOrder.Result(error: "无法读取源配置文件")
        }

        let r = reorderInto(src: srcData, dest: copyPath, want: want, always: false)
        if (r.error ?? "").isEmpty && r.changed == true {
            markGenerated(copyPath)
        }
        return r
    }

    // MARK: - Group Order Regenerate

    /// Rebuilds a copy from fresh source subscription content, applying copy's stored order.
    /// When `force` is false and copy was edited manually, returns `{modified: true, error: "副本已手动修改"}`.
    /// When `force` is true, overwrites edits and keeps backup in `.bak`.
    static func regenerate(home: URL, sourcePath: String, copyPath: String, force: Bool) -> GroupOrder.Result {
        guard let srcData = try? Data(contentsOf: URL(fileURLWithPath: sourcePath)) else {
            return GroupOrder.Result(error: "无法读取源配置文件")
        }

        if !force && !copyGenerated(copyPath) {
            return GroupOrder.Result(changed: false, modified: true, error: "副本已手动修改")
        }

        let copyURL = URL(fileURLWithPath: copyPath)
        let profileID = copyURL.deletingPathExtension().lastPathComponent
        let want = GroupEditStore.get(profileID).order ?? []

        if want.isEmpty {
            let curData = try? Data(contentsOf: copyURL)
            if let cur = curData, cur == srcData {
                markGenerated(copyPath)
                return GroupOrder.Result(changed: false)
            }
            do {
                try replaceKeepingBak(copyPath, data: srcData)
                markGenerated(copyPath)
                return GroupOrder.Result(changed: true)
            } catch {
                return GroupOrder.Result(error: error.localizedDescription)
            }
        }

        let r = reorderInto(src: srcData, dest: copyPath, want: want, always: true)
        if r.changed == true || (r.error ?? "").isEmpty {
            markGenerated(copyPath)
        }
        return r
    }

    // MARK: - Reorder File / Into

    static func reorderFile(path: String, want: [String]) -> GroupOrder.Result {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
            return GroupOrder.Result(error: "无法读取配置文件")
        }
        let generated = copyGenerated(path)
        let r = reorderInto(src: data, dest: path, want: want, always: false)
        if (r.error ?? "").isEmpty && r.changed == true && generated {
            markGenerated(path)
        }
        return r
    }

    static func reorderInto(src: Data, dest: String, want: [String], always: Bool) -> GroupOrder.Result {
        func plain(_ e: String) -> GroupOrder.Result {
            if !always {
                return GroupOrder.Result(error: e)
            }
            do {
                try replaceKeepingBak(dest, data: src)
                return GroupOrder.Result(changed: true, error: e)
            } catch {
                return GroupOrder.Result(error: error.localizedDescription)
            }
        }

        guard let srcText = String(data: src, encoding: .utf8) else {
            return plain("源配置不是有效的 UTF-8 文本")
        }

        let reorderRes = reorderGroupsText(srcText, want: want)
        guard reorderRes.error == nil else {
            return plain(reorderRes.error!)
        }

        let after = reorderRes.order
        let changed = reorderRes.changed
        let method = reorderRes.method
        let nb = reorderRes.text.data(using: .utf8) ?? src

        if !changed {
            if !always {
                return GroupOrder.Result(changed: false, order: after)
            }
            let cur = try? Data(contentsOf: URL(fileURLWithPath: dest))
            if let cur = cur, cur == src {
                return GroupOrder.Result(changed: false, order: after)
            }
            do {
                try replaceKeepingBak(dest, data: src)
                return GroupOrder.Result(changed: true, order: after)
            } catch {
                return GroupOrder.Result(error: error.localizedDescription)
            }
        }

        if always {
            let cur = try? Data(contentsOf: URL(fileURLWithPath: dest))
            if let cur = cur, cur == nb {
                return GroupOrder.Result(changed: false, order: after, method: method)
            }
        }

        do {
            try replaceKeepingBak(dest, data: nb)
            return GroupOrder.Result(changed: true, order: after, method: method)
        } catch {
            return GroupOrder.Result(error: error.localizedDescription)
        }
    }

    // MARK: - Text Reordering Algorithm

    static func reorderGroupsText(_ srcText: String, want: [String]) -> ReorderTextResult {
        guard let docVal = NCYAML.parse(srcText),
              case .object(let raw) = docVal else {
            return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: NCProfileCheck.withLine("YAML 解析失败", srcText))
        }

        guard let pgArray = raw["proxy-groups"]?.array, !pgArray.isEmpty else {
            return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "配置文件中没有可排序的策略组")
        }

        var fileNames: [String] = []
        var seen = Set<String>()
        for item in pgArray {
            guard let name = item["name"]?.string, !name.isEmpty else {
                return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "有策略组缺少名称")
            }
            if seen.contains(name) {
                return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "策略组「\(name)」重名")
            }
            seen.insert(name)
            fileNames.append(name)
        }

        let perm = groupSlots(fileNames: fileNames, want: want)
        let after = perm.map { fileNames[$0] }
        if isIdentity(perm) {
            return ReorderTextResult(text: srcText, changed: false, method: nil, order: after, error: nil)
        }

        let lines = splitLines(srcText)
        var keyLineIdx: Int?
        for (i, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed == "proxy-groups:" || trimmed.hasPrefix("proxy-groups: ") || trimmed.hasPrefix("proxy-groups:#") {
                keyLineIdx = i
                break
            }
        }

        guard let keyIdx = keyLineIdx else {
            return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "未找到 proxy-groups 配置项")
        }

        let keyIndent = indentOf(lines[keyIdx])
        var dashIndices: [Int] = []
        var dashCol = -1

        var seqEnd = lines.count
        for i in (keyIdx + 1)..<lines.count {
            let line = lines[i]
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let ind = indentOf(line)
            if dashCol == -1 {
                if ind > keyIndent && trimmed.hasPrefix("-") {
                    dashCol = ind
                    dashIndices.append(i)
                } else if ind <= keyIndent {
                    seqEnd = i
                    break
                }
            } else {
                if ind == dashCol && trimmed.hasPrefix("-") {
                    dashIndices.append(i)
                } else if ind <= keyIndent {
                    seqEnd = i
                    break
                }
            }
        }

        let n = dashIndices.count
        if n != fileNames.count {
            return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "无法安全地重排策略组（配置使用了 YAML 锚点或特殊格式）")
        }

        var start = [Int](repeating: 0, count: n)
        for i in 0..<n {
            let lo = (i == 0) ? (keyIdx + 1) : (dashIndices[i - 1] + 1)
            var s = dashIndices[i]
            while s - 1 >= lo && isComment(lines[s - 1]) && indentOf(lines[s - 1]) <= dashCol {
                s -= 1
            }
            start[i] = s
        }

        var bodyEnd = [Int](repeating: 0, count: n)
        var sepEnd = [Int](repeating: 0, count: n)
        for i in 0..<n {
            let hi = (i + 1 < n) ? start[i + 1] : seqEnd
            var e = hi
            while e - 1 > dashIndices[i] && (isBlank(lines[e - 1]) || (isComment(lines[e - 1]) && indentOf(lines[e - 1]) <= dashCol)) {
                e -= 1
            }
            bodyEnd[i] = e
            sepEnd[i] = hi
        }

        var out = ""
        for l in lines[0..<start[0]] {
            out.append(l)
        }
        for k in 0..<n {
            let src = perm[k]
            var body = lines[start[src]..<bodyEnd[src]].joined()
            if !body.hasSuffix("\n") { body.append("\n") }
            out.append(body)
            for l in lines[bodyEnd[k]..<sepEnd[k]] {
                out.append(l)
            }
        }
        for l in lines[sepEnd[n - 1]..<lines.count] {
            out.append(l)
        }

        // Verify result decodes and group names match after
        if let checkVal = NCYAML.parse(out),
           case .object(let checkRaw) = checkVal,
           let checkGroups = checkRaw["proxy-groups"]?.array {
            let checkNames = checkGroups.compactMap { $0["name"]?.string }
            if checkNames == after {
                return ReorderTextResult(text: out, changed: true, method: "text", order: after, error: nil)
            }
        }

        return ReorderTextResult(text: srcText, changed: false, method: nil, order: [], error: "重排后行内容不一致")
    }

    // MARK: - Slot Calculation

    static func groupSlots(fileNames: [String], want: [String]) -> [Int] {
        var inFile: [String: Int] = [:]
        for (i, n) in fileNames.enumerated() {
            inFile[n] = i
        }
        var seen = Set<String>()
        var ranked: [Int] = []
        for n in want {
            if let i = inFile[n], !seen.contains(n) {
                seen.insert(n)
                ranked.append(i)
            }
        }
        var perm = [Int](repeating: 0, count: fileNames.count)
        var k = 0
        for (i, n) in fileNames.enumerated() {
            if seen.contains(n) {
                perm[i] = ranked[k]
                k += 1
            } else {
                perm[i] = i
            }
        }
        return perm
    }

    static func isIdentity(_ perm: [Int]) -> Bool {
        for (i, v) in perm.enumerated() {
            if i != v { return false }
        }
        return true
    }

    // MARK: - Profile Group Names

    static func fileGroupNames(path: String) -> [String] {
        let url = URL(fileURLWithPath: path)
        guard let content = try? String(contentsOf: url, encoding: .utf8),
              let docVal = NCYAML.parse(content),
              case .object(let raw) = docVal,
              let groups = raw["proxy-groups"]?.array else {
            return []
        }
        return groups.compactMap { $0["name"]?.string }
    }

    // MARK: - File & Hash Helpers

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func copyGenPath(_ copyPath: String) -> String {
        copyPath + ".gen"
    }

    static func markGenerated(_ copyPath: String) {
        let url = URL(fileURLWithPath: copyPath)
        if let data = try? Data(contentsOf: url) {
            let hash = sha256Hex(data)
            let genURL = URL(fileURLWithPath: copyGenPath(copyPath))
            try? hash.data(using: .utf8)?.write(to: genURL, options: .atomic)
        }
    }

    static func copyGenerated(_ copyPath: String) -> Bool {
        let genURL = URL(fileURLWithPath: copyGenPath(copyPath))
        guard let genData = try? Data(contentsOf: genURL),
              let wantHash = String(data: genData, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return true
        }
        let copyURL = URL(fileURLWithPath: copyPath)
        guard let curData = try? Data(contentsOf: copyURL) else {
            return true
        }
        return wantHash == sha256Hex(curData)
    }

    static func replaceKeepingBak(_ dest: String, data: Data) throws {
        let destURL = URL(fileURLWithPath: dest)
        let bakURL = URL(fileURLWithPath: dest + ".bak")
        if let curData = try? Data(contentsOf: destURL) {
            try? curData.write(to: bakURL, options: .atomic)
        }
        try data.write(to: destURL, options: .atomic)
    }

    static func splitLines(_ text: String) -> [String] {
        var out: [String] = []
        var current = ""
        for ch in text {
            current.append(ch)
            if ch == "\n" {
                out.append(current)
                current = ""
            }
        }
        if !current.isEmpty {
            out.append(current)
        }
        return out
    }

    static func indentOf(_ line: String) -> Int {
        var n = 0
        for ch in line {
            if ch == " " { n += 1 }
            else if ch == "\t" { n += 4 }
            else { break }
        }
        return n
    }

    static func isBlank(_ line: String) -> Bool {
        line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func isComment(_ line: String) -> Bool {
        line.trimmingCharacters(in: .whitespaces).hasPrefix("#")
    }
}
