import SwiftUI
import Libmihomo

// Surge / Quantumult X .conf → mihomo profile (+ a module for its rewrite / MitM / script sections).
// Translation happens once, at import (bridge/confimport.go); afterwards it is an ordinary profile.

struct ConfImportResult: Decodable {
    struct Report: Decodable {
        var format: String?
        var proxies: Int?
        var groups: Int?
        var rules: Int?
        var providers: Int?
        var module: Bool?
        var skipped: [String]?
        var notes: [String]?
    }
    var yaml: String?
    var module: String?
    var report: Report?
    var error: String?

    static func convert(_ text: String) async -> ConfImportResult {
        let json = await Task.detached(priority: .userInitiated) { LibmihomoImportConf(text) }.value
        return (try? JSONDecoder().decode(ConfImportResult.self, from: Data(json.utf8)))
            ?? ConfImportResult(yaml: nil, module: nil, report: nil, error: "转换失败")
    }
}

enum ConfImport {
    /// Saves the converted profile (validated by the real core) and, if present, the module.
    static func save(text: String, name: String, result: ConfImportResult?, store: ProfileStore) async throws -> String {
        let r: ConfImportResult
        if let result { r = result } else { r = await ConfImportResult.convert(text) }
        if let e = r.error, !e.isEmpty { throw ProfileStore.StoreError.invalid(e) }
        guard let yaml = r.yaml, !yaml.isEmpty else { throw ProfileStore.StoreError.empty }
        let p = try await store.addLocal(name: name.isEmpty ? "导入的配置" : name, text: yaml)
        var msg = "已导入配置「\(p.name)」"
        if let m = r.module, !m.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            await MainActor.run { EngineStore.shared.addModule(text: m, name: p.name + "（重写）") }
            msg += "，重写 / MitM / 脚本已作为模块「\(p.name)（重写）」添加"
        }
        return msg
    }
}

/// Conversion report shown before importing a .conf.
struct ConfReportSection: View {
    let text: String
    @Binding var result: ConfImportResult?
    @State private var showSkipped = false

    init(text: String, result: Binding<ConfImportResult?>) {
        self.text = text
        self._result = result
    }

    var body: some View {
        Group {
            if let r = result {
                if let e = r.error, !e.isEmpty {
                    Section { Label(e, systemImage: "xmark.octagon.fill").foregroundStyle(Theme.bad).font(.footnote) }
                        .listRowBackground(Theme.card)
                } else if let rep = r.report {
                    Section {
                        HStack {
                            Label(rep.format == "qx" ? "Quantumult X 配置" : "Surge 配置", systemImage: "arrow.triangle.2.circlepath.doc.on.clipboard")
                                .font(.headline)
                            Spacer()
                            Text("→ mihomo").font(.caption.weight(.bold)).foregroundStyle(Theme.accent)
                        }
                        LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                            stat("节点", rep.proxies ?? 0)
                            stat("策略组", rep.groups ?? 0)
                            stat("规则", rep.rules ?? 0)
                            stat("规则集", rep.providers ?? 0)
                        }
                        if rep.module == true {
                            Label("重写 / MitM / 脚本 → 作为模块导入", systemImage: "puzzlepiece.extension").font(.footnote)
                        }
                    } header: { Text("转换结果") }
                    .listRowBackground(Theme.card)
                    if let notes = rep.notes, !notes.isEmpty {
                        Section("说明") {
                            ForEach(notes, id: \.self) { Text($0).font(.caption) }
                        }
                        .listRowBackground(Theme.card)
                    }
                    if let skipped = rep.skipped, !skipped.isEmpty {
                        Section {
                            DisclosureGroup("未转换 \(skipped.count) 项", isExpanded: $showSkipped) {
                                ForEach(skipped, id: \.self) { Text($0).scaledFont(10, design: .monospaced).foregroundStyle(.secondary) }
                            }
                            .tint(Theme.warn)
                        }
                        .listRowBackground(Theme.card)
                    }
                }
            } else {
                Section { LoadingRow(text: "正在转换…") }
                    .listRowBackground(Theme.card)
            }
        }
        .task { if result == nil { result = await ConfImportResult.convert(text) } }
    }

    func stat(_ title: String, _ n: Int) -> some View {
        VStack(spacing: 2) {
            Text("\(n)").font(.title3.weight(.bold).monospacedDigit())
            Text(LocalizedStringKey(title)).font(.caption2).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Theme.cardHi))
    }
}
