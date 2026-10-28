import SwiftUI

/// feat/nc-conf-native (user 2026-10-28): the profile editor shows and saves Tern's own .conf (Quantumult X-style
/// sections) instead of the internal YAML. Section-aware highlighting, live check through the .conf parser and the
/// same runtime check a connect does (「N 个节点 · N 个策略组 · N 条规则」), 保存并重载 regenerates the internal file and
/// reloads. Subscriptions open read-only with 复制为本地配置. The internal YAML is only a read-only view under 更多.
struct ConfEditorView: View {
    @EnvironmentObject var store: ProfileStore
    @Environment(\.dismiss) var dismiss
    let title: String
    let profile: Profile?
    @State var name: String
    @State private var text = ""
    @State private var initialText = ""
    @State private var loaded = false
    @State private var error: String?
    @State private var busy = false
    @State private var check: NCProfileCheck.Result?
    @State private var checking = false
    @State private var checkTask: Task<Void, Never>?
    @State private var checkGen = 0
    @State private var scrollToken = 0
    @State private var confirmDiscard = false
    @State private var share: ShareItem?
    @State private var showInternal = false
    private let initialName: String

    init(title: String, initialName: String, profile: Profile?) {
        self.title = title
        self.profile = profile
        self.initialName = initialName
        _name = State(initialValue: initialName)
    }

    var readOnly: Bool { profile?.kind == .remote }
    /// Unsaved edits: swipe-down is blocked and 取消 asks first.
    var dirty: Bool { loaded && !readOnly && (text != initialText || name != initialName) }

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if readOnly {
                    HStack(spacing: 8) {
                        Image(systemName: "lock.fill")
                        Text("订阅配置只读：更新订阅时会被覆盖。需要修改请复制为本地配置。")
                    }
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(10)
                    .background(Theme.cardHi)
                } else {
                    TextField("名称", text: $name)
                        .padding(12)
                        .background(Theme.cardHi)
                }
                if let error {
                    Text(error).font(.caption).foregroundStyle(Theme.bad).padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if loaded {
                    CodeEditor(text: $text, language: .ternConf, editable: !readOnly,
                               errorLine: check?.ok == false ? check?.line : nil, scrollToken: scrollToken)
                        .accessibilityIdentifier("conf.editor")
                } else {
                    ProgressView().frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                statusBar
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(LocalizedStringKey(title))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(readOnly ? "关闭" : "取消") { if dirty { confirmDiscard = true } else { dismiss() } }
                }
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button {
                            if let u = store.exportConfFile(of: profile, name: name, text: text) { share = ShareItem(url: u, temporary: true) }
                            else { error = String(localized: "导出失败：") + String(localized: "配置文件为空或无法读取") }
                        } label: { Label("导出 .conf", systemImage: "square.and.arrow.up") }
                        .accessibilityIdentifier("conf.export")
                        if profile != nil {
                            Button { showInternal = true } label: { Label("查看内部格式（只读）", systemImage: "doc.text.magnifyingglass") }
                                .accessibilityIdentifier("conf.internal")
                        }
                    } label: { Image(systemName: "ellipsis.circle") }
                    .accessibilityIdentifier("conf.more")
                    .disabled(!loaded)
                }
                ToolbarItem(placement: .confirmationAction) {
                    if busy { ProgressView() }
                    else if readOnly { Button("复制为本地配置") { copyAsLocal() }.disabled(!loaded) }
                    else { Button(profile == nil ? "校验并保存" : "保存并重载") { save() }.disabled(!loaded || check?.ok == false) }
                }
            }
            .task {
                guard !loaded else { return }
                let t = await ProfileStore.confEditorText(profile)
                text = t
                initialText = t
                loaded = true
                scheduleCheck(delay: 0)
            }
            .onChange(of: text) { _ in if loaded { scheduleCheck(delay: 700_000_000) } }
            .onDisappear { checkTask?.cancel() }
            .confirmationDialog("放弃修改？", isPresented: $confirmDiscard, titleVisibility: .visible) {
                Button("放弃修改", role: .destructive) { dismiss() }
            }
            .sheet(item: $share, onDismiss: { ProfileStore.purgeExports() }) { ActivityView(items: [$0.url], cleanup: $0.temporary ? $0.url : nil) }
            .sheet(isPresented: $showInternal) {
                if let profile { InternalFormatView(text: store.internalText(of: profile)) }
            }
        }
        .interactiveDismissDisabled(dirty)
    }

    var statusBar: some View {
        HStack(spacing: 8) {
            if checking {
                ProgressView().controlSize(.mini)
                Text("校验中…").font(.caption2).foregroundStyle(.secondary)
            } else if let c = check {
                if c.ok {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.good)
                    Text("\(c.nodes) 个节点 · \(c.groups) 个策略组 · \(c.rules) 条规则 · \(c.providers) 个节点集")
                        .font(.caption2.monospacedDigit()).foregroundStyle(.secondary).lineLimit(1)
                        .accessibilityIdentifier("conf.status")
                } else {
                    Image(systemName: "xmark.octagon.fill").foregroundStyle(Theme.bad)
                    Text(c.error ?? "").font(.caption2).foregroundStyle(Theme.bad).lineLimit(3)
                        .accessibilityIdentifier("conf.status")
                }
            }
            Spacer(minLength: 4)
            if let c = check, !c.ok, let l = c.line, l > 0 {
                Button { scrollToken += 1 } label: {
                    Text("第 \(l) 行")
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(Capsule().fill(Theme.bad.opacity(0.18)))
                        .foregroundStyle(Theme.bad)
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .frame(minHeight: 36)
        .background(Theme.card)
    }

    func scheduleCheck(delay: UInt64) {
        checkTask?.cancel()
        checkGen &+= 1
        let gen = checkGen
        let t = text
        let path = profile?.fileURL.path ?? AppShared.homeURL.appendingPathComponent("new-profile.yaml").path
        let home = AppShared.homeURL.path
        checkTask = Task {
            defer { if gen == checkGen { checking = false } }
            if delay > 0 { try? await Task.sleep(nanoseconds: delay) }
            guard !Task.isCancelled else { return }
            checking = true
            let r = await Task.detached(priority: .userInitiated) { TernConfStore.check(home: home, profilePath: path, text: t) }.value
            guard !Task.isCancelled else { return }
            checking = false
            let jump = check?.line != r.line && r.ok == false
            check = r
            if jump && delay == 0 { scrollToken += 1 }
        }
    }

    func save() {
        busy = true; error = nil
        Task {
            defer { busy = false }
            do {
                if let p = profile {
                    try await store.saveConfEdit(p, text: text)
                    if name != p.name { store.rename(p, to: name) }
                } else {
                    _ = try await store.addLocalConf(name: name, text: text)
                }
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }

    func copyAsLocal() {
        busy = true; error = nil
        let base = profile?.name ?? name
        Task {
            defer { busy = false }
            do {
                _ = try await store.addLocalConf(name: String(localized: "\(base) 副本"), text: text)
                dismiss()
            } catch { self.error = error.localizedDescription }
        }
    }
}

/// The internal file a profile's .conf is turned into (diagnostics only; edits go through the .conf).
struct InternalFormatView: View {
    @Environment(\.dismiss) var dismiss
    @State var text: String

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                    Text("由 .conf 自动生成，仅供排查问题；修改请编辑 .conf。")
                }
                .font(.caption).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(Theme.cardHi)
                CodeEditor(text: $text, language: .yaml, editable: false)
            }
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle("内部格式（只读）")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("关闭") { dismiss() } }
            }
        }
    }
}
