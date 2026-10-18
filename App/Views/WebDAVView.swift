import SwiftUI

/// v0.19 备份与恢复 → WebDAV 备份: server settings (password in the Keychain), backup now, keep the newest N,
/// list versions on the server, restore or delete one, optional password encryption. Engine: App/Core/WebDAV.swift.
struct WebDAVView: View {
    @State private var s = WebDAVSettings.load()
    @State private var password = Keychain.read(WebDAVSettings.passwordAccount) ?? ""
    @State private var encPassword = Keychain.read(WebDAVSettings.encryptionAccount) ?? ""
    @State private var files: [WebDAVFile] = []
    @State private var listed = false
    @State private var busy: String?
    @State private var message: String?
    @State private var error: String?
    @State private var pendingRestore: WebDAVFile?
    @State private var encrypted: EncryptedData?
    @State private var pendingDelete: WebDAVFile?

    static let keepChoices = [3, 5, 10, 20, 50]

    var body: some View {
        List {
            Section {
                TextField("https://dav.example.com/dav/Mihomo/", text: $s.url)
                    .keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("webdav.url")
                TextField("用户名", text: $s.username)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .accessibilityIdentifier("webdav.user")
                SecureField("密码 / 应用密码", text: $password)
                    .accessibilityIdentifier("webdav.password")
            } header: {
                Text("服务器")
            } footer: {
                Text("填写一个文件夹地址（不存在会自动创建）。坚果云等服务请使用「应用密码」。密码保存在钥匙串中。")
            }
            .listRowBackground(Theme.card)

            Section {
                Picker("保留版本", selection: $s.keep) {
                    ForEach(Self.keepChoices, id: \.self) { Text("\($0) 个").tag($0) }
                }
                Toggle("包含 MitM 根证书和私钥", isOn: $s.includeCA)
                Toggle("加密备份", isOn: $s.encrypt)
                    .accessibilityIdentifier("webdav.encrypt")
                if s.encrypt {
                    SecureField("加密密码", text: $encPassword)
                        .accessibilityIdentifier("webdav.encpassword")
                }
            } header: {
                Text("选项")
            } footer: {
                Text(s.encrypt
                     ? LocalizedStringKey("备份先用 AES-256-GCM 加密（密钥由加密密码经 PBKDF2 生成）再上传；恢复时需要同一个密码，忘记就无法恢复。")
                     : LocalizedStringKey("每次备份上传一个新文件，超过保留数量时删除最旧的。"))
            }
            .listRowBackground(Theme.card)

            Section {
                Button { backup() } label: {
                    HStack {
                        Label("立即备份", systemImage: "icloud.and.arrow.up")
                        Spacer()
                        if busy == "backup" { ProgressView().controlSize(.small) }
                    }
                }
                .disabled(busy != nil || !canBackup)
                .accessibilityIdentifier("webdav.backup")
                if let error {
                    ErrorRow(message: error).accessibilityIdentifier("webdav.error")
                }
            } footer: {
                if s.encrypt && encPassword.isEmpty { Text("请先填写加密密码。").foregroundStyle(Theme.warn) }
            }
            .listRowBackground(Theme.card)

            Section {
                if busy == "list" {
                    HStack { ProgressView().controlSize(.small); Text("正在读取…").foregroundStyle(.secondary) }
                } else if listed && files.isEmpty {
                    Text("服务器上还没有备份。").foregroundStyle(.secondary)
                }
                ForEach(files) { f in
                    Button { pendingRestore = f } label: { fileRow(f) }
                        .buttonStyle(.plain)
                        .swipeActions {
                            Button(role: .destructive) { pendingDelete = f } label: { Label("删除", systemImage: "trash") }
                        }
                        .accessibilityIdentifier("webdav.file.\(f.name)")
                }
            } header: {
                HStack {
                    Text("服务器上的版本")
                    Spacer()
                    Button { Task { await list() } } label: { Image(systemName: "arrow.clockwise") }
                        .disabled(busy != nil || !(s.configured || WebDAVClient.demo))
                        .accessibilityLabel(Text("刷新"))
                        .accessibilityIdentifier("webdav.refresh")
                }
            } footer: {
                Text("轻点一个版本恢复，左滑删除。恢复前会自动保存一个配置快照。")
            }
            .listRowBackground(Theme.card)
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(Theme.bg.ignoresSafeArea())
        .navigationTitle("WebDAV 备份")
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: s) { v in v.save() }
        .onChange(of: password) { _ = Keychain.write(WebDAVSettings.passwordAccount, $0) }
        .onChange(of: encPassword) { _ = Keychain.write(WebDAVSettings.encryptionAccount, $0) }
        .task { if s.configured || WebDAVClient.demo { await list() } }
        .confirmationDialog("恢复这个版本会覆盖当前的同名配置与设置", isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }), titleVisibility: .visible) {
            Button("恢复", role: .destructive) { if let f = pendingRestore { restore(f) }; pendingRestore = nil }
            Button("取消", role: .cancel) { pendingRestore = nil }
        }
        .confirmationDialog("从服务器删除这个版本？", isPresented: Binding(get: { pendingDelete != nil }, set: { if !$0 { pendingDelete = nil } }), titleVisibility: .visible) {
            Button("删除", role: .destructive) { if let f = pendingDelete { delete(f) }; pendingDelete = nil }
            Button("取消", role: .cancel) { pendingDelete = nil }
        }
        .sheet(item: $encrypted) { e in
            BackupPasswordSheet(data: e.data) { n in
                encrypted = nil
                // After the sheet has gone, or the alert has nothing to present on.
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { message = String(localized: "已恢复 \(n) 个文件") }
            }
        }
        .alert("WebDAV 备份", isPresented: Binding(get: { message != nil }, set: { if !$0 { message = nil } })) {
            Button("好") { message = nil }
        } message: { Text(message ?? "") }
    }

    var canBackup: Bool { (s.configured || WebDAVClient.demo) && (!s.encrypt || !encPassword.isEmpty) }

    func fileRow(_ f: WebDAVFile) -> some View {
        HStack(spacing: 10) {
            Image(systemName: f.encrypted ? "lock.doc" : "doc.text").foregroundStyle(Theme.accent).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: (f.stamp ?? f.modified).map { $0.formatted(date: .abbreviated, time: .standard) } ?? f.name)
                    .font(.subheadline.weight(.semibold))
                HStack(spacing: 6) {
                    if f.encrypted { Text("已加密") }
                    if let sz = f.size { Text(verbatim: Fmt.bytes(sz)) }
                }
                .font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            Image(systemName: "arrow.down.circle").foregroundStyle(.secondary)
        }
        .contentShape(Rectangle())
    }

    func backup() {
        busy = "backup"
        error = nil
        Keychain.write(WebDAVSettings.passwordAccount, password)
        Keychain.write(WebDAVSettings.encryptionAccount, encPassword)
        let settings = s
        Task {
            defer { busy = nil }
            do {
                let (_, n, removed) = try await WebDAVClient.backup(settings)
                message = removed > 0 ? String(localized: "已备份 \(n) 个文件，删除了 \(removed) 个旧版本") : String(localized: "已备份 \(n) 个文件")
                await list()
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    func list() async {
        busy = "list"
        defer { if busy == "list" { busy = nil } }
        do {
            let t = try WebDAVClient.transport(s)
            files = WebDAVClient.sorted(try await t.list())
            listed = true
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    func restore(_ f: WebDAVFile) {
        busy = "restore"
        Task {
            defer { busy = nil }
            do {
                let data = try await WebDAVClient.transport(s).get(f.name)
                if BackupCrypto.isEncrypted(data) {
                    encrypted = EncryptedData(data: data)
                    return
                }
                let n = try BackupRestore.apply(data)
                message = String(localized: "已恢复 \(n) 个文件")
            } catch {
                self.error = error.localizedDescription
            }
        }
    }

    func delete(_ f: WebDAVFile) {
        Task {
            do {
                try await WebDAVClient.transport(s).delete(f.name)
                files.removeAll { $0.id == f.id }
            } catch {
                self.error = error.localizedDescription
            }
        }
    }
}
