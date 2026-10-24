# B7: TLS 终止 — Swift 侧草稿设计文档

> **⚠ 验收修正（Muse，2026-10-24）**：本草稿第一版的 `LeafCertIssuer.swift`
> 使用了 `SecCertificateCreateWithCertificateTemplate` 与 `SecPKCS12Export`——
> **这两个 API 在 Apple 公开 SDK 中不存在**（iOS 没有公开的证书创建 API，
> PKCS#12 只有导入 `SecPKCS12Import`、没有导出）。第一版代码无法编译。
> `LeafCertIssuer.swift` 已重写为手搓 DER 构建 TBS + `SecKeyCreateSignature`
> 签名（并对齐 Go 的共享 leafKey 语义）；PKCS#12 改为 `PKCS12Exporting`
> 接口位，未实现前 `pkcs12Data` 为 nil，待 B6 决定（手搓 PBES2 writer /
> Go 侧继续产出 identity）。下方原文中涉及这两个伪 API 的表格行与
> 可用性说明已逐处修正。参数调研部分（P-256、-48h、1 年、120-bit、
> 通配规则、maxCertNames=64）经核对与 `bridge/mitm/ca.go` 一致；
> `CertCache.swift` 验收通过、未改动。

本目录包含 B7（原生 MitM 中的 TLS 终止）的 **自包含 Swift 草稿实现**，供在 Xcode 工程中集成测试。Go 侧 flow API（B6）尚未定稿，因此接口处留出了对齐点。

---

## 文件清单

| 文件 | 说明 |
|------|------|
| `LeafCertIssuer.swift` | 按主机签发叶证书（手搓 DER + SecKeyCreateSignature）；PKCS#12 为接口位 |
| `CertCache.swift` | 线程安全有界 LRU 缓存（叶证书 / P12） |
| `README.md` | 本文档 |

---

## 1. 接口清单

### 1.1 `LeafCertIssuer`

```swift
public final class LeafCertIssuer: Sendable {
    public init(caCertificate: SecCertificate,
                caPrivateKey: SecKey,
                config: LeafCertConfig) throws

    public func issueLeafCertificate(for hostname: String,
                                     extraDNSNames: [String] = []) throws -> LeafCertResult
}
```

**输入**：
- `caCertificate: SecCertificate` — CA 证书（由 Go 侧生成、通过 App Group 传入或在扩展内加载）
- `caPrivateKey: SecKey` — CA 私钥（ECDSA P-256，`kSecAttrKeyTypeECSECPrimeRandom`，256 位）
- `config: LeafCertConfig` — 签发参数（见下）

**输出**：`LeafCertResult`
- `leafCertificateDER: Data` — 叶证书 DER
- `chainDER: [Data]` — 证书链 `[leaf, CA]`
- `leafPrivateKey: SecKey` — 叶私钥（ECDSA P-256）
- `pkcs12Data: Data` — PKCS#12（含叶证书+私钥+CA证书，Modern 编码，密码保护）
- `hostname: String` — 目标主机名
- `notBefore / notAfter: Date` — 有效期

**错误**：`LeafCertError`（`invalidCAPrivateKey`、`certificateCreationFailed`、`pkcs12CreationFailed` 等）

---

### 1.2 `LeafCertConfig`

```swift
public struct LeafCertConfig: Sendable {
    public var keyAlgorithm: KeyAlgorithm = .ecdsaP256
    public var validityDays: Int = 365              // 1 年（Go 侧同）
    public var notBeforeOffset: TimeInterval = -48*3600  // -48h（Go 侧同）
    public var addWildcardSAN: Bool = true          // a.example.com → *.example.com
    public var maxExtraDNSNames: Int = 64           // Go 侧 maxCertNames
    public var pkcs12Password: String               // 必填，非空
}
```

---

### 1.3 `CertCache<Value>` / `LeafCertCache` / `PKCS12Cache`

```swift
public final class CertCache<Value: Sendable>: @unchecked Sendable {
    public init(capacity: Int = 64)
    public func get(_ key: String) -> Value?
    public func set(_ key: String, _ value: Value) -> Value?  // 返回被淘汰的旧值
    public func remove(_ key: String) -> Value?
    public func removeAll()
    public var count: Int { get }
    public var isFull: Bool { get }
    public func keys() -> [String]      // MRU → LRU
    public func snapshot() -> [(String, Value)]
}
```

**复合键**（匹配 Go 侧 `cache[key]` 逻辑）：
```swift
// hostname + "|" + extraDNSNames.joined(separator: ",")
CertCache.compositeKey(hostname: "a.example.com", extraDNSNames: ["b.example.com"])
// → "a.example.com|b.example.com"
```

---

## 2. 与 B6（Go 侧 Flow API）需对齐的开放问题

| 问题 | 当前草稿处理 | 需与 B6 确认 |
|------|-------------|--------------|
| **CA 材料从何而来** | `LeafCertIssuer.init` 接收 `SecCertificate` + `SecKey`。假设 Go 侧在 App Group 容器写 `ca.pem`/`ca.key`，Swift 侧启动时用 `SecCertificateCreateWithData` + `SecKeyCreateWithData` 加载。 | B6 是否提供 `SecKey` 直接句柄？或仅提供 PEM/DER 由 Swift 侧导入？是否需要 Keychain 存储？ |
| **CA 私钥是否常驻内存** | 当前设计：`LeafCertIssuer` 持有 `SecKey` 引用。扩展生命周期内常驻。 | 若 B6 要求 CA 私钥**不进入扩展内存**，需改为每次签发调用 Go 侧 RPC（性能/权衡）。 |
| **叶私钥策略** | 草稿**每次签发生成新叶私钥**（`SecKeyCreateRandomKey`）。Go 侧用**共享叶密钥**（`ca.leafKey`）仅做签名。 | 共享叶密钥可减少密钥生成开销，但需同步导出。建议 B6 定稿后对齐：要么 Swift 侧也持有共享叶密钥，要么每次生成。 |
| **握手失败上报通道** | **未实现**（草稿仅管签发/缓存）。需在 TLS 握手回调（`GetCertificate`）捕获失败，经由 B6 定义的回调/Channel 上报 Go 侧，供证书固定判断（`pinned/strikes` 逻辑）。 | B6 需定义：`onTLSHandshakeFailure(host: String, error: Error, certSent: Bool)` 等回调签名、调用时机、线程模型。 |
| **PKCS#12 导出用途** | 仅用于**真机验证**（iOS 17/18 导入“设置 → 通用 → VPN 与设备管理”查看信任链）。运行时**不**用 P12 做握手。 | 确认是否需要在扩展内把 P12 写入 App Group 供主 App 读取/分享。 |
| **证书有效期上限** | 365 天（Go 侧同）。iOS 17+ 仍执行 825 天上限，365 安全。 | 若 B6 以后改用更短有效期（如 90 天），同步修改 `validityDays`。 |
| **SAN 扩展名一致性** | 草稿实现：`DNSNames` + `IPAddresses` + 可选 `*.suffix`。 | 与 Go 侧 `LeafWithNames` 完全对齐（已按 `ca.go` 逻辑复刻）。 |
| **EKU** | `serverAuth`（`kSecExtKeyUsageServerAuth`）。 | Go 侧 `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}` 一致。 |
| **KeyUsage** | `DigitalSignature`（`kSecKeyUsageDigitalSignature`）。 | Go 侧同。 |
| **BasicConstraints** | `CA=false`。 | 隐含。 |
| **序列号** | 120-bit 随机（Go 侧 `big.Int.Lsh(1, 120)`）。 | 已对齐。 |

---

## 3. 参数与 Go 侧一致性对照表

| 参数 | Go 侧 (`bridge/mitm/ca.go`) | Swift 草稿 (`LeafCertConfig`) | 备注 |
|------|----------------------------|------------------------------|------|
| 密钥算法 | `ecdsa.GenerateKey(elliptic.P256())` | `KeyAlgorithm.ecdsaP256` | 仅支持 P-256 |
| 叶密钥 | 共享 `ca.leafKey`（启动时生成一次） | **每次签发生成新密钥** | 见开放问题 |
| 有效期 | `NotAfter: now.AddDate(1, 0, 0)` | `validityDays = 365` | 1 年 |
| NotBefore | `now.Add(-48 * time.Hour)` | `notBeforeOffset = -48*3600` | -48h |
| KeyUsage | `x509.KeyUsageDigitalSignature` | `kSecKeyUsageDigitalSignature` | |
| ExtKeyUsage | `x509.ExtKeyUsageServerAuth` | `kSecExtKeyUsageServerAuth` | |
| SAN: DNS | `tpl.DNSNames = [host] + wildcard + extra` | `dnsNames` 数组 | 完全对齐 |
| SAN: IP | `tpl.IPAddresses = [ip]` | `ipAddresses` 数组 | |
| 通配符 SAN | `*.example.com` for `a.example.com` | `addWildcardSAN = true` | 同一逻辑 |
| 额外 DNS 上限 | `maxCertNames = 64` | `maxExtraDNSNames = 64` | |
| 序列号 | 120-bit 随机 | 120-bit 随机（清最高位保正数、最小长度 DER INTEGER，不强加 0x00 前缀） | |
| PKCS#12 | `go-pkcs12.Modern.Encode` | **无公开导出 API**（已改 `PKCS12Exporting` 接口位） | 待 B6 决定实现路线 |
| CA 导入验证 | `MobileConfig()` 生成 `.mobileconfig` | **未实现**（主 App 负责） | Swift 侧仅导出 P12 |

---

## 4. 真机验证要点（iOS 17/18）

### 4.1 PKCS#12 导入验证流程
1. 在扩展内调用 `LeafCertIssuer.issueLeafCertificate` 获得 `pkcs12Data`。
2. 将 `pkcs12Data` 写入 App Group 共享容器（如 `shared/p12/<host>.p12`）。
3. 主 App 读取并通过 `UIDocumentInteractionController` 或 `UIActivityViewController` 分享，或写入 Files.app。
4. 在真机上打开 `.p12` 文件 → “设置 → 通用 → VPN 与设备管理” → 点击描述文件安装。
5. 安装后进入“证书信任设置”，为对应根证书（CA）开启“完全信任”。
6. 在 Safari / curl 访问目标站点，确认 TLS 握手成功、证书链完整。

### 4.2 验证检查清单
- [ ] 叶证书 `Subject CN` 等于目标主机名。
- [ ] SAN 包含目标主机名（或 IP）、通配符（如适用）、额外 DNS 名。
- [ ] EKU 含 `Server Authentication (1.3.6.1.5.5.7.3.1)`。
- [ ] Key Usage 含 `Digital Signature`。
- [ ] Basic Constraints `CA:FALSE`。
- [ ] 证书链：Leaf → CA（自签根）。
- [ ] 有效期 ≤ 365 天，NotBefore 约 48h 前。
- [ ] 签名算法：`ecdsa-with-SHA256`（P-256）。
- [ ] 导入 P12 无报错，安装后信任设置可开启。

### 4.3 常见坑
| 现象 | 原因 | 对策 |
|------|------|------|
| “证书无效/不受信任” | CA 根证书未在“证书信任设置”开启完全信任 | 引导用户开启；或通过 MDM/监督模式自动信任 |
| “无法验证服务器身份” | SAN 缺失目标主机名 | 检查 `extraDNSNames` 传递、IP vs DNS 匹配 |
| P12 导入提示“密码错误” | `pkcs12Password` 与导入时输入不一致 | 统一用固定密码或由用户指定并记录 |
| 握手失败但无上报 | 缺少 B6 回调对接 | 待 B6 定稿后补齐 |

---

## 5. 集成指引（草稿）

### 5.1 在 PacketTunnel 扩展中使用

```swift
// 启动时加载 CA
let caURL = AppShared.homeURL.appendingPathComponent("engine/ca/ca.pem")
let keyURL = AppShared.homeURL.appendingPathComponent("engine/ca/ca.key")
let caDER = try Data(contentsOf: caURL)
let keyDER = try Data(contentsOf: keyURL)

let caCert = SecCertificateCreateWithData(nil, caDER as CFData)!
let caKey = try importPrivateKey(keyDER)  // 需实现：SecKeyCreateWithData + 属性

let config = LeafCertConfig(pkcs12Password: "fixed-or-user-password")
let issuer = try LeafCertIssuer(caCertificate: caCert, caPrivateKey: caKey, config: config)
let cache = LeafCertCache(capacity: 128)

// 在 TLS 握手回调（GetCertificate）中：
func getCertificate(for hostname: String, extraDNSNames: [String]) -> SecCertificate? {
    let key = CertCache.compositeKey(hostname: hostname, extraDNSNames: extraDNSNames)
    if let cached = cache.get(hostname: hostname, extraDNSNames: extraDNSNames) {
        return SecCertificateCreateWithData(nil, cached.leafCertificateDER as CFData)
    }
    do {
        let result = try issuer.issueLeafCertificate(for: hostname, extraDNSNames: extraDNSNames)
        _ = cache.set(hostname: hostname, extraDNSNames: extraDNSNames, value: result)
        // 可选：写 P12 到共享容器供真机验证
        try result.pkcs12Data.write(to: p12URL(for: hostname))
        return SecCertificateCreateWithData(nil, result.leafCertificateDER as CFData)
    } catch {
        // TODO: 经由 B6 回调上报握手失败
        return nil
    }
}
```

### 5.2 CA 私钥导入辅助（需补全）

```swift
func importPrivateKey(_ pkcs8DER: Data) throws -> SecKey {
    let options: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        kSecAttrKeySizeInBits as String: 256,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(pkcs8DER as CFData, options as CFDictionary, &error) else {
        throw LeafCertError.invalidCAPrivateKey
    }
    return key
}
```

---

## 6. 无法在无 Xcode 环境下验证的部分

| 功能 | 原因 | 建议验证方式 |
|------|------|--------------|
| `SecKeyCreateWithData` 导入 PKCS#8 私钥 | 需真机/模拟器运行 Security.framework | 单元测试在 Xcode 中跑 `SecKeyCreateWithData` + `SecKeyCopyPublicKey` 校验 |
| 手搓 DER 签发（重写版 `LeafCertIssuer`） | 需 Xcode 编译 + 真机/模拟器运行 | 在真机扩展中跑 `issueLeafCertificate`，用 `openssl x509 -in leaf.der -text -noout` 校验字段，并用 CA 公钥 `openssl verify` |
| PKCS#12 导出 | 公开 API 不存在，待 `PKCS12Exporting` 实现（手搓 PBES2）或 Go 侧产出 | 实现后 `openssl pkcs12 -in file.p12 -nodes -info` 校验内容 |
| PKCS#12 在 iOS 17/18 真机导入安装 | 需真机、设置 App、证书信任 UI | 实机测试（TestFlight 或开发者签名） |
| TLS 握手回调中的 `GetCertificate` 实际调用 | 需 NetworkExtension 真实流量 | 在 PacketTunnel 中接入 `NWListener` / `libmihomo` 回调验证 |
| 内存/性能（扩展 50 MB jetsam 限制） | 需真实负载 | `MemoryGuard` + `Instruments` 监测缓存命中率、内存占用 |
| 并发签发竞争（多连接同一主机） | 需并发压测 | `DispatchQueue.concurrentPerform` 压测 `LeafCertIssuer` + `CertCache` |

---

## 7. 后续演进（B6 定稿后）

1. **对齐 CA 材料传递**：Go 侧提供 `SecKey` 句柄或 PEM/DER，Swift 侧统一加载路径。
2. **叶密钥策略统一**：若 Go 侧坚持共享叶密钥，Swift 侧改为持有 `leafKey: SecKey` 复用。
3. **握手失败上报**：实现 `TLSHandshakeReporter` 协议，按 B6 定义的回调签名上报 `host`、`error`、`certSent`。
4. **证书固定判断联动**：Go 侧 `pinned/strikes` 逻辑收到上报后决定是否放行，Swift 侧只管上报。
5. **配置下发**：`LeafCertConfig` 可从 Go 侧配置（`engine.json` 或新的 `mitm.json`）读取，避免硬编码。
6. **审计日志**：签发/缓存命中/握手失败统一写入 `TunnelErrorLog` 或 Go 侧 `RequestLog`。

---

## 8. 依赖与编译要求

- **最低部署目标**：iOS 15.0+（重写版仅用 `SecKeyCreateSignature`、`SecKeyCreateRandomKey`、`SecCertificateCreateWithData` 等长期公开 API，无版本敏感点）
- **框架**：`Security.framework`、`Foundation`
- **权限**：无额外 entitlement；CA 私钥读取需 App Group 容器访问权限
- **Swift 版本**：5.9+（`@unchecked Sendable`、严格并发）

---

## 9. 变更记录

| 日期 | 版本 | 说明 |
|------|------|------|
| 2025-01-XX | v0.1 | 初始草稿：LeafCertIssuer、CertCache、README |

---

> **注意**：本草稿**未在 Xcode 编译/真机运行**，仅按 Go 侧 `ca.go` 逻辑和公开 Security.framework API 推导实现。集成前请在 Xcode 中完整编译、跑单测、真机验证 P12 导入与 TLS 握手。