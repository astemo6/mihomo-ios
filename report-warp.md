# Cloudflare WARP MASQUE（cf-connect-ip）接入交付报告

- **分支**：`feat/nc-masque-warp`
- **基线**：`fix/nc-combine-2` @ `de14927`
- **任务目标**：完成 Cloudflare WARP MASQUE（`cf-connect-ip`）纯 Swift 客户端核心接入（代码实现 + 单测 + docs + 交付报告），支持 mTLS 客户端自签证书生成、服务端公钥固定比对、Extended CONNECT `cf-connect-ip` 请求协商与本地地址即时回退。

---

## 1. 改动文件清单

1. `Shared/NativeCore/NCMASQUEWarp.swift`（**新建**）：
   - `parsePrivateKey(_:) -> SecKey?`：支持 PKCS#8 DER、SEC 1 DER 与 PEM（`PRIVATE KEY` / `EC PRIVATE KEY`）格式的 P-256 私钥解析，支持标准与 URL-safe base64 以及缺失 padding 容忍；提取 32 字节标量，通过 CryptoKit `P256.Signing.PrivateKey(rawRepresentation:)` 导出公开点，组装 ANSI X9.63（`04||X||Y||K`，私钥标量位于末尾 32 字节）并通过 `SecKeyCreateWithData` 构建 `SecKey`。
   - `publicPoint(fromConfiguredKey:) -> Data?`：将配置中的公钥归一化为 65 字节未压缩 EC 点（支持 SPKI DER base64、裸 65B 点以及 PEM 格式），并校验曲线上有效性。
   - `peerPointMatches(leafCertDER:configuredPoint:) -> Bool`：纯函数，解析服务端叶证书 DER，提取公钥未压缩点并与配置点进行比对。
   - `makeClientCertificateDER(privateKey:notBefore:) -> Data?`：手写极简 X.509 DER 编码器，生成 Cloudflare WARP 认证专用的自签客户端证书（Version 3、Serial 0、NotBefore=now、NotAfter=now+24h、空 Issuer/Subject、无扩展、ECDSA-SHA256 签名）；兼容 SecKey 返回 DER 序列与 raw R‖S 两种签名格式。
   - `makeLocalIdentity(config:) -> SecIdentity?`：门面函数，将客户端证书 DER 与私钥封装为 `SecIdentity`。
   - `validate(privateKey:publicKey:) -> String?`：供 `NCSupport` 调用的纯校验函数，分别校验私钥可解析与公钥可归一。
   - `NCMASQUEWarpError`：结构化错误枚举与中文错误文案（`warpKeyInvalid`、`warpPublicKeyInvalid`、`warpPinMismatch`、`warpIdentityFailed`）。

2. `Shared/NativeCore/NCMASQUE.swift`：
   - `NCMASQUE.Config` 增加计算属性 `var isWarp: Bool { mode == .connectIP && !(privateKey ?? "").isEmpty && !(publicKey ?? "").isEmpty }`。
   - `Config.init?(proxy: NCProxy)`：在 WARP 模式下，若节点未显式配置 `sni`，缺省使用 `NCMASQUE.defaultWarpSNI`（`"consumer-masque.cloudflareclient.com"`）。

3. `Shared/NativeCore/NCMASQUEIP.swift`：
   - `NCMASQUEIPTunnel.openRequest()`：WARP 模式下请求伪头 `:protocol` 取 `"cf-connect-ip"`，通用 CONNECT-IP 保持 `"connect-ip"`。
   - `consumeFrames()`：WARP 模式下收到 2xx HEADERS 后不再等待 3 秒，直接调用 `fallbackAddress()` 绑定本地 `ip` / `ipv6`；若地址无效或缺失则以明确中文错误失败。
   - `fallbackAddress()`：访问级别由 `private` 调整为 `internal`，以便单元测试直接覆盖回退逻辑。

4. `Shared/NativeCore/NCMASQUESession.swift`：
   - `NCMASQUEConnection` 增加 `private var cachedIdentity: SecIdentity?` 属性。
   - `start(completion:)`：在 WARP 模式下前置构造本地身份并缓存，若构造失败直接以 `warpIdentityFailed` 失败，避免静默降级。
   - `makeQUICOptions()`：
     - 若为 WARP 且未配置 SNI，使用默认 WARP SNI；
     - 通过 `sec_protocol_options_set_local_identity` 注入客户端身份；
     - 设置 `sec_protocol_options_set_verify_block` 执行服务端公钥固定校验（覆盖 `skipCertVerify` 语义，直接比对未压缩点，不调用系统信任链评估）。
     - 非 WARP 模式保持原逻辑不变。

5. `Shared/NativeCore/NCSupport.swift`：
   - `masqueUnsupported(_:)` 的 `case .connectIP:` 分支中，当存在密钥对时，调用 `NCMASQUEWarp.validate(privateKey:priv, publicKey:pub)` 进行纯校验。校验失败返回结构化中文错误，校验成功返回 `nil` 放行。

6. `UnitTests/NativeCoreMASQUEIPTests.swift`：
   - 扩充约 300 行针对 WARP 的全面单元测试：
     - 私钥解析测试：PKCS#8、SEC 1、PEM（两种标头）、URL-safe base64 以及格式错误与负例；
     - 公钥归一化测试：SPKI base64、裸 65B 点、PEM 格式以及负例比对；
     - 客户端证书 DER 结构与 24 小时有效期测试；
     - 服务端证书固定比对（正例与反例）；
     - `cf-connect-ip` Extended CONNECT 请求头 QPACK 编码与反解断言；
     - `makeLocalIdentity` 身份构造测试；
     - `fallbackAddress` 地址即时回退测试；
     - `NCSupport.masqueUnsupported` 校验及错误信息分类测试；
     - `NCMASQUE.Config` WARP 属性与默认 SNI 测试。

7. `docs/nc-proto-masque.md`：
   - 更新 WARP 状态说明、请求伪头、客户端证书结构、服务端公钥固定比对与本地地址回退机制。

---

## 2. 关键设计决定与理由

1. **SecIdentity 构造路线选择**：
   - **核查结论**：查验 `project.yml` 可知，`Tern`（App 目标）、`PacketTunnel`（扩展目标）以及 `TernUnitTests` 均包含 `PacketTunnel/NativeMitM/TLS`（其中包含 `NCPKCS12Exporter.swift`）。在既有代码库中，`Shared/NativeCore/NCCAManager.swift:277` 已经直接调用了 `NCPKCS12Exporter.shared.export(...)` 配合系统 `SecPKCS12Import` 从证书 DER 与私钥导出/提取 `SecIdentity`。
   - **选择理由**：沿用该仓内先例路线最为稳健、完全无跨 target 符号缺失风险。临时生成的 PKCS#12 在内存中通过 `SecPKCS12Import` 解构出 `SecIdentity`，无需任何外部依赖，且不会在系统持久化 Keychain 中留下长效脏数据。

2. **身份生命周期与连接层缓存**：
   - Cloudflare 官方客户端按每次连接动态生成客户端证书。本实现在连接对象 `NCMASQUEConnection` 内部按连接缓存 `cachedIdentity`，在当前连接的整个生命周期内复用该身份实例（避免打开控制流与请求流时重复导出/解析 PKCS#12），连接释放时自动销毁，内存开销可控。

3. **公钥固定覆盖 skip-cert-verify**：
   - Cloudflare WARP 服务端证书为自签名或专属 CA 证书，生产中 WARP 节点的安全性依赖于配置中 `public-key` 的精确固定比对。因此在 WARP 模式下，TLS 验证块强制执行叶证书公钥比对，即使用户节点配置了 `skip-cert-verify: true` 亦不得绕过固定校验；且校验完全在纯内存点比对中完成，不调用系统 SecTrust 信任评估。

4. **无 ADDRESS_ASSIGN 时的即时回退**：
   - 经三方公开实现与 qlog 验证，Cloudflare WARP 服务端不会下发 RFC 9484 的 `ADDRESS_ASSIGN` 胶囊，而是预期客户端在握手成功（2xx）后直接使用注册时获得的固定 IP（保存在节点配置的 `ip` / `ipv6`）发包。因此，收到 2xx HEADERS 后直接执行 `fallbackAddress()` 绑定网卡地址，不等待通用 CONNECT-IP 的 3 秒回退定时器。

---

## 3. 未做项与范围边界

- **WARP 账户注册（Issue #164 第 6 项）**：按照任务简报要求本轮不做。节点配置所需的 `private-key`、`public-key` 与 `ip`/`ipv6` 需通过配置 YAML 或分享链接预先提供。
- **现网真机端到端联调与 CI**：本机无 Xcode 与真机环境，未运行外部联调与 CI。交付标准为严格的静态自洽、符号签名匹配、括号平衡与 term_audit 检查，真机与现网互通由维护者后续推进。

---

## 4. 自检与合规性

1. **上游品牌词检查**：
   - 运行 `python3 scripts/term_audit.py` 退出码 0，全仓零残留、零违规。
   - 全代码、文档与注释中均未引入任何被禁止的上游项目名称。
2. **非 WARP 行为保持**：
   - 非 WARP CONNECT-IP 节点（无密钥对或非 connect-ip 模式）依旧按通用 RFC 9484 路径工作（等待 ADDRESS_ASSIGN、3 秒回退、系统证书验证/skipCertVerify），逻辑完全互不影响。
3. **静态自洽性**：
   - 所有调用的 Security、CryptoKit 与 Network framework API 均对照系统头文件与仓内用法逐一核对签名；
   - 括号与字符串闭合性通过自动化脚本验证，全部配平。
