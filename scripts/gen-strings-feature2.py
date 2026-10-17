#!/usr/bin/env python3
"""Generates the feature2 (A2) string resources from one table.

  app/src/main/res/values/strings_feature2.xml          简体中文 (default)
  app/src/main/res/values-en/strings_feature2.xml       English
  app/src/main/res/values-b+zh+Hant/strings_feature2.xml 繁體中文 (OpenCC s2twp from the zh column)

Run: python3 scripts/gen-strings-feature2.py   (繁體 needs `pip install opencc-python-reimplemented`)
Every key is prefixed f2_ so it never collides with the shared values/strings.xml.
"""
import os
import re
import sys

T = r"""
f2_rulesets_title | 规则列表 | Rule Lists
f2_dns_title | DNS 日志 | DNS Log
f2_traffic_title | 流量统计 | Traffic
f2_nodesubs_title | 订阅管理 | Node Subscriptions
f2_groups_title | 策略组编辑 | Policy Groups
f2_manual_title | 手动节点 | Manual Nodes
f2_diag_title | 诊断 | Diagnostics
f2_unknown_title | 未知页面 | Unknown page
f2_ok | 好 | OK
f2_search | 搜索 | Search
f2_done_n | 完成 (%1$d) | Done (%1$d)
f2_add | 添加 | Add
f2_add_n | 添加 %1$d 条 | Add %1$d
f2_advanced | 高级 | Advanced
f2_advanced_footer | ECH 与证书指纹需要服务端配合；多路复用要求服务端开启 sing-mux。「IP 版本」留空时使用「连接与内核 → IP 优先」。 | ECH and certificate pinning need server support; multiplexing needs sing-mux on the server. An empty "IP version" uses Connection → IP preference.
f2_auto_update | 自动更新 | Auto update
f2_basic | 基本 | Basic
f2_clear | 清空 | Clear
f2_copied | 已复制 | Copied
f2_copy_link | 复制链接 | Copy link
f2_copy_suffix | 副本 | copy
f2_current | 当前 | Current
f2_daily | 每天 | Daily
f2_days_n | %1$d 天 | %1$d d
f2_hours_n | %1$d 小时 | %1$d h
f2_every_hours_n | 每 %1$d 小时 | Every %1$d h
f2_weekly | 每周 | Weekly
f2_default | 默认 | Default
f2_delete_q | 删除？ | Delete?
f2_edit | 编辑 | Edit
f2_enabled | 启用 | Enabled
f2_err_empty_name | 名称不能为空 | The name cannot be empty
f2_err_name_clash | 已有同名的策略组或节点 | A group or node with this name already exists
f2_examples | 示例（轻点填入） | Examples (tap to use)
f2_expires | 到期 %1$s | Expires %1$s
f2_filter | 过滤 | Filter
f2_hidden | 隐藏 | Hidden
f2_import | 导入 | Import
f2_kept_of | 保留 %1$d / 共 %2$d | Kept %1$d of %2$d
f2_live_preview | 实时预览 | Live preview
f2_members_n | %1$d 个成员 | %1$d members
f2_more_n | 另有 %1$d 条 | %1$d more
f2_n_nodes | %1$d 个节点 | %1$d nodes
f2_n_rules | %1$d 条 | %1$d rules
f2_name | 名称 | Name
f2_name_auto | 留空自动获取 | Leave empty to detect
f2_need_connect | 未连接：连接后才有数据。 | Not connected: data appears once connected.
f2_no_profile | 请先添加并选择一个配置 | Add and select a profile first
f2_none | 无 | None
f2_off | 关闭 | Off
f2_on | 开启 | On
f2_params | 参数 | Parameters
f2_paste | 从剪贴板粘贴 | Paste
f2_pause | 暂停 | Pause
f2_policy | 策略 | Policy
f2_port | 端口 | Port
f2_preview | 预览 | Preview
f2_preview_empty | 没有可预览的节点（节点集未下载时，连接一次后再来看） | Nothing to preview (providers that are not downloaded yet appear after one connection)
f2_providers_n | %1$d 个节点集 | %1$d providers
f2_restore | 恢复 | Restore
f2_revert | 还原未保存的修改 | Revert unsaved changes
f2_rule | 规则 | Rule
f2_save | 保存 | Save
f2_saved_next_connect | 已保存，下次连接生效 | Saved; applies on the next connection
f2_saved_reloaded | 已保存并重载 | Saved and reloaded
f2_server | 服务器 | Server
f2_share | 分享 | Share
f2_share_unsupported | 这个节点类型不支持分享链接 | This node type has no share link
f2_show_removed | 显示已移除 | Show removed
f2_times_n | %1$d 次 | %1$d×
f2_today | 今天 | Today
f2_last_days_n | 近 %1$d 天 | Last %1$d days
f2_type | 类型 | Type
f2_update | 更新 | Update
f2_update_all | 全部更新 | Update all
f2_updated_at | 更新于 %1$s | Updated %1$s
f2_used_of | 已用 %1$s / %2$s | Used %1$s of %2$s
f2_domain | 域名 | Domain

f2_rules_add | 添加规则 | Add rule
f2_rules_bulk | 批量粘贴 | Paste many
f2_rules_bulk_hint | 每行一条规则 | One rule per line
f2_rules_bulk_footer | 可直接粘贴 Surge [Rule] 段、QX filter_local / filter_remote 段或 Clash rules 列表；以 #、;、// 开头的行和 [段名] 会被跳过。 | Paste a Surge [Rule] section, a QX filter_local / filter_remote block or a Clash rules list; lines starting with #, ;, // and [section] headers are skipped.
f2_rules_custom_n | 自定义规则 %1$d | Custom rules %1$d
f2_rules_edit_title | 自定义规则 | Custom rule
f2_rules_empty | 点右上角 + 添加。自定义规则排在配置规则之前，可以直接粘贴 Surge / Quantumult X / Loon / mihomo 写法，也可以导入远程规则列表。 | Tap + to add. Custom rules go before the profile\'s rules; paste Surge / Quantumult X / Loon / mihomo syntax or import a remote rule list.
f2_rules_footer | 策略名会对应到当前配置的策略组；找不到时使用第一个手动选择组并标黄。远程列表通过内核下载并转换为 mihomo 规则集（rule-provider）；QX filter_remote 没有 force-policy 时整份列表走 proxy。 | Policy names map to the current profile\'s groups; unknown ones fall back to the first select group (shown in yellow). Remote lists become mihomo rule-providers downloaded and converted by the core; a QX filter_remote without force-policy routes the whole list to proxy.
f2_rules_fmt_domainset | 域名集（Surge DOMAIN-SET / Clash domain） | Domain set (Surge DOMAIN-SET / Clash domain)
f2_rules_fmt_list | 规则列表（Surge / Clash classical / QX 列表） | Rule list (Surge / Clash classical / QX list)
f2_rules_fmt_qx | Quantumult X filter_remote | Quantumult X filter_remote
f2_rules_format | 格式 | Format
f2_rules_import_remote | 导入远程规则列表 | Import remote rule list
f2_rules_interval | 远程列表更新间隔 | Remote list update interval
f2_rules_list_url | 列表地址 | List URL
f2_rules_live_check | 输入时实时校验：显示转换后的 mihomo 规则和对应的策略组。 | Checked as you type: shows the converted mihomo rule and its policy group.
f2_rules_providers_n | 规则集 %1$d | Rule providers %1$d
f2_rules_remote_footer | 列表由内核下载并转换，列表里每行的策略会被忽略，整份列表使用这里选择的策略。QX 列表里的 host / host-suffix 等写法会自动转换。 | The core downloads and converts the list; per-line policies are ignored and the whole list uses the policy chosen here. QX host / host-suffix lines are converted.
f2_rules_remote_tag | 远程 | Remote
f2_rules_tag | 名称（tag） | Name (tag)

f2_dns_allow | 放行 | Allow
f2_dns_blocked_note | 被 REJECT / REJECT-DROP 规则拦截的连接（按域名汇总）。「放行」会添加一条 DOMAIN,…,DIRECT 自定义规则。 | Connections stopped by REJECT / REJECT-DROP rules, grouped by domain. "Allow" adds a DOMAIN,…,DIRECT custom rule.
f2_dns_cached | 缓存 | cached
f2_dns_fakeip_note | 当前为 Fake-IP 模式：App 的查询大多直接得到本地分配的 Fake-IP，不会发往上游，因此这里只显示需要真实解析的查询（直连规则、真实 IP 域名、节点域名等）；这些域名在「网络活动」里可以看到。 | Fake-IP mode: most app queries get a local fake address without an upstream query, so only real resolutions (direct rules, real-IP domains, node servers…) appear here; the other domains show up in Activity.
f2_dns_lookup_note | 通过内核的 DNS 设置查询（/dns/query），与 App 实际得到的结果一致。 | Resolved with the core\'s DNS settings (/dns/query), the same answer apps get.
f2_dns_no_blocked | 还没有被拦截的域名 | No blocked domains yet
f2_dns_no_queries | 还没有 DNS 查询记录 | No DNS queries yet
f2_dns_query | 查询 | Look up
f2_dns_rule_added | 已添加放行规则并重载 | Allow rule added and reloaded
f2_dns_tab_blocked | 拦截 %1$d | Blocked %1$d
f2_dns_tab_lookup | DNS 查询工具 | Lookup
f2_dns_tab_queries | 查询 %1$d | Queries %1$d
f2_dns_type | 记录类型 | Record type

f2_traffic_by_policy | 按策略（本次会话） | By policy (this session)
f2_traffic_cellular | 蜂窝 | Cellular
f2_traffic_clear_history | 清除历史记录 | Clear history
f2_traffic_connections | 连接（活动 / 总数） | Connections (active / total)
f2_traffic_direct | 直连 | Direct
f2_traffic_download | 下载 | Download
f2_traffic_history | 历史记录 | History
f2_traffic_history_note | 内核总流量，App 在后台时也会每 30 秒记录一次（与 VPN 服务同进程）；Wi-Fi / 蜂窝按记录时的网络划分。 | Core totals, sampled every 30 s even in the background (same process as the VPN); Wi-Fi / cellular is the network in use at each sample.
f2_traffic_other | 其他 | Other
f2_traffic_peak | 峰值 %1$s | Peak %1$s
f2_traffic_proxy | 代理 | Proxy
f2_traffic_rate | 实时流速 | Rate
f2_traffic_reset | 重置本次统计 | Reset session
f2_traffic_session | 本次会话 | This session
f2_traffic_session_note | 按连接统计，只计入 App 在前台时看到的流量（与 iOS 相同）。 | Counted per connection while the app is in the foreground (as on iOS).
f2_traffic_since | 开始于 %1$s | Since %1$s
f2_traffic_split | 直连 / 代理 | Direct / proxy
f2_traffic_split_note | 来自 App 在前台时的连接记录。 | From connections seen while the app was in the foreground.
f2_traffic_top_hosts | 流量最多的域名 | Top hosts
f2_traffic_top_rules | 命中最多的规则 | Top rules
f2_traffic_total | 合计 | Total
f2_traffic_upload | 上传 | Upload

f2_nodesubs_add | 添加节点订阅 | Add subscription
f2_nodesubs_edit | 编辑节点订阅 | Edit subscription
f2_nodesubs_empty | 节点订阅只提供节点，会以节点集（proxy-provider）的形式加入每个配置的策略组。点右上角 + 添加。 | A node subscription only provides nodes; it joins every profile\'s groups as a proxy-provider. Tap + to add one.
f2_nodesubs_footer | 节点订阅对所有配置生效：启用后作为文件节点集合并进运行配置，配置文件本身不变。 | Node subscriptions apply to every profile: enabled ones are merged into the runtime config as file providers; profile files are unchanged.
f2_nodesubs_groups | 加入的策略组 | Groups
f2_nodesubs_groups_footer | 默认加入含节点的手动选择组和自动选择（url-test）组；选择的组在别的配置中不存在时也按默认处理。 | By default it joins select groups that contain nodes and url-test groups; groups missing in another profile fall back to the default.
f2_nodesubs_link | 订阅链接 | Link
f2_nodesubs_n | 节点订阅 %1$d | Node subscriptions %1$d
f2_nodesubs_providers_n | 当前运行配置中的节点集 %1$d | Providers in the running config %1$d
f2_nodesubs_url | 订阅地址 | Subscription URL

f2_sub_add_flag | 按地区添加旗帜 Emoji | Add a region flag emoji
f2_sub_add_rename | + 添加重命名规则 | + Add rename rule
f2_sub_clear_rules | 清空规则 | Clear rules
f2_sub_dedupe | 去除重复节点（类型、地址、端口、凭据相同） | Remove duplicates (same type, server, port, credential)
f2_sub_dedupe_footer | 同名节点会自动加序号。节点集（proxy-providers）只应用过滤和重命名（mihomo 原生 filter / override），旗帜、去重、排序只作用于配置里直接列出的节点。 | Duplicate names get a number. Providers only get filter and rename (mihomo filter / override); flags, dedupe and sort apply to nodes listed in the profile itself.
f2_sub_dedupe_sort | 去重与排序 | Dedupe and sort
f2_sub_exclude | 排除（匹配的节点会被移除） | Exclude (matching nodes are removed)
f2_sub_filter | 过滤 | Filter
f2_sub_include | 保留（只保留匹配的节点，留空为全部） | Keep (only matching nodes; empty = all)
f2_sub_pattern | 匹配（正则） | Pattern (regex)
f2_sub_prefix | 添加前缀 | Add prefix
f2_sub_prefix_flags | 前缀与旗帜 | Prefix and flags
f2_sub_regex | 使用正则（JavaScript 写法，不区分大小写） | Regex (JavaScript syntax, case-insensitive)
f2_sub_renames | 重命名（按顺序执行） | Rename (in order)
f2_sub_replace | 替换为（$1 引用分组） | Replace with ($1 = group)
f2_sub_rules | 节点处理 | Node rules
f2_sub_rules_enable | 启用节点处理 | Enable node rules
f2_sub_rules_note | 规则只保存在本机覆写里，在生成运行配置时应用；订阅文件本身不改动，更新订阅后规则依然有效。 | Rules are kept in the local overrides and applied when the runtime config is built; the downloaded file is untouched, so they survive updates.
f2_sub_rules_on | 节点处理已开启 | Node rules on
f2_sub_rules_profile | 当前配置的节点处理 | Node rules of the current profile
f2_sub_rules_profile_footer | 过滤、重命名、旗帜、去重和排序当前配置自带的节点和节点集。 | Filter, rename, flag, dedupe and sort the current profile\'s own nodes and providers.
f2_sub_sort | 排序 | Sort
f2_sub_sort_keep | 保持原顺序 | Keep order
f2_sub_sort_name | 按名称 | By name
f2_sub_sort_region | 按地区 | By region
f2_sub_strip_flags | 去掉原有的旗帜 Emoji | Remove existing flag emojis
f2_sub_strip_prefix | 去掉前缀 | Strip prefix
f2_preset_brackets | 去掉括号内容 | Remove bracketed text
f2_preset_hongkong | 「Hong Kong」→「香港」 | "Hong Kong" → "香港"
f2_preset_multiplier | 去掉「| 倍率」等后缀 | Remove "| 2x"-style suffixes
f2_preset_spaces | 合并多余空格 | Collapse spaces

f2_groups_add_member | 添加成员 | Add members
f2_groups_added | 新增 | Added
f2_groups_delete | 删除策略组 | Delete group
f2_groups_delete_q | 删除策略组「%1$s」？ | Delete group "%1$s"?
f2_groups_delete_refs | 其他策略组中对它的引用会一并移除。 | References in other groups are removed too.
f2_groups_delete_rules | 有 %1$d 条规则指向它，删除后改用第一个手动选择组。 | %1$d rules point to it; they will use the first select group.
f2_groups_deleted | 已删除的策略组 | Deleted groups
f2_groups_duplicate | 复制为新策略组 | Duplicate as new group
f2_groups_edit | 编辑策略组 | Edit group
f2_groups_edited | 已修改 | Edited
f2_groups_exclude | 排除（正则） | Exclude (regex)
f2_groups_filter | 筛选（正则，保留匹配的节点） | Filter (regex, keep matches)
f2_groups_filter_footer | 筛选作用于节点集和「包含全部节点」带来的节点；预览按已缓存的节点计算，多个正则可用 ` 分隔。 | Filters apply to provider nodes and "include all"; the preview uses cached nodes. Separate several regexes with `.
f2_groups_footer | 修改保存在本机覆写里（按配置），在生成运行配置时应用，配置文件本身不变。url-test / fallback 组可开启「智能选择」：按近期测速结果打分并固定最佳节点。 | Edits are stored per profile in the local overrides and applied to the runtime config; the profile file is unchanged. url-test / fallback groups can use Smart selection: members are scored from recent checks and the best one is pinned.
f2_groups_icon | 图标链接（可选） | Icon URL (optional)
f2_groups_include_all | 包含全部节点 | Include all nodes
f2_groups_interval | 间隔（秒） | Interval (s)
f2_groups_lazy | 懒惰测速（仅在使用时测速） | Lazy (test only while in use)
f2_groups_matches_n | 匹配 %1$d 个节点 | %1$d nodes match
f2_groups_members_footer | 成员可以是节点、其他策略组、DIRECT / REJECT。 | Members can be nodes, other groups, DIRECT / REJECT.
f2_groups_n | 策略组 %1$d | Groups %1$d
f2_groups_new | 新建策略组 | New group
f2_groups_new_name | 新策略组 | New group
f2_groups_no_providers | 当前配置没有节点集 | The profile has no providers
f2_groups_no_routed | 没有规则直接指向这个策略组 | No rule points to this group
f2_groups_providers_filter | 节点集与筛选 | Providers and filter
f2_groups_restore | 恢复原始 | Restore original
f2_groups_routed_n | 指向此策略组的规则 %1$d | Rules using this group %1$d
f2_groups_strategy | 策略 | Strategy
f2_groups_test | 测速 | Health check
f2_groups_test_url | 测速地址 | Test URL
f2_groups_tolerance | 容差（ms） | Tolerance (ms)
f2_groups_via | 前置代理 | Dialer proxy
f2_groups_via_footer | 先经过另一个节点或策略组再连接（代理链），立即保存；不会形成循环的才可选。 | Connect through another node or group first (proxy chain); saved immediately. Only choices that do not form a loop are listed.
f2_gt_fallback | 故障转移 | Fallback
f2_gt_lb | 负载均衡 | Load balance
f2_gt_select | 手动选择 | Select
f2_gt_urltest | 自动选择（延迟最低） | URL test (lowest latency)
f2_kind_builtin | 内置 | Built-in
f2_kind_group | 策略组 | Group
f2_kind_node | 节点 | Node
f2_lb_hash | 一致性哈希 | Consistent hashing
f2_lb_rr | 轮询 | Round robin
f2_lb_sticky | 粘性会话 | Sticky sessions
f2_smart | 智能 | Smart
f2_smart_nodata | 暂无足够的测速记录，沿用 %1$s | Not enough checks yet, keeping %1$s
f2_smart_summary | 已选 %1$s · 近期平均 %2$d ms · 失败 %3$d/%4$d | Picked %1$s · avg %2$d ms · failed %3$d/%4$d
f2_smart_waiting | 等待首次评分（使用策略组自身的健康检查结果） | Waiting for the first score (uses the group\'s own health checks)

f2_manual_add | 添加节点 | Add node
f2_manual_added_n | 已添加 %1$d 个节点 | Added %1$d nodes
f2_manual_edit | 编辑节点 | Edit node
f2_manual_empty | 还没有手动节点。可以粘贴分享链接导入，或点右上角 + 填写表单。 | No manual nodes yet. Paste share links above or tap + to fill in a form.
f2_manual_export_all | 导出全部（订阅格式） | Export all (subscription)
f2_manual_import | 导入 | Import
f2_manual_import_footer | 支持 ss / ssr / vmess / vless / trojan / hysteria / hysteria2 (hy2) / tuic / wireguard (wg) / snell / anytls / mieru / socks5 / http(s) 分享链接、base64 订阅，以及 Surge / Egern / Quantumult X 的节点行。二维码：用相机或其他扫码 App 扫描后，把得到的链接粘贴到这里。 | Share links (ss / ssr / vmess / vless / trojan / hysteria / hysteria2 / tuic / wireguard / snell / anytls / mieru / socks5 / http(s)), base64 subscriptions and Surge / Egern / Quantumult X node lines. QR codes: scan with the camera or another scanner app and paste the link here.
f2_manual_import_hint | 分享链接或节点行，每行一个 | Share links or node lines, one per line
f2_manual_merge | 把手动节点加入每个配置 | Add manual nodes to every profile
f2_manual_merge_desc | 作为「手动节点」策略组合并进当前配置 | Merged into the current profile as a "manual" group
f2_manual_n | 手动节点 %1$d | Manual nodes %1$d
f2_manual_probe_footer | 出口 IP 与解锁检测通过 MIHOMO-PROBE（127.0.0.1:7899）进行，需要已连接，且节点在当前运行配置中（使用手动节点配置，或开启「加入每个配置」）。 | Exit IP and unlock checks go through MIHOMO-PROBE (127.0.0.1:7899); they need a connection and the node in the running config (use the manual profile or turn on "add to every profile").
f2_manual_profile_name | 手动节点 | Manual nodes
f2_manual_use | 使用方式 | Use
f2_manual_use_profile | 切换到手动节点配置 | Switch to the manual nodes profile
f2_manual_via_footer | 先经过另一个节点或策略组再连接这个节点（代理链）。开启「加入每个配置」后，也可以选择当前订阅里的策略组。 | Connect through another node or group first (proxy chain). With "add to every profile" on, groups of the current profile can be chosen too.

f2_fl_auth | 认证 | Auth
f2_fl_cert_fp | 证书指纹 | Certificate fingerprint
f2_fl_cipher | 加密 | Cipher
f2_fl_congestion | 拥塞控制 | Congestion control
f2_fl_down_bw | 下行带宽 | Download bandwidth
f2_fl_ech_config | ECH 配置（留空则查询 DNS） | ECH config (empty = DNS lookup)
f2_fl_grpc_service | gRPC 服务名 | gRPC service name
f2_fl_https_tls | HTTPS（TLS） | HTTPS (TLS)
f2_fl_ip_version | IP 版本 | IP version
f2_fl_local_ipv4 | 本地 IPv4 | Local IPv4
f2_fl_local_ipv6 | 本地 IPv6 | Local IPv6
f2_fl_multiplexing | 多路复用 | Multiplexing
f2_fl_obfs | 混淆 | Obfs
f2_fl_obfs_host | 混淆 Host | Obfs host
f2_fl_obfs_param | 混淆参数 | Obfs param
f2_fl_obfs_password | 混淆密码 | Obfs password
f2_fl_password | 密码 | Password
f2_fl_peer_public_key | 对端公钥 | Peer public key
f2_fl_plugin | 插件 | Plugin
f2_fl_plugin_host | 插件 Host | Plugin host
f2_fl_plugin_mode | 插件模式 | Plugin mode
f2_fl_plugin_path | 插件路径（v2ray-plugin） | Plugin path (v2ray-plugin)
f2_fl_port_hopping | 端口跳跃 | Port hopping
f2_fl_port_range | 端口范围 | Port range
f2_fl_private_key | 私钥 | Private key
f2_fl_private_key_opt | 私钥（可选） | Private key (optional)
f2_fl_protocol | 协议 | Protocol
f2_fl_protocol_param | 协议参数 | Protocol param
f2_fl_psk | 预共享密钥 | Pre-shared key
f2_fl_reality_pk | Reality 公钥 | Reality public key
f2_fl_shadowtls_password | shadow-tls 密码 | shadow-tls password
f2_fl_shadowtls_version | shadow-tls 版本 | shadow-tls version
f2_fl_skip_cert | 跳过证书验证 | Skip certificate verification
f2_fl_smux | 多路复用（smux） | Multiplexing (smux)
f2_fl_smux_max | 最大连接数 | Max connections
f2_fl_smux_padding | 填充 | Padding
f2_fl_smux_protocol | 复用协议 | Mux protocol
f2_fl_tls_fp | TLS 指纹 | TLS fingerprint
f2_fl_transport | 传输 | Transport
f2_fl_udp_relay | UDP 转发 | UDP relay
f2_fl_up_bw | 上行带宽 | Upload bandwidth
f2_fl_username | 用户名 | Username
f2_fl_version | 版本 | Version
f2_fl_ws_host | WS Host | WS host
f2_fl_ws_path | WS 路径 | WS path

f2_probe_exit | 出口 IP | Exit IP
f2_probe_exit_info | 出口信息 | Exit
f2_probe_footer | 探测请求经过隐藏的 MIHOMO-PROBE 策略组和本机 127.0.0.1:7899 监听，只影响这些请求；一次只能探测一个策略。解锁检测按常见脚本的规则判断，服务改版后可能不准；「检测失败」表示无法读取结果，并非被封锁。 | Probes go through the hidden MIHOMO-PROBE group and the 127.0.0.1:7899 listener and affect nothing else; one policy at a time. Unlock checks follow common region-check heuristics and can drift when a service changes; "check failed" means the answer could not be read, not that it is blocked.
f2_probe_needs_reconnect | 当前连接的配置不含节点探测，请断开后重新连接一次 | The running config has no probe group; disconnect and connect once
f2_probe_no_answer | 所有查询接口都没有响应（节点可能不可用） | No lookup service answered (the node may be down)
f2_probe_none_yet | 还没有探测结果 | No result yet
f2_probe_not_connected | 未连接：节点探测需要先连接代理 | Not connected: probes need a running connection
f2_probe_unknown_policy | 这个策略不在当前运行的配置中 | This policy is not in the running config
f2_probe_unlock | 解锁检测 | Unlock check
f2_probe_unlock_results | 解锁检测 | Unlock check
f2_unlock_badge | 解锁 %1$d/%2$d | Unlocked %1$d/%2$d
f2_svc_bili_hkmotw | 哔哩哔哩 港澳台 | bilibili HK/MO/TW
f2_svc_bili_tw | 哔哩哔哩 台湾 | bilibili Taiwan
f2_un_connect | 连接失败 | Connection failed
f2_un_denied | 被拒绝访问 | Access denied
f2_un_failed | 检测失败 | Check failed
f2_un_no | 不可用 | Unavailable
f2_un_originals | 仅自制剧 | Originals only
f2_un_partial | 部分 | Partial
f2_un_region | 地区不支持 | Region not supported
f2_un_timeout | 超时 | Timed out
f2_un_tls | TLS 失败 | TLS failed
f2_un_unrecognized | 页面无法识别 | Page not recognized
f2_un_waf | 被风控拦截（HTTP 403） | Blocked by WAF (HTTP 403)
f2_un_web_only | 仅网页版（App 拒绝此 IP） | Web only (the app rejects this IP)
f2_un_yes | 解锁 | Unlocked

f2_diag_bundle | 诊断包 | Diagnostics bundle
f2_diag_bundle_footer | 诊断包包含版本、设置、启动日志、最近的内核日志与内存记录、配置结构摘要。服务器地址、密码、UUID、订阅链接、IP 等都会被脱敏。 | The bundle has versions, settings, the startup log, recent core log and memory samples and a profile outline. Servers, passwords, UUIDs, subscription links and IPs are redacted.
f2_diag_connect_normal | 恢复正常连接 | Reconnect normally
f2_diag_connect_safe | 以安全模式连接 | Connect in safe mode
f2_diag_copy_text | 复制为文本 | Copy as text
f2_diag_core | 内核版本 | Core version
f2_diag_export | 导出诊断包（zip） | Export bundle (zip)
f2_diag_last_error | 最近的错误 | Last error
f2_diag_probe | 节点探测 | Node probe
f2_diag_probe_policy | 选择节点或策略组 | Choose a node or group
f2_diag_probe_port | 探测端口 | Probe port
f2_diag_safe_active | 安全模式已开启：本次连接不加载模块、脚本、MitM 和自定义规则。 | Safe mode is on: this connection runs without modules, scripts, MitM and custom rules.
f2_diag_safe_footer | 连接失败或连接后异常时，可以先用安全模式排查：只运行配置本身。恢复正常连接会关闭安全模式并重新连接。 | When connecting fails or misbehaves, safe mode runs the profile alone. Reconnect normally turns it off and connects again.
f2_diag_safe_mode | 安全模式 | Safe mode
f2_diag_saved | 已保存诊断包 | Bundle saved
f2_diag_share_text | 以文本分享 | Share as text
f2_diag_status | 状态 | Status
f2_diag_vpn | VPN | VPN
"""


def parse():
    rows = []
    for line in T.strip().splitlines():
        if not line.strip():
            continue
        parts = [p.strip() for p in re.split(r"\s\|\s", line, maxsplit=2)]
        if len(parts) != 3:
            sys.exit("bad row: " + line)
        rows.append(parts)
    keys = [r[0] for r in rows]
    dup = {k for k in keys if keys.count(k) > 1}
    if dup:
        sys.exit("duplicate keys: %s" % dup)
    return rows


def esc(s):
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # apostrophes: keep the ones already escaped (\'), escape bare ones
    s = re.sub(r"(?<!\\)'", r"\\'", s)
    s = s.replace('"', '\\"')
    if s.startswith("@") or s.startswith("?"):
        s = "\\" + s
    return s


def write(path, rows, col, conv=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n')
        f.write("<!-- Generated by scripts/gen-strings-feature2.py; edit the table there. -->\n<resources>\n")
        for r in rows:
            v = r[col]
            if conv:
                v = conv(v)
            fmt = ' formatted="true"' if "%2$" in v else ""
            f.write('    <string name="%s"%s>%s</string>\n' % (r[0], fmt, esc(v)))
        f.write("</resources>\n")


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    res = os.path.join(root, "app", "src", "main", "res")
    rows = parse()
    write(os.path.join(res, "values", "strings_feature2.xml"), rows, 1)
    write(os.path.join(res, "values-en", "strings_feature2.xml"), rows, 2)
    try:
        import opencc
        cc = opencc.OpenCC("s2twp")
        write(os.path.join(res, "values-b+zh+Hant", "strings_feature2.xml"), rows, 1, cc.convert)
    except ImportError:
        sys.exit("opencc missing: pip install opencc-python-reimplemented")
    print("%d strings" % len(rows))


if __name__ == "__main__":
    main()
