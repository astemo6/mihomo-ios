#!/usr/bin/env python3
"""Generates res/values*/strings_engine2.xml (A2 engine extras). Keys start with e2_.
Edit the table below and re-run: python3 scripts/gen-strings-engine2.py"""
import os
from xml.sax.saxutils import escape

# key: (简体, English, 繁體)
S = {
    "e2_actions": ("操作", "Actions", "操作"),
    "e2_args_surge": ("参数（#!arguments）", "Arguments (#!arguments)", "參數（#!arguments）"),
    "e2_args_loon": ("参数（[Argument]）", "Arguments ([Argument])", "參數（[Argument]）"),
    "e2_args_egern": ("参数（compat_arguments）", "Arguments (compat_arguments)", "參數（compat_arguments）"),
    "e2_args_save": ("保存参数", "Save arguments", "儲存參數"),
    "e2_args_reset": ("恢复默认", "Reset to defaults", "恢復預設"),
    "e2_args_saved": ("已保存参数，模块已按新参数重新解析", "Arguments saved; the module was re-parsed", "已儲存參數，模組已依新參數重新解析"),
    "e2_argument": ("传入 argument", "Pass argument", "傳入 argument"),
    "e2_binary_mode": ("二进制内容模式（binary-body-mode）", "Binary body mode", "二進位內容模式（binary-body-mode）"),
    "e2_body": ("内容", "Body", "內容"),
    "e2_body_base64": ("二进制内容（base64，%1$d 字符）", "Binary body (base64, %1$d chars)", "二進位內容（base64，%1$d 字元）"),
    "e2_body_binary": ("二进制或压缩内容（%1$s）", "Binary or compressed body (%1$s)", "二進位或壓縮內容（%1$s）"),
    "e2_body_none": ("无内容或未记录（仅记录前 32 KB）", "No body or not captured (first 32 KB only)", "無內容或未記錄（僅記錄前 32 KB）"),
    "e2_cannot_replay": ("请求体是二进制或超过 32 KB，没有完整记录，无法重放。", "The request body is binary or over 32 KB and was not fully captured, so it cannot be replayed.", "請求內容是二進位或超過 32 KB，沒有完整記錄，無法重播。"),
    "e2_collapse": ("收起", "Collapse", "收合"),
    "e2_console_n": ("控制台 %1$d", "Console %1$d", "主控台 %1$d"),
    "e2_copied": ("已复制", "Copied", "已複製"),
    "e2_copy": ("复制", "Copy", "複製"),
    "e2_copy_curl": ("复制为 cURL", "Copy as cURL", "複製為 cURL"),
    "e2_core_rules_n": ("内核规则 %1$d", "Core rules %1$d", "核心規則 %1$d"),
    "e2_debug_note": ("调试在应用进程中运行，不需要连接；$httpClient 直接发出请求（已连接时经过 VPN）；$persistentStore 使用真实存储。", "Runs in the app process, no connection needed. $httpClient requests go out directly (through the VPN when connected); $persistentStore is the real store.", "偵錯在應用程式行程中執行，不需要連線；$httpClient 直接送出請求（已連線時經過 VPN）；$persistentStore 使用真實儲存。"),
    "e2_debug_run": ("调试运行", "Debug run", "偵錯執行"),
    "e2_debug_with_request": ("用此请求调试脚本", "Debug a script with this request", "用此請求偵錯腳本"),
    "e2_details": ("详情", "Details", "詳情"),
    "e2_discard": ("放弃修改", "Discard", "放棄修改"),
    "e2_done_called": ("已调用 $done", "$done called", "已呼叫 $done"),
    "e2_done_missing": ("未调用 $done", "$done not called", "未呼叫 $done"),
    "e2_duration": ("耗时", "Duration", "耗時"),
    "e2_edit_replay": ("编辑后重放", "Edit and replay", "編輯後重播"),
    "e2_failed": ("失败", "Failed", "失敗"),
    "e2_file_name": ("文件名", "File name", "檔名"),
    "e2_format": ("格式", "Format", "格式"),
    "e2_group_icon": ("策略组图标", "Group icon", "策略組圖示"),
    "e2_headers_hint": ("头部（每行 名称: 值）", "Headers (one Name: value per line)", "標頭（每行 名稱: 值）"),
    "e2_headers_n": ("头部 %1$d", "Headers %1$d", "標頭 %1$d"),
    "e2_hostnames_n": ("MitM 主机名 %1$d", "MitM hostnames %1$d", "MitM 主機名稱 %1$d"),
    "e2_https_decrypt": ("HTTPS 解密", "HTTPS decrypted", "HTTPS 解密"),
    "e2_icon_bad_url": ("请输入以 http:// 或 https:// 开头的图片地址", "Enter an image URL starting with http:// or https://", "請輸入以 http:// 或 https:// 開頭的圖片位址"),
    "e2_icon_clear_cache": ("清除图标缓存", "Clear icon cache", "清除圖示快取"),
    "e2_icon_follow_profile": ("使用配置文件的图标", "Use the profile's icon", "使用設定檔的圖示"),
    "e2_icon_galleries": ("图标库", "Icon galleries", "圖示庫"),
    "e2_icon_galleries_note": ("图标来自 GitHub 上的开源图标库，经 jsDelivr 镜像加载并缓存在本机。", "Icons come from open-source galleries on GitHub, loaded through the jsDelivr mirror and cached on this device.", "圖示來自 GitHub 上的開源圖示庫，經 jsDelivr 鏡像載入並快取在本機。"),
    "e2_icon_gallery_failed": ("图标库加载失败：%1$s", "Could not load the gallery: %1$s", "圖示庫載入失敗：%1$s"),
    "e2_icon_load_failed": ("无法加载这张图片", "Could not load this image", "無法載入這張圖片"),
    "e2_icon_local_note": ("长按策略组图标可打开此页。选择只保存在本机设置里，不会改动配置文件。", "Long-press a group icon to open this page. Your choice is stored on this device only and never changes the profile.", "長按策略組圖示可開啟此頁。選擇只儲存在本機設定裡，不會改動設定檔。"),
    "e2_icon_restore": ("恢复默认", "Restore default", "恢復預設"),
    "e2_icon_search": ("搜索图标", "Search icons", "搜尋圖示"),
    "e2_icon_src_custom": ("你选择的图标", "Your icon", "你選擇的圖示"),
    "e2_icon_src_default": ("默认图标", "Default icon", "預設圖示"),
    "e2_icon_src_default_chosen": ("默认图标（你的选择）", "Default icon (your choice)", "預設圖示（你的選擇）"),
    "e2_icon_src_profile": ("来自配置文件", "From the profile", "來自設定檔"),
    "e2_icon_url": ("图片地址", "Image URL", "圖片位址"),
    "e2_icon_use_default": ("使用默认图标", "Use the default icon", "使用預設圖示"),
    "e2_icon_use_url": ("使用此地址", "Use this URL", "使用此位址"),
    "e2_lines_chars": ("%1$d 行 · %2$d 字符", "%1$d lines · %2$d chars", "%1$d 行 · %2$d 字元"),
    "e2_local_response": ("本地响应", "Local response", "本機回應"),
    "e2_local_script_hint": ("保存在 engine/scripts/，在 script-path 里直接写文件名即可引用。", "Saved in engine/scripts/; reference it by file name in script-path.", "儲存在 engine/scripts/，在 script-path 裡直接寫檔名即可引用。"),
    "e2_local_scripts": ("本地脚本", "Local scripts", "本機腳本"),
    "e2_local_scripts_empty": ("没有本地脚本", "No local scripts", "沒有本機腳本"),
    "e2_matched": ("命中规则 / 脚本", "Matched rules / scripts", "命中規則 / 腳本"),
    "e2_method": ("方法", "Method", "方法"),
    "e2_method_status": ("方法 / 状态", "Method / status", "方法 / 狀態"),
    "e2_mock_response": ("本地响应（请求阶段）", "Local response (request phase)", "本機回應（請求階段）"),
    "e2_module_args_n": ("%1$d 个参数", "%1$d arguments", "%1$d 個參數"),
    "e2_module_policies_n": ("%1$d 个策略映射", "%1$d policy mappings", "%1$d 個策略對應"),
    "e2_new_script": ("新建", "New", "新增"),
    "e2_no_plain": ("否（明文 HTTP）", "No (plain HTTP)", "否（明文 HTTP）"),
    "e2_not_imported_n": ("未导入 %1$d", "Not imported %1$d", "未匯入 %1$d"),
    "e2_notes": ("备注", "Notes", "備註"),
    "e2_notifications_n": ("通知 %1$d", "Notifications %1$d", "通知 %1$d"),
    "e2_open_script": ("打开脚本", "Open script", "開啟腳本"),
    "e2_options": ("选项", "Options", "選項"),
    "e2_p12_export": ("导出 p12", "Export p12", "匯出 p12"),
    "e2_p12_export_desc": ("p12 包含证书和私钥，用于在其他设备或应用（如 iOS 版、Surge、QX）使用同一个 CA。请设置密码并妥善保管。", "The p12 holds the certificate and private key, to use the same CA on another device or app (iOS, Surge, QX). Set a password and keep it safe.", "p12 包含憑證和私密金鑰，用於在其他裝置或應用程式（如 iOS 版、Surge、QX）使用同一個 CA。請設定密碼並妥善保管。"),
    "e2_p12_exported": ("已导出 p12", "p12 exported", "已匯出 p12"),
    "e2_p12_failed": ("p12 操作失败：%1$s", "p12 failed: %1$s", "p12 操作失敗：%1$s"),
    "e2_p12_import": ("导入 p12", "Import p12", "匯入 p12"),
    "e2_p12_import_desc": ("将用 p12 里的证书替换当前 CA。若新证书与已安装的不同，需要重新安装。", "Replaces the current CA with the one in the p12. Reinstall it if it differs from the installed one.", "將用 p12 裡的憑證取代目前的 CA。若新憑證與已安裝的不同，需要重新安裝。"),
    "e2_p12_imported": ("已导入 CA 证书", "CA certificate imported", "已匯入 CA 憑證"),
    "e2_p12_password": ("密码", "Password", "密碼"),
    "e2_policy_auto": ("自动（第一个手动组）", "Auto (first select group)", "自動（第一個手動組）"),
    "e2_policy_map": ("策略映射", "Policy mapping", "策略對應"),
    "e2_policy_map_desc": ("模块规则里的这些策略名在当前配置中不存在。为每个名称选择一个策略组；未选择时使用第一个手动选择组。", "These policy names in the module's rules do not exist in the current profile. Pick a group for each; unmapped names use the first select group.", "模組規則裡的這些策略名稱在目前設定中不存在。為每個名稱選擇一個策略組；未選擇時使用第一個手動選擇組。"),
    "e2_policy_no_profile": ("没有可用的配置文件，无法列出策略组", "No active profile, so no groups to choose from", "沒有可用的設定檔，無法列出策略組"),
    "e2_remote_readonly": ("远程脚本（缓存副本）只读；可在此调试，或另存为本地脚本后修改。", "Remote script (cached copy) is read-only; debug it here or save it as a local script to edit.", "遠端腳本（快取副本）唯讀；可在此偵錯，或另存為本機腳本後修改。"),
    "e2_replay": ("重放", "Replay", "重播"),
    "e2_replay_note": ("重放经内核按你的规则与策略发出，不再经过重写与脚本；结果也会出现在请求列表里。", "Replays go out through the core with your rules and policies, without rewrites or scripts; they also appear in the request list.", "重播經核心依你的規則與策略送出，不再經過重寫與腳本；結果也會出現在請求列表裡。"),
    "e2_request": ("请求", "Request", "請求"),
    "e2_request_detail": ("请求详情", "Request details", "請求詳情"),
    "e2_requests": ("HTTP 请求", "HTTP requests", "HTTP 請求"),
    "e2_requests_empty": ("还没有经过 HTTP 引擎的请求。开启重写或 MitM 后，匹配的请求会显示在这里。", "No requests through the HTTP engine yet. With rewrite or MitM on, matching requests show up here.", "還沒有經過 HTTP 引擎的請求。開啟重寫或 MitM 後，符合的請求會顯示在這裡。"),
    "e2_requests_search": ("筛选 URL / 规则", "Filter URL / rule", "篩選 URL / 規則"),
    "e2_response": ("响应", "Response", "回應"),
    "e2_result": ("脚本处理后的结果", "Result after the script", "腳本處理後的結果"),
    "e2_rules_n": ("规则 / 脚本 %1$d", "Rules / scripts %1$d", "規則 / 腳本 %1$d"),
    "e2_run": ("运行", "Run", "執行"),
    "e2_save": ("保存", "Save", "儲存"),
    "e2_save_as": ("另存为", "Save as", "另存為"),
    "e2_save_as_local": ("另存为本地脚本", "Save as local script", "另存為本機腳本"),
    "e2_saved": ("已保存", "Saved", "已儲存"),
    "e2_saved_as": ("已保存为 %1$s", "Saved as %1$s", "已儲存為 %1$s"),
    "e2_saved_short": ("已保存", "Saved", "已儲存"),
    "e2_script_load_failed": ("无法读取脚本：%1$s（远程脚本需要先连接一次让内核下载）", "Could not read the script: %1$s (remote scripts are downloaded by the core after connecting once)", "無法讀取腳本：%1$s（遠端腳本需要先連線一次讓核心下載）"),
    "e2_send": ("发送", "Send", "送出"),
    "e2_size": ("大小", "Size", "大小"),
    "e2_status": ("状态码", "Status", "狀態碼"),
    "e2_tasks_n": ("定时 / 事件 / 通用脚本 %1$d", "Cron / event / generic scripts %1$d", "定時 / 事件 / 通用腳本 %1$d"),
    "e2_timeout_s": ("超时 %1$d 秒", "Timeout %1$d s", "逾時 %1$d 秒"),
    "e2_trust_checking": ("正在检查系统是否信任…", "Checking system trust…", "正在檢查系統是否信任…"),
    "e2_trust_missing": ("系统尚未安装此证书", "Not installed on this device", "系統尚未安裝此憑證"),
    "e2_trust_recheck": ("重新检查", "Check again", "重新檢查"),
    "e2_trust_system": ("已安装（系统证书）", "Installed (system CA)", "已安裝（系統憑證）"),
    "e2_trust_unknown": ("无法读取系统证书列表", "Could not read the system certificate store", "無法讀取系統憑證列表"),
    "e2_trust_user": ("已安装（用户证书）", "Installed (user CA)", "已安裝（使用者憑證）"),
    "e2_trust_user_note": ("用户证书只被信任它的应用接受（见下方说明）。", "User CAs are only accepted by apps that trust them (see below).", "使用者憑證只被信任它的應用程式接受（見下方說明）。"),
    "e2_unsaved": ("有未保存的修改，确定离开？", "Discard unsaved changes?", "有未儲存的修改，確定離開？"),
    "e2_updated": ("更新于", "Updated", "更新於"),
    "e2_view_content": ("查看内容", "View content", "檢視內容"),
    "e2_view_response": ("查看响应", "View response", "檢視回應"),
    "e2_workbench": ("调试台", "Workbench", "偵錯台"),
    "e2_yes": ("是", "Yes", "是"),
}


def esc(s: str) -> str:
    s = escape(s).replace("'", "\\'").replace('"', '\\"')
    if s.startswith("@") or s.startswith("?"):
        s = "\\" + s
    return s


def write(d: str, idx: int) -> None:
    root = os.path.join(os.path.dirname(__file__), "..", "app", "src", "main", "res", d)
    os.makedirs(root, exist_ok=True)
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<!-- Generated by scripts/gen-strings-engine2.py; edit the table there. -->", "<resources>"]
    for k in sorted(S):
        v = S[k][idx]
        fmt = ' formatted="false"' if "%" in v and "%1$" not in v else ""
        lines.append(f'    <string name="{k}"{fmt}>{esc(v)}</string>')
    lines.append("</resources>")
    with open(os.path.join(root, "strings_engine2.xml"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


write("values", 0)
write("values-en", 1)
write("values-b+zh+Hant", 2)
