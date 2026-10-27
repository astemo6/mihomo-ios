import Foundation

/// The one place that still knows the app's pre-rename name ("Mihomo iOS", user decision 2026-10-27).
///
/// Since the rename the bundle ids and the App Group are new (com.astemo6.tern / group.com.astemo6.tern), so an
/// install of the new app starts with an empty container. Importing an old backup is the migration path:
/// backups, WebDAV copies, sync-folder files and 完整导出 written by the old app carry the old envelope name and
/// storage directory, and are accepted here and mapped onto the current layout. Nothing below is ever written.
///
/// No directory on disk is ever named after the old app (user 2026-10-27 「不要有mihomo路径」): the old storage directory
/// name below exists only to rewrite the entry paths inside an old backup / export to `tern/` while it is decoded.
///
/// Keep every old-name literal in this file (scripts/term_audit.py allow-lists it).
enum LegacyImport {
    /// Backup envelope `"app"` values written by the old app (BackupFile / WebDAV / sync folder).
    static let backupAppNames: Set<String> = ["mihomo-ios"]
    /// The old app's storage directory as it appears in the entry paths of its backups / exports (rewritten to `tern/`
    /// on import; never looked up on disk).
    static let storageDir = "mihomo"
    /// Old WebDAV backup file name prefix (now `tern-backup-`).
    static let webDAVPrefixes = ["mihomo-backup-"]
    /// Old sync-folder file name (now Tern-sync.json).
    static let syncFileName = "Mihomo-sync.json"

    /// True for an envelope written by this app or by the old one.
    static func isOurBackupApp(_ app: String, current: String) -> Bool { app == current || backupAppNames.contains(app) }

    /// A container-relative path from an old backup / export mapped onto the current storage directory:
    /// "mihomo/x" → "tern/x"; every other path is returned unchanged.
    static func mapPath(_ rel: String, currentDir: String = "tern") -> String {
        if rel == storageDir { return currentDir }
        if rel.hasPrefix(storageDir + "/") { return currentDir + String(rel.dropFirst(storageDir.count)) }
        return rel
    }
}
