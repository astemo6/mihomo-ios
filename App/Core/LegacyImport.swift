import Foundation

/// The one place that still knows the app's pre-rename name ("Mihomo iOS", user decision 2026-10-27).
///
/// Since the rename the bundle ids and the App Group are new (com.astemo6.tern / group.com.astemo6.tern), so an
/// install of the new app starts with an empty container. Importing an old backup is the migration path:
/// backups, WebDAV copies, sync-folder files and 完整导出 written by the old app carry the old envelope name and
/// storage directory, and are accepted here and mapped onto the current layout. Nothing below is ever written.
///
/// A re-signed build that keeps its own App Group across the update also finds the old storage directory in the
/// same container; `migrateStorageDirIfNeeded` moves it once.
///
/// Keep every old-name literal in this file (scripts/term_audit.py allow-lists it).
enum LegacyImport {
    /// Backup envelope `"app"` values written by the old app (BackupFile / WebDAV / sync folder).
    static let backupAppNames: Set<String> = ["mihomo-ios"]
    /// The old storage directory inside the App Group container (now `tern/`).
    static let storageDir = "mihomo"
    /// Old WebDAV backup file name prefix (now `tern-backup-`).
    static let webDAVPrefixes = ["mihomo-backup-"]
    /// Old plaintext backup export name prefix in tmp (now `Tern-备份-`).
    static let tempExportPrefixes = ["Mihomo-备份-"]
    /// Old sync-folder file name (now Tern-sync.json).
    static let syncFileName = "Mihomo-sync.json"
    /// Old VPN configuration name; a re-signed build that kept its bundle id may still own one.
    static let vpnNames: Set<String> = ["Mihomo"]

    /// True for an envelope written by this app or by the old one.
    static func isOurBackupApp(_ app: String, current: String) -> Bool { app == current || backupAppNames.contains(app) }

    /// A container-relative path from an old backup / export mapped onto the current storage directory:
    /// "mihomo/x" → "tern/x"; every other path is returned unchanged.
    static func mapPath(_ rel: String, currentDir: String = "tern") -> String {
        if rel == storageDir { return currentDir }
        if rel.hasPrefix(storageDir + "/") { return currentDir + String(rel.dropFirst(storageDir.count)) }
        return rel
    }

    /// One-time move of the old storage directory to the current one in the same container. Never overwrites: when
    /// the current directory already exists (something — the tunnel on an on-demand start, a store's first save —
    /// created it before the app's first launch after the update), every top-level item of the old directory that
    /// the current one does not have yet is moved in, and the old directory is removed once it is empty.
    /// (selfreview-g2: the whole-directory move used to give up as soon as the current directory held anything,
    /// leaving every old setting behind for good.)
    static func migrateStorageDirIfNeeded(container: URL = AppShared.containerURL, currentDir: String = "tern") {
        let fm = FileManager.default
        let old = container.appendingPathComponent(storageDir, isDirectory: true)
        let new = container.appendingPathComponent(currentDir, isDirectory: true)
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: old.path, isDirectory: &isDir), isDir.boolValue else { return }
        if !fm.fileExists(atPath: new.path) {
            do {
                try fm.moveItem(at: old, to: new)
                NSLog("[Tern] moved the old storage directory to %@/", currentDir)
            } catch {
                NSLog("[Tern] storage directory move failed: %@", error.localizedDescription)
            }
            return
        }
        var moved = 0, kept = 0
        for name in (try? fm.contentsOfDirectory(atPath: old.path)) ?? [] {
            let dst = new.appendingPathComponent(name)
            if fm.fileExists(atPath: dst.path) { kept += 1; continue }
            do { try fm.moveItem(at: old.appendingPathComponent(name), to: dst); moved += 1 } catch { kept += 1 }
        }
        if ((try? fm.contentsOfDirectory(atPath: old.path)) ?? ["?"]).isEmpty { try? fm.removeItem(at: old) }
        NSLog("[Tern] merged the old storage directory into %@/: %d moved, %d already present", currentDir, moved, kept)
    }
}
