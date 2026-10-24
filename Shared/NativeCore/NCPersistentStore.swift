import Foundation

/// Pure Swift Persistent Store backing $persistentStore / $prefs.
/// Replaces Go's Store (`bridge/mitm/store.go`).
/// Persists key-value pairs as a JSON object in `<home>/engine/store.json`.
public final class NCPersistentStore {
    public static let shared = NCPersistentStore()

    private let lock = NSLock()
    private var data: [String: String] = [:]
    private var fileURL: URL?
    private var saveTimer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "nc.persistentstore", qos: .utility)
    private var dirty = false

    init(homeURL: URL = AppShared.homeURL) {
        let storeURL = homeURL.appendingPathComponent("engine/store.json")
        self.fileURL = storeURL
        load()
    }

    private func load() {
        guard let url = fileURL,
              let raw = try? Data(contentsOf: url),
              let dict = (try? JSONSerialization.jsonObject(with: raw)) as? [String: String] else {
            return
        }
        lock.lock()
        data = dict
        lock.unlock()
    }

    public func read(key: String) -> String? {
        lock.lock()
        defer { lock.unlock() }
        return data[key]
    }

    @discardableResult
    public func write(key: String, value: String) -> Bool {
        lock.lock()
        data[key] = value
        dirty = true
        lock.unlock()
        scheduleFlush()
        return true
    }

    @discardableResult
    public func delete(key: String) -> Bool {
        lock.lock()
        data.removeValue(forKey: key)
        dirty = true
        lock.unlock()
        scheduleFlush()
        return true
    }

    @discardableResult
    public func clear() -> Bool {
        lock.lock()
        data.removeAll()
        dirty = true
        lock.unlock()
        scheduleFlush()
        return true
    }

    public func flush() {
        lock.lock()
        guard dirty, let url = fileURL else {
            lock.unlock()
            return
        }
        let copy = data
        dirty = false
        lock.unlock()

        do {
            let dir = url.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let raw = try JSONSerialization.data(withJSONObject: copy, options: [.sortedKeys, .prettyPrinted])
            try raw.write(to: url, options: .atomic)
        } catch {
            // Silently ignore disk write error
        }
    }

    private func scheduleFlush() {
        queue.async { [weak self] in
            guard let self else { return }
            self.lock.lock()
            if self.saveTimer == nil {
                let t = DispatchSource.makeTimerSource(queue: self.queue)
                t.schedule(deadline: .now() + 0.25)
                t.setEventHandler { [weak self] in
                    self?.flush()
                    self?.lock.lock()
                    self?.saveTimer = nil
                    self?.lock.unlock()
                }
                t.resume()
                self.saveTimer = t
            }
            self.lock.unlock()
        }
    }
}
