import Darwin
import Foundation

/// fix/nc-ctrl-bsd (build 395 device report): the NativeCore controller's listener, a plain BSD socket bound to
/// 127.0.0.1:<port> like the old core era's `net.Listen("tcp", "127.0.0.1:9090")`. On iOS 18.7 an
/// `NWListener(requiredInterfaceType: .loopback)` inside the packet tunnel reported `.ready` but never delivered a
/// connection (controller accepted 0, the extension's own GET /version timed out), so the App's 策略组 / 连接 pages
/// hung (「已取消」). Accept runs on a DispatchSource read source on the caller's serial queue.
final class NCLoopbackListener {
    let queue: DispatchQueue
    private var fd: Int32 = -1
    private var source: DispatchSourceRead?
    private(set) var port: UInt16 = 0
    /// Called on `queue` for every accepted connection.
    var onAccept: ((NCLoopbackConn) -> Void)?
    /// accept(2) errors other than EAGAIN (first one is reported once through this hook).
    var onAcceptError: ((String) -> Void)?
    private var reportedAcceptError = false

    init(queue: DispatchQueue) { self.queue = queue }

    static func errnoText(_ e: Int32) -> String { "errno \(e) \(String(cString: strerror(e)))" }

    /// Binds 127.0.0.1:`port` (0 = any free port, read back into `port`), listens and starts accepting.
    /// Returns nil when listening, else what failed (with errno).
    func start(port wanted: UInt16, backlog: Int32 = 64) -> String? {
        let s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard s >= 0 else { return "socket() \(Self.errnoText(errno))" }
        var one: Int32 = 1
        let optLen = socklen_t(MemoryLayout<Int32>.size)
        _ = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, optLen)
        _ = setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, optLen)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = wanted.bigEndian
        addr.sin_addr.s_addr = UInt32(0x7F00_0001).bigEndian
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if rc != 0 {
            let e = errno
            Darwin.close(s)
            return "bind 127.0.0.1:\(wanted) \(Self.errnoText(e))"
        }
        if listen(s, backlog) != 0 {
            let e = errno
            Darwin.close(s)
            return "listen \(Self.errnoText(e))"
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        port = UInt16(bigEndian: bound.sin_port)
        _ = fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
        fd = s
        let src = DispatchSource.makeReadSource(fileDescriptor: s, queue: queue)
        src.setEventHandler { [weak self] in self?.acceptPending() }
        src.setCancelHandler { Darwin.close(s) }
        source = src
        src.resume()
        return nil
    }

    private func acceptPending() {
        guard fd >= 0 else { return }
        for _ in 0..<64 {
            let c = accept(fd, nil, nil)
            if c < 0 {
                let e = errno
                if e != EAGAIN, e != EWOULDBLOCK, e != EINTR, e != ECONNABORTED, !reportedAcceptError {
                    reportedAcceptError = true
                    onAcceptError?("accept \(Self.errnoText(e))")
                }
                return
            }
            var one: Int32 = 1
            _ = setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            _ = fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK)
            let conn = NCLoopbackConn(fd: c, queue: queue)
            if let onAccept { onAccept(conn) } else { conn.cancel() }
        }
    }

    /// Stops accepting and closes the listening socket (accepted connections are the owner's to cancel).
    func stop() {
        onAccept = nil
        source?.cancel()
        source = nil
        fd = -1
    }
}

/// One accepted loopback connection, with the slice of `NWConnection`'s API the controller uses
/// (`receive(minimumIncompleteLength:maximumLength:completion:)`, `send(content:completion:)`, `cancel()`).
/// Every entry point hops onto `queue` (callers may be on a delay-test queue); callbacks run on `queue`.
final class NCLoopbackConn {
    enum SendCompletion {
        case idempotent
        case contentProcessed((Error?) -> Void)
    }

    let queue: DispatchQueue
    private let fd: Int32
    private let readSource: DispatchSourceRead
    private let writeSource: DispatchSourceWrite
    private var readSuspended = true   // sources start inactive; resume() activates them
    private var writeSuspended = true
    private var pendingReceive: ((Data?, Void?, Bool, Error?) -> Void)?
    private var pendingMax = 0
    private var outQ: [(data: Data, done: ((Error?) -> Void)?)] = []
    private var outOffset = 0
    private(set) var isClosed = false
    /// Called once on `queue` when the connection ends (cancel, peer EOF on a failed write, error).
    var onClose: (() -> Void)?

    init(fd: Int32, queue: DispatchQueue) {
        self.fd = fd
        self.queue = queue
        readSource = DispatchSource.makeReadSource(fileDescriptor: fd, queue: queue)
        writeSource = DispatchSource.makeWriteSource(fileDescriptor: fd, queue: queue)
        // Close the fd only after both sources are cancelled (the fd must not be reused under a live source).
        let group = DispatchGroup()
        group.enter(); group.enter()
        readSource.setCancelHandler { group.leave() }
        writeSource.setCancelHandler { group.leave() }
        group.notify(queue: queue) { Darwin.close(fd) }
        readSource.setEventHandler { [weak self] in self?.readReady() }
        writeSource.setEventHandler { [weak self] in self?.flush() }
    }

    deinit {
        // A suspended / inactive source must be resumed before it is released.
        if !isClosed {
            if readSuspended { readSource.resume() }
            if writeSuspended { writeSource.resume() }
            readSource.cancel()
            writeSource.cancel()
        }
    }

    private static func posixError(_ code: Int32) -> NSError {
        NSError(domain: NSPOSIXErrorDomain, code: Int(code))
    }

    /// Delivers up to `maximumLength` bytes once some arrive; (nil, nil, true, nil) on EOF; an error on failure.
    func receive(minimumIncompleteLength: Int, maximumLength: Int,
                 completion: @escaping (Data?, Void?, Bool, Error?) -> Void) {
        queue.async {
            guard !self.isClosed else {
                completion(nil, nil, true, Self.posixError(ECANCELED))
                return
            }
            self.pendingReceive = completion
            self.pendingMax = max(1, maximumLength)
            if self.readSuspended {
                self.readSuspended = false
                self.readSource.resume()
            }
        }
    }

    private func readReady() {
        guard !isClosed, let cb = pendingReceive else {
            if !readSuspended { readSuspended = true; readSource.suspend() }
            return
        }
        var buf = [UInt8](repeating: 0, count: min(pendingMax, 65536))
        let n = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        if n < 0 {
            let e = errno
            if e == EAGAIN || e == EWOULDBLOCK || e == EINTR { return }
            pendingReceive = nil
            cb(nil, nil, false, Self.posixError(e))
            return
        }
        pendingReceive = nil
        if !readSuspended { readSuspended = true; readSource.suspend() }
        if n == 0 {
            cb(nil, nil, true, nil)
        } else {
            cb(Data(buf[0..<n]), nil, false, nil)
        }
    }

    func send(content: Data?, completion: SendCompletion) {
        let done: ((Error?) -> Void)?
        switch completion {
        case .idempotent: done = nil
        case .contentProcessed(let f): done = f
        }
        queue.async {
            guard !self.isClosed else { done?(Self.posixError(ECANCELED)); return }
            self.outQ.append((content ?? Data(), done))
            self.flush()
        }
    }

    private func flush() {
        while !isClosed, let head = outQ.first {
            let remaining = head.data.count - outOffset
            if remaining > 0 {
                let n = head.data.withUnsafeBytes { raw -> Int in
                    Darwin.write(fd, raw.baseAddress!.advanced(by: outOffset), remaining)
                }
                if n < 0 {
                    let e = errno
                    if e == EAGAIN || e == EWOULDBLOCK || e == EINTR {
                        if writeSuspended { writeSuspended = false; writeSource.resume() }
                        return
                    }
                    let failed = outQ
                    outQ = []
                    outOffset = 0
                    for f in failed { f.done?(Self.posixError(e)) }
                    cancelNow()
                    return
                }
                outOffset += n
                if outOffset < head.data.count { continue }
            }
            outQ.removeFirst()
            outOffset = 0
            head.done?(nil)
        }
        if !writeSuspended { writeSuspended = true; writeSource.suspend() }
    }

    /// fix/nc-e2e-gaps: half-close — FIN after everything queued so far was written; reads keep working
    /// (the plain-HTTP MitM front's ByteStream.closeWrite).
    func shutdownWrite() {
        queue.async {
            guard !self.isClosed else { return }
            self.outQ.append((Data(), { [weak self] _ in
                guard let self, !self.isClosed else { return }
                _ = Darwin.shutdown(self.fd, SHUT_WR)
            }))
            self.flush()
        }
    }

    /// Closes the connection (queued, unsent bytes are dropped — callers cancel from a send completion).
    func cancel() {
        queue.async { self.cancelNow() }
    }

    private func cancelNow() {
        guard !isClosed else { return }
        isClosed = true
        pendingReceive = nil
        outQ = []
        if readSuspended { readSuspended = false; readSource.resume() }
        if writeSuspended { writeSuspended = false; writeSource.resume() }
        readSource.cancel()
        writeSource.cancel()
        let cb = onClose
        onClose = nil
        cb?()
    }
}
