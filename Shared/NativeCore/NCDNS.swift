import Foundation

/// DNS wire codec + fake-IP responder (pure logic; sockets live in the tunnel
/// glue). Parsing follows RFC 1035 including compression pointers; responses
/// are built uncompressed, which is always legal.

struct NCDNSQuestion: Equatable {
    var name: String
    var type: UInt16
    var klass: UInt16
}

struct NCDNSRecord: Equatable {
    var name: String
    var type: UInt16
    var klass: UInt16
    var ttl: UInt32
    var rdata: Data
}

struct NCDNSMessage: Equatable {
    var id: UInt16 = 0
    var isResponse = false
    var opcode: UInt16 = 0
    var authoritative = false
    var truncated = false
    var recursionDesired = false
    var recursionAvailable = false
    var rcode: UInt16 = 0
    var questions: [NCDNSQuestion] = []
    var answers: [NCDNSRecord] = []

    static let typeA: UInt16 = 1
    static let typeAAAA: UInt16 = 28
    static let classIN: UInt16 = 1

    static func parse(_ data: Data) -> NCDNSMessage? {
        guard data.count >= 12 else { return nil }
        func u16(_ off: Int) -> UInt16 { UInt16(data[off]) << 8 | UInt16(data[off + 1]) }
        func u32(_ off: Int) -> UInt32 { UInt32(data[off]) << 24 | UInt32(data[off + 1]) << 16 | UInt32(data[off + 2]) << 8 | UInt32(data[off + 3]) }
        var msg = NCDNSMessage()
        msg.id = u16(0)
        let flags = u16(2)
        msg.isResponse = flags & 0x8000 != 0
        msg.opcode = (flags >> 11) & 0xf
        msg.authoritative = flags & 0x0400 != 0
        msg.truncated = flags & 0x0200 != 0
        msg.recursionDesired = flags & 0x0100 != 0
        msg.recursionAvailable = flags & 0x0080 != 0
        msg.rcode = flags & 0xf
        let qd = Int(u16(4)), an = Int(u16(6))
        var off = 12
        for _ in 0..<qd {
            guard let (name, next) = decodeName(data, off) else { return nil }
            off = next
            guard off + 4 <= data.count else { return nil }
            msg.questions.append(NCDNSQuestion(name: name, type: u16(off), klass: u16(off + 2)))
            off += 4
        }
        for _ in 0..<an {
            guard let (name, next) = decodeName(data, off) else { return nil }
            off = next
            guard off + 10 <= data.count else { return nil }
            let type = u16(off), klass = u16(off + 2), ttl = u32(off + 4), rdlen = Int(u16(off + 8))
            off += 10
            guard off + rdlen <= data.count else { return nil }
            msg.answers.append(NCDNSRecord(name: name, type: type, klass: klass, ttl: ttl,
                                            rdata: Data(data[off..<off + rdlen])))
            off += rdlen
        }
        return msg
    }

    /// Decode a (possibly compressed) domain name at `start`; returns the name
    /// and the offset just past it in the *original* stream position.
    static func decodeName(_ data: Data, _ start: Int) -> (String, Int)? {
        var labels: [String] = []
        var off = start
        var next: Int?
        var jumps = 0
        while off < data.count {
            let len = Int(data[off])
            if len == 0 {
                if next == nil { next = off + 1 }
                break
            }
            if len & 0xc0 == 0xc0 {
                guard off + 1 < data.count else { return nil }
                let ptr = Int(len & 0x3f) << 8 | Int(data[off + 1])
                if next == nil { next = off + 2 }
                off = ptr
                jumps += 1
                if jumps > 10 { return nil }
                continue
            }
            guard len <= 63, off + 1 + len <= data.count else { return nil }
            labels.append(String(decoding: data[(off + 1)..<(off + 1 + len)], as: UTF8.self))
            off += 1 + len
        }
        guard let end = next else { return nil }
        return (labels.joined(separator: "."), end)
    }

    static func encodeName(_ name: String) -> Data {
        var out = Data()
        for label in name.split(separator: ".", omittingEmptySubsequences: true) {
            let bytes = Array(label.utf8.prefix(63))
            out.append(UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(0)
        return out
    }

    func serialized() -> Data {
        var out = Data()
        func put16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xff)) }
        func put32(_ v: UInt32) { put16(UInt16(v >> 16)); put16(UInt16(v & 0xffff)) }
        put16(id)
        var flags: UInt16 = 0
        if isResponse { flags |= 0x8000 }
        flags |= (opcode & 0xf) << 11
        if authoritative { flags |= 0x0400 }
        if truncated { flags |= 0x0200 }
        if recursionDesired { flags |= 0x0100 }
        if recursionAvailable { flags |= 0x0080 }
        flags |= rcode & 0xf
        put16(flags)
        put16(UInt16(questions.count))
        put16(UInt16(answers.count))
        put16(0)
        put16(0)
        for q in questions {
            out.append(NCDNSMessage.encodeName(q.name))
            put16(q.type)
            put16(q.klass)
        }
        for r in answers {
            out.append(NCDNSMessage.encodeName(r.name))
            put16(r.type)
            put16(r.klass)
            put32(r.ttl)
            put16(UInt16(r.rdata.count))
            out.append(r.rdata)
        }
        return out
    }
}

/// Answers A queries with fake IPs (mihomo fake-ip mode). Anything it cannot
/// answer returns nil, meaning: forward the original query upstream.
final class NCFakeIPResponder {
    let pool: NCFakeIPPool

    init(pool: NCFakeIPPool) { self.pool = pool }

    func respond(to queryData: Data) -> Data? {
        guard let query = NCDNSMessage.parse(queryData), query.questions.count == 1 else { return nil }
        let q = query.questions[0]
        guard q.klass == NCDNSMessage.classIN else { return nil }
        let host = q.name.lowercased()
        guard pool.shouldFake(host) else { return nil }
        var resp = NCDNSMessage()
        resp.id = query.id
        resp.isResponse = true
        resp.opcode = query.opcode
        resp.recursionDesired = query.recursionDesired
        resp.recursionAvailable = true
        resp.questions = query.questions
        switch q.type {
        case NCDNSMessage.typeA:
            let ip = pool.address(for: host)
            resp.answers = [NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: 1,
                                        rdata: Data(ip.bytes))]
        case NCDNSMessage.typeAAAA:
            if let ip6 = pool.address6(for: host) {
                resp.answers = [NCDNSRecord(name: q.name, type: q.type, klass: q.klass, ttl: 1,
                                            rdata: Data(ip6.bytes))]
            } else {
                // No v6 fake range configured -> NOERROR with no records,
                // which keeps clients on the v4 fake path (mihomo behaves
                // the same when its fake-ip range is v4-only).
                resp.answers = []
            }
        default:
            return nil
        }
        return resp.serialized()
    }
}


extension NCDNSMessage {
    /// A/AAAA answers as (address, ttl) pairs.
    var addressAnswers: [(NCIP, UInt32)] {
        answers.compactMap { record in
            switch record.type {
            case NCDNSMessage.typeA where record.rdata.count == 4:
                let v = UInt32(record.rdata[0]) << 24 | UInt32(record.rdata[1]) << 16
                    | UInt32(record.rdata[2]) << 8 | UInt32(record.rdata[3])
                return (.v4(v), record.ttl)
            case NCDNSMessage.typeAAAA where record.rdata.count == 16:
                return (.v6([UInt8](record.rdata)), record.ttl)
            default:
                return nil
            }
        }
    }
}

/// redir-host mode support: remembers which real IPs a host resolved to,
/// so connections to those IPs can be rule-matched by the original host
/// (mihomo's redir-host behaves the same). TTL-bound, size-capped.
final class NCRealIPMap {
    private struct Entry {
        var host: String
        var expires: Date
    }

    private var map: [NCIP: Entry] = [:]
    private let lock = NSLock()
    private let cap = 4096
    var now: () -> Date = { Date() }

    func record(host: String, answers: [(NCIP, UInt32)]) {
        guard !answers.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        if map.count >= cap {
            // Drop expired first; if still full, clear (simple + bounded).
            let t = now()
            map = map.filter { $0.value.expires > t }
            if map.count >= cap { map.removeAll() }
        }
        for (ip, ttl) in answers {
            let clamped = min(max(ttl, 30), 3600)
            map[ip] = Entry(host: host.lowercased(), expires: now().addingTimeInterval(Double(clamped)))
        }
    }

    func host(for ip: NCIP) -> String? {
        lock.lock(); defer { lock.unlock() }
        guard let entry = map[ip] else { return nil }
        if entry.expires <= now() {
            map.removeValue(forKey: ip)
            return nil
        }
        return entry.host
    }

    var size: Int { lock.lock(); defer { lock.unlock() }; return map.count }
}
