import Foundation

/// RFC 9460 (SVCB and HTTPS Resource Records) wire format parsing and model.
///
/// Handles both SVCB (TYPE 64) and HTTPS (TYPE 65) resource records,
/// with full SvcParams extraction including ECH (key 5, raw ECHConfigList),
/// ALPN (key 1), port (key 3), ipv4hint (key 4), ipv6hint (key 6),
/// and AliasMode (priority 0) / ServiceMode (priority > 0) semantics.

struct NCSvcParamKey: RawRepresentable, Hashable, Equatable {
    let rawValue: UInt16

    static let mandatory = NCSvcParamKey(rawValue: 0)
    static let alpn = NCSvcParamKey(rawValue: 1)
    static let noDefaultALPN = NCSvcParamKey(rawValue: 2)
    static let port = NCSvcParamKey(rawValue: 3)
    static let ipv4Hint = NCSvcParamKey(rawValue: 4)
    static let ech = NCSvcParamKey(rawValue: 5)
    static let ipv6Hint = NCSvcParamKey(rawValue: 6)
    static let dohPath = NCSvcParamKey(rawValue: 7)
}

/// A parsed SVCB (TYPE 64) or HTTPS (TYPE 65) candidate record per RFC 9460.
struct NCSVCCandidate: Equatable {
    /// SvcPriority (0 = AliasMode, >0 = ServiceMode).
    var priority: UInt16

    /// TargetName. In ServiceMode, "." or empty indicates the owner name.
    /// In AliasMode, this is the alias domain to resolve.
    var targetName: String

    /// SvcParam alpn (key 1): list of ALPN protocol identifiers (e.g. ["h2", "h3"]).
    var alpn: [String]?

    /// SvcParam no-default-alpn (key 2).
    var noDefaultALPN: Bool

    /// SvcParam port (key 3): alternate port number.
    var port: UInt16?

    /// SvcParam ipv4hint (key 4): IPv4 address hints.
    var ipv4Hints: [NCIP]?

    /// SvcParam ech (key 5): raw ECHConfigList bytes to be decoded by E1.
    var echConfigList: Data?

    /// SvcParam ipv6hint (key 6): IPv6 address hints.
    var ipv6Hints: [NCIP]?

    /// SvcParam mandatory (key 0): list of keys marked mandatory.
    var mandatoryKeys: [UInt16]?

    /// All raw SvcParams preserved by key (including unrecognized/future keys).
    var rawParams: [UInt16: Data]

    /// True if this is an AliasMode record (priority == 0).
    var isAliasMode: Bool { priority == 0 }

    /// Returns the effective target host for this record given the queried owner domain.
    func effectiveTarget(for ownerName: String) -> String {
        if isAliasMode { return targetName }
        if targetName == "." || targetName.isEmpty { return ownerName }
        return targetName
    }

    /// Serializes this candidate's RDATA to DNS wire format.
    func serializedRData() -> Data {
        var out = Data()
        func put16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xff)) }
        put16(priority)

        // TargetName
        if isAliasMode || (targetName != "." && !targetName.isEmpty) {
            out.append(NCDNSMessage.encodeName(targetName))
        } else {
            out.append(0) // root label "."
        }

        guard priority > 0 else {
            return out // AliasMode MUST NOT have SvcParams
        }

        // Canonical SvcParams serialization in ascending key order
        var paramsToWrite: [(key: UInt16, val: Data)] = []

        if let mKeys = mandatoryKeys, !mKeys.isEmpty {
            var mData = Data()
            for k in mKeys { mData.append(UInt8(k >> 8)); mData.append(UInt8(k & 0xff)) }
            paramsToWrite.append((key: 0, val: mData))
        }

        if let alpnList = alpn, !alpnList.isEmpty {
            var aData = Data()
            for s in alpnList {
                let bytes = Array(s.utf8.prefix(255))
                aData.append(UInt8(bytes.count))
                aData.append(contentsOf: bytes)
            }
            paramsToWrite.append((key: 1, val: aData))
        }

        if noDefaultALPN {
            paramsToWrite.append((key: 2, val: Data()))
        }

        if let p = port {
            paramsToWrite.append((key: 3, val: Data([UInt8(p >> 8), UInt8(p & 0xff)])))
        }

        if let hints = ipv4Hints, !hints.isEmpty {
            var v4Data = Data()
            for ip in hints {
                if case .v4(let v) = ip {
                    v4Data.append(UInt8((v >> 24) & 0xff))
                    v4Data.append(UInt8((v >> 16) & 0xff))
                    v4Data.append(UInt8((v >> 8) & 0xff))
                    v4Data.append(UInt8(v & 0xff))
                }
            }
            if !v4Data.isEmpty { paramsToWrite.append((key: 4, val: v4Data)) }
        }

        if let ech = echConfigList, !ech.isEmpty {
            paramsToWrite.append((key: 5, val: ech))
        }

        if let hints = ipv6Hints, !hints.isEmpty {
            var v6Data = Data()
            for ip in hints {
                if case .v6(let bytes) = ip, bytes.count == 16 {
                    v6Data.append(contentsOf: bytes)
                }
            }
            if !v6Data.isEmpty { paramsToWrite.append((key: 6, val: v6Data)) }
        }

        // Any additional raw params not handled specifically
        for (k, v) in rawParams where k > 6 {
            paramsToWrite.append((key: k, val: v))
        }

        paramsToWrite.sort { $0.key < $1.key }

        for p in paramsToWrite {
            put16(p.key)
            put16(UInt16(p.val.count))
            out.append(p.val)
        }

        return out
    }
}

extension NCDNSRecord {
    /// Parses HTTPS (65) or SVCB (64) RDATA into an `NCSVCCandidate`.
    /// Returns nil if this record is not SVCB/HTTPS or if RDATA is malformed per RFC 9460.
    func parseSVCB() -> NCSVCCandidate? {
        guard type == NCDNSMessage.typeHTTPS || type == NCDNSMessage.typeSVCB else { return nil }
        return Self.parseSVCBRData(rdata)
    }

    /// Parses raw SVCB/HTTPS RDATA bytes per RFC 9460.
    static func parseSVCBRData(_ rdata: Data) -> NCSVCCandidate? {
        guard rdata.count >= 3 else { return nil }
        let priority = UInt16(rdata[rdata.startIndex]) << 8 | UInt16(rdata[rdata.startIndex + 1])
        var off = rdata.startIndex + 2

        // Decode TargetName (uncompressed DNS wire format per RFC 9460 §2.2)
        var labels: [String] = []
        var hitTerminator = false
        while off < rdata.endIndex {
            let len = Int(rdata[off])
            if len == 0 {
                off += 1
                hitTerminator = true
                break
            }
            // RFC 9460 §2.2: MUST NOT be compressed. Reject if pointer bits (0xc0) set.
            if len & 0xc0 != 0 { return nil }
            guard len <= 63, off + 1 + len <= rdata.endIndex else { return nil }
            guard let label = String(data: rdata[(off + 1)..<(off + 1 + len)], encoding: .utf8) else { return nil }
            labels.append(label)
            off += 1 + len
        }
        guard hitTerminator else { return nil }

        let targetName = labels.isEmpty ? "." : labels.joined(separator: ".")

        // RFC 9460 §2.4.1: In AliasMode (priority 0):
        // - TargetName MUST NOT be root (".")
        // - SvcParams MUST NOT be present
        if priority == 0 {
            guard targetName != "." else { return nil }
            guard off == rdata.endIndex else { return nil }
            return NCSVCCandidate(
                priority: 0,
                targetName: targetName,
                alpn: nil,
                noDefaultALPN: false,
                port: nil,
                ipv4Hints: nil,
                echConfigList: nil,
                ipv6Hints: nil,
                mandatoryKeys: nil,
                rawParams: [:]
            )
        }

        // ServiceMode (priority > 0): parse SvcParams
        var rawParams: [UInt16: Data] = [:]
        var seenKeys = Set<UInt16>()
        var alpn: [String]? = nil
        var noDefaultALPN = false
        var port: UInt16? = nil
        var ipv4Hints: [NCIP]? = nil
        var echConfigList: Data? = nil
        var ipv6Hints: [NCIP]? = nil
        var mandatoryKeys: [UInt16]? = nil

        while off + 4 <= rdata.endIndex {
            let key = UInt16(rdata[off]) << 8 | UInt16(rdata[off + 1])
            let valLen = Int(UInt16(rdata[off + 2]) << 8 | UInt16(rdata[off + 3]))
            off += 4
            guard off + valLen <= rdata.endIndex else { return nil }
            // RFC 9460 §2.1: Duplicate keys are malformed
            guard seenKeys.insert(key).inserted else { return nil }
            let valData = Data(rdata[off..<off + valLen])
            rawParams[key] = valData
            off += valLen

            switch key {
            case 0: // mandatory
                guard valLen > 0, valLen % 2 == 0 else { return nil }
                var mKeys: [UInt16] = []
                for i in stride(from: valData.startIndex, to: valData.endIndex, by: 2) {
                    let k = UInt16(valData[i]) << 8 | UInt16(valData[i + 1])
                    mKeys.append(k)
                }
                // RFC 9460 §8: SvcParamKeys in mandatory MUST be strictly ascending
                // and MUST NOT contain mandatory itself (0).
                guard !mKeys.contains(0) else { return nil }
                for i in 1..<mKeys.count {
                    guard mKeys[i] > mKeys[i - 1] else { return nil }
                }
                mandatoryKeys = mKeys

            case 1: // alpn
                // RFC 9460 §7.1.1: sequence of 1-octet length-prefixed strings, non-empty
                guard valLen > 0 else { return nil }
                var pOff = valData.startIndex
                var list: [String] = []
                while pOff < valData.endIndex {
                    let sLen = Int(valData[pOff])
                    pOff += 1
                    guard sLen > 0, pOff + sLen <= valData.endIndex else { return nil }
                    guard let str = String(data: valData[pOff..<pOff + sLen], encoding: .utf8) else { return nil }
                    list.append(str)
                    pOff += sLen
                }
                guard !list.isEmpty else { return nil }
                alpn = list

            case 2: // no-default-alpn
                // RFC 9460 §7.1.2: value MUST be empty
                guard valLen == 0 else { return nil }
                noDefaultALPN = true

            case 3: // port
                // RFC 9460 §7.2: 2 octets UInt16
                guard valLen == 2 else { return nil }
                port = UInt16(valData[valData.startIndex]) << 8 | UInt16(valData[valData.startIndex + 1])

            case 4: // ipv4hint
                // RFC 9460 §7.3: sequence of 4-octet IPv4 addresses, non-empty
                guard valLen > 0, valLen % 4 == 0 else { return nil }
                var ips: [NCIP] = []
                for i in stride(from: valData.startIndex, to: valData.endIndex, by: 4) {
                    let v = UInt32(valData[i]) << 24 | UInt32(valData[i + 1]) << 16 | UInt32(valData[i + 2]) << 8 | UInt32(valData[i + 3])
                    ips.append(.v4(v))
                }
                ipv4Hints = ips

            case 5: // ech
                // RFC 9460 §7.5: raw ECHConfigList, non-empty
                guard valLen > 0 else { return nil }
                echConfigList = valData

            case 6: // ipv6hint
                // RFC 9460 §7.4: sequence of 16-octet IPv6 addresses, non-empty
                guard valLen > 0, valLen % 16 == 0 else { return nil }
                var ips: [NCIP] = []
                for i in stride(from: valData.startIndex, to: valData.endIndex, by: 16) {
                    let bytes = [UInt8](valData[i..<i + 16])
                    ips.append(.v6(bytes))
                }
                ipv6Hints = ips

            default:
                break
            }
        }
        guard off == rdata.endIndex else { return nil }

        // RFC 9460 §8: All keys in mandatory MUST appear in SvcParams
        if let mandatoryKeys {
            for k in mandatoryKeys {
                guard seenKeys.contains(k) else { return nil }
            }
        }

        return NCSVCCandidate(
            priority: priority,
            targetName: targetName,
            alpn: alpn,
            noDefaultALPN: noDefaultALPN,
            port: port,
            ipv4Hints: ipv4Hints,
            echConfigList: echConfigList,
            ipv6Hints: ipv6Hints,
            mandatoryKeys: mandatoryKeys,
            rawParams: rawParams
        )
    }
}

extension NCDNSMessage {
    /// Parsed HTTPS and SVCB candidate records from answers, sorted by priority ascending.
    var svcbAnswers: [NCSVCCandidate] {
        answers
            .compactMap { $0.parseSVCB() }
            .sorted { $0.priority < $1.priority }
    }

    /// Parsed HTTPS and SVCB candidate records paired with their original NCDNSRecord,
    /// sorted by priority ascending.
    var svcbEntries: [(record: NCDNSRecord, candidate: NCSVCCandidate)] {
        answers.compactMap { r in
            r.parseSVCB().map { (r, $0) }
        }.sorted { $0.candidate.priority < $1.candidate.priority }
    }

    /// Finds a CNAME target for `name` within this message's answers, if any.
    func cnameTarget(for name0: String) -> String? {
        let name = name0.trimmingCharacters(in: .whitespaces).lowercased()
        for r in answers where r.type == NCDNSMessage.typeCNAME {
            let rname = r.name.trimmingCharacters(in: .whitespaces).lowercased()
            if rname == name || rname == name + "." {
                return r.cnameTarget
            }
        }
        return nil
    }
}
