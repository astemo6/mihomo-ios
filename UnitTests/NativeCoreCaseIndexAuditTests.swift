import XCTest
@testable import Mihomo

/// fix/nc-callsite-audit (task 1): regression guards for the case-transform
/// index audit. The build-372 crash came from slicing an original string
/// with indices taken from a lowercased() copy (folding changes character
/// counts: İ → i̇, ß → ss). The full-repo audit found no remaining site of
/// that shape; the sites below are the verified same-source ones (indices
/// are produced from, and applied to, the transformed copy itself, or a
/// constant-count cut of the original whose prefix was matched on ASCII).
/// These tests pin their behaviour with fold-expanding and non-ASCII
/// inputs so a future refactor into the crash shape fails loudly.
final class NativeCoreCaseIndexAuditTests: XCTestCase {

    // NCVLESS.uuidBytes: hex is the lowercased copy, indexed within itself.
    func testUUIDBytesMixedCase() {
        let lower = NCVLESS.uuidBytes("b831381d-6324-4d53-ad4f-8cda48b30811")
        let upper = NCVLESS.uuidBytes("B831381D-6324-4D53-AD4F-8CDA48B30811")
        XCTAssertNotNil(lower)
        XCTAssertEqual(lower, upper)
        XCTAssertEqual(upper?.count, 16)
        XCTAssertNil(NCVLESS.uuidBytes("\u{130}831381d-6324-4d53-ad4f-8cda48b30811"))
    }

    // NCDNSPolicy policy keys: the kind prefix is matched on a lowercased
    // copy, the argument is cut from the ORIGINAL string by constant count
    // (geosite:/rule-set:) or by the original's own index (regexp:). The
    // argument must keep its original characters — slicing the copy would
    // turn ß into ss and İ into i̇.
    func testDNSPolicyKeyArgsKeepOriginalCharacters() {
        var dns = NCDNSModel()
        dns.domainServers = [
            (key: "Geosite:ßKÖLN🎉", servers: [NCDNSServerRef.parse("tls://1.1.1.1")]),
            (key: "RULE-SET:İstanbul", servers: [NCDNSServerRef.parse("tls://1.1.1.1")]),
        ]
        let p = NCDNSPolicy(model: dns, hosts: [])
        let args = p.matcherKeyArgs
        XCTAssertTrue(args.contains { $0.kind == .geosite && $0.arg == "ßKÖLN🎉" },
                      "geosite arg must come from the original string, got \(args)")
        XCTAssertTrue(args.contains { $0.kind == .ruleSet && $0.arg == "İstanbul" },
                      "rule-set arg must come from the original string, got \(args)")
    }

    // NCMitmConfig.matches: host and patterns are lowercased copies that are
    // only compared / prefix-cut within themselves ("-" exclusion marker).
    // İ is written as an escape: U+0130 lowercases to i + U+0307 (one
    // Character, two scalars) — the fold-expansion case from the crash.
    func testMitmHostMatchingFoldChars() {
        var m = NCMitmConfig()
        m.enabled = true
        m.hostnames = ["-*.\u{130}STANBUL.example", "*.ß.example", "Emoji🎉.Example"]
        XCTAssertFalse(m.matches(host: "www.i\u{307}stanbul.example"))
        XCTAssertTrue(m.matches(host: "www.ß.example"))
        XCTAssertTrue(m.matches(host: "WWW.ß.EXAMPLE"))
        XCTAssertTrue(m.matches(host: "emoji🎉.example"))
        XCTAssertFalse(m.matches(host: "unrelated.example"))
    }

    // SettingsSearch.normalize / textRange: folding + Hant→Hans transforms
    // feed comparisons and ranges measured on the searched string itself.
    func testSettingsSearchFoldChars() {
        // normalize folds with .diacriticInsensitive, so İ's combining dot (U+0307) is dropped:
        // İ, i̇ and i all normalize to plain "i" (a search for "istanbul" finds "İstanbul").
        // The old expectation "i\u{307}" was lowercased() semantics, not this normalizer's.
        XCTAssertEqual(SettingsSearchIndex.normalize("\u{130}"), "i")
        XCTAssertEqual(SettingsSearchIndex.normalize("i\u{307}"), "i")
        XCTAssertEqual(SettingsSearchIndex.normalize("ß"), "ss")
        XCTAssertFalse(SettingsSearchIndex.normalize("  🎉 A ").isEmpty)
        // ß case-folds to "ss": a two-letter query matches the one Character.
        XCTAssertEqual(SettingsSearchIndex.textRange(of: "SS", in: "aßb"), 1..<2)
        XCTAssertEqual(SettingsSearchIndex.textRange(of: "🎉", in: "ab🎉cd"), 2..<3)
    }

    // IPInfoFetcher.splitASOrg: the AS number is uppercased as a copy and cut by
    // constant count within itself; the org part is cut from the original
    // by the original's own space index.
    func testSplitASOrgMixedCaseAndNonASCII() {
        let (asn, org) = IPInfoFetcher.splitASOrg("as13335 例子🎉, Inc.")
        XCTAssertEqual(asn, "AS13335")
        XCTAssertEqual(org, "例子🎉, Inc.")
        let (asn2, org2) = IPInfoFetcher.splitASOrg("AS64500 İstanbul Telekom")
        XCTAssertEqual(asn2, "AS64500")
        XCTAssertEqual(org2, "İstanbul Telekom")
    }

    // RejectClassifier.normalise: the normalised copy is what dstPorts
    // searches and slices (same string), including ß→SS length changes.
    func testRejectClassifierNormaliseFoldChars() {
        XCTAssertEqual(RejectClassifier.normalise("dst-port, 443"), "DSTPORT,443")
        XCTAssertEqual(RejectClassifier.normalise("ß (DST-PORT,80-90)"), "SS(DSTPORT,80-90)")
    }
}
