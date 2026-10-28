import XCTest
import CryptoKit
@testable import Tern

/// fix/nc-sudoku-interop: byte-exact vectors for the Sudoku data plane. Table / codec / legacy PRNG / Ed25519
/// vectors were produced by the reference server's code (SUDOKU-ASCII/sudoku v0.5.2, its own pkg/obfs/sudoku
/// functions); key-schedule and record vectors by an independent reference client that completed echo
/// round trips against the official v0.5.2.0 server binary.
final class NativeCoreSudokuWireTests: XCTestCase {

    private static let splitKey = "e2eac3d4c0036ceb028048417bf2bf7c213681e145603c38ec8bffadb2e40c014130de746760b7dc9b515545f47e29df255687fe3ee972c2c517264f6a37b60b"
    private static let masterPub = "3388f6b59b225f4e41cd14f445b73b6568711ce536832217b15649253612451d"

    private static func hex(_ s: String) -> Data { Data(NCSudokuEd25519.hexBytes(s) ?? []) }
    private static func hexString<S: Sequence>(_ d: S) -> String where S.Element == UInt8 {
        d.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: Legacy PRNG (additive lagged Fibonacci)

    func testLaggedFibRandMatchesReference() {
        let vectors: [(Int64, [Int64], UInt32)] = [
            (1, [5577006791947779410, 8674665223082153551, 6129484611666145821], 1879968118),
            (0, [8717895732742165505, 2259404117704393152, 6050128673802995827], 233405013),
            (-7, [747107023976529931, 7084732931963018726, 6995717851144434728], 379331713),
            (0x0123456789abcdef, [4303309306080173548, 738694355209974960, 1239204929968885730], 757257611),
        ]
        for (seed, int63s, u32) in vectors {
            var r = NCLaggedFibRand(seed: seed)
            XCTAssertEqual([r.int63(), r.int63(), r.int63()], int63s, "seed \(seed)")
            XCTAssertEqual(r.uint32(), u32, "seed \(seed)")
        }
        XCTAssertEqual(NCLaggedFibSeedTable.values.count, 607)
    }

    // MARK: Tables

    func testGridEnumerationAndShuffleMatchReference() {
        let grids = NCSudokuGrids.all()
        XCTAssertEqual(grids.count, 288)
        XCTAssertEqual(grids[0], [1, 2, 3, 4, 3, 4, 1, 2, 2, 1, 4, 3, 4, 3, 2, 1])
        XCTAssertEqual(NCSudokuGrids.hintPositions.count, 1820)
        XCTAssertEqual(NCSudokuGrids.permutations.count, 24)

        // Seed = int64(BE(SHA-256("sudoku")[0..8])) = 0xee0440321a0e5aa7.
        XCTAssertEqual(NCSudokuKeys.tableSeed("sudoku"), -1295840208846169433)
        let core = NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("sudoku"))
        XCTAssertEqual((0..<16).map { core.cell(byte: 0, pos: $0) }, [3, 2, 4, 1, 4, 1, 2, 3, 2, 3, 1, 4, 1, 4, 3, 2])
        XCTAssertEqual((0..<16).map { core.cell(byte: 1, pos: $0) }, [3, 4, 2, 1, 2, 1, 4, 3, 4, 3, 1, 2, 1, 2, 3, 4])
        XCTAssertEqual((0..<16).map { core.cell(byte: 255, pos: $0) }, [3, 1, 2, 4, 4, 2, 1, 3, 2, 3, 4, 1, 1, 4, 3, 2])
        XCTAssertEqual(core.puzzlePositions.count, 22676)
        XCTAssertEqual(core.puzzleStart[1], 128)
        XCTAssertEqual(core.puzzleStart[256], 22676)
    }

    /// Every puzzle of every byte, as wire bytes in the reference order, hashes to the reference table's digest.
    func testPuzzleTablesMatchReferenceForEveryLayout() {
        let core = NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("sudoku"))
        let cases: [(NCSudokuLayout, String, String)] = [
            (.entropy(), "92f32cd16d8ae772d2d56ab35ef1395475822dd33601bd198234f7a0a2e95e63", "80108111821283138414851586168717"),
            (NCSudokuLayout.custom("xpxvvpvv")!, "64bcd8c7ffc389879eeadf21ea7d64d92fb12146766cf952a1508ec21b4813f1",
             "2f373b3d3e3f676b6d6e6f73757677797a7b7c7d7e7f8f979b9d9e9fc7cbcdcecfd3d5d6d7d9dadbdcdddedf"),
            (.ascii(), "da968043dcd4efd1cc59dc4ac59c113dee118d793f77efe235df78a8a343743d",
             "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        ]
        let hp = NCSudokuGrids.hintPositions
        for (layout, digest, pool) in cases {
            var all = [UInt8]()
            all.reserveCapacity(22676 * 4)
            for b in 0..<256 {
                for k in Int(core.puzzleStart[b])..<Int(core.puzzleStart[b + 1]) {
                    let packed = hp[Int(core.puzzlePositions[k])]
                    for i in 0..<4 {
                        let pos = Int(packed >> UInt16(4 * i)) & 15
                        all.append(layout.hintByte(val: core.cell(byte: b, pos: pos) - 1, pos: pos))
                    }
                }
            }
            XCTAssertEqual(Self.hexString(SHA256.hash(data: Data(all))), digest, layout.name)
            XCTAssertEqual(Self.hexString(layout.paddingPool), pool, layout.name)
        }
    }

    func testTableHintMatchesReference() {
        XCTAssertEqual(NCSudokuKeys.tableHint(psk: "sudoku", mode: "prefer_entropy", uplinkPattern: "", downlinkPattern: ""), 0xc7a4871c)
        XCTAssertEqual(NCSudokuKeys.tableHint(psk: "sudoku", mode: "prefer_entropy", uplinkPattern: "xpxvvpvv",
                                              downlinkPattern: "xpxvvpvv"), 0x3f9bdece)
        XCTAssertEqual(NCSudokuKeys.tableHint(psk: "sudoku", mode: "prefer_ascii", uplinkPattern: "", downlinkPattern: ""), 0x37be4ec4)
    }

    // MARK: Decoding reference-encoded wire bytes (with the server's padding)

    /// `msg` encoded by the reference sudoku.Conn / PackedConn with padding 30–60 %, key "sudoku".
    private static let goWire: [(kind: String, layout: NCSudokuLayout, msg: String, wire: String)] = [
        ("classic", .entropy(), "68656c6c6f207375646f6b75200001feff",
         "142e0546692d85054b8563832c04426a1586266085480e6081064d4b0c1363112a4514228668824b01810a144010292e85054c266f256e01142312624429160f17680723401113482a63016205282f84498024226f816f1027416925476a110b"),
        ("packed", .entropy(), "68656c6c6f207375646f6b75200001feff6162",
         "132a1106254c132b828206126c40862c6786812510442b1066154d65821208101100848600016f824f836c80838315281426088015"),
        ("classic", NCSudokuLayout.custom("xpxvvpvv")!, "68656c6c6f207375646f6b75200001feff",
         "d3e0a32fb4f57bf3a4f59ba26df6e2bc9fa8ef37a5f0baf9d7e47caadee2ec97bd7ab3e2cedbeaa1bf79f4b5e6b2e06bddf2d3a96dbde6d3f3fee4dbbccbe6f9bbcda4b273b5ffe09de73ef0a1b63de6b4b8bfcfe57afadcbd6bb2fff5a4ea3bfa73adebb8"),
        ("packed", NCSudokuLayout.custom("xpxvvpvv")!, "68656c6c6f207375646f6b75200001feff6162",
         "7bb67faa3badf8d5b76daa776bfcdfe07fd6bc8fefdc8faddfe86f8fb7758fee97f96fedd5b0a07fcedca09ea1ffcdfbfc2fdf75dd77b4ae6db02f"),
        ("classic", .ascii(), "68656c6c6f207375646f6b75200001feff",
         "7966582157736148275a322562447a5c2e3f4e655c2b77283d482262224655305d4b6226743b59413a667e363078603266325e2f0a48503567287e2b5a34642879467c506a4c6b533d7820735d4b37654a33456e31582a4c71522e0a336b36455d270a6e3c4c552b74"),
        ("packed", .ascii(), "68656c6c6f207375646f6b75200001feff6162",
         "305a2146556c385b3a3946237c37603d2c5c77262f55643c5b30763b6d753d33482a402b363e4041260a216f7c3f3458562f33483f3a"),
    ]

    func testDecodesReferenceEncodedWireAcrossArbitraryReadBoundaries() throws {
        let core = NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("sudoku"))
        for v in Self.goWire {
            let table = NCSudokuTable(core: core, layout: v.layout)
            let wire = Self.hex(v.wire)
            for step in [1, 3, 5, 7, wire.count] {
                let dec: NCSudokuStreamDecoder = v.kind == "classic" ? NCSudokuClassicDecoder(table: table)
                                                                     : NCSudokuPackedDecoder(layout: v.layout)
                var out = Data()
                var off = 0
                while off < wire.count {
                    let end = min(off + step, wire.count)
                    out.append(try dec.feed(wire.subdata(in: off..<end)))
                    off = end
                }
                XCTAssertEqual(Self.hexString(out), v.msg, "\(v.kind) \(v.layout.name) step \(step)")
            }
        }
    }

    func testClassicDecoderWithForeignTable() throws {
        // Puzzle validity does not depend on the key, the byte <-> grid assignment does: another key's table turns
        // the reference vector into different bytes, and a longer stream soon hits one of the 32 grids that carry no byte.
        let other = NCSudokuTable(core: NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("not-sudoku")), layout: .entropy())
        let wire = Self.hex(Self.goWire[0].wire)
        if let out = try? NCSudokuClassicDecoder(table: other).feed(wire) {
            XCTAssertNotEqual(Self.hexString(out), Self.goWire[0].msg)
        }
        let mine = NCSudokuTable(core: NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("sudoku")), layout: .entropy())
        let long = NCSudokuEncoder(table: mine, paddingMin: 0, paddingMax: 0).encode(Data((0..<512).map { UInt8($0 & 0xff) }))
        XCTAssertThrowsError(try NCSudokuClassicDecoder(table: other).feed(long))
    }

    // MARK: Encoder

    func testEncoderRoundTripsWithPaddingInEveryLayout() throws {
        let core = NCSudokuTableCore(seed: NCSudokuKeys.tableSeed(Self.masterPub))
        let msg = Data((0..<4096).map { UInt8(($0 * 13 + 5) & 0xff) }) + Data(0...255)
        for layout in [NCSudokuLayout.entropy(), .ascii(), NCSudokuLayout.custom("vpvxpvxv")!] {
            let table = NCSudokuTable(core: core, layout: layout)
            for (lo, hi) in [(0, 0), (10, 30), (100, 100)] {
                let enc = NCSudokuEncoder(table: table, paddingMin: lo, paddingMax: hi)
                let wire = enc.encode(msg)
                if hi == 0 { XCTAssertEqual(wire.count, msg.count * 4, layout.name) }
                if lo == 100 { XCTAssertEqual(wire.count, msg.count * 9 + 1, layout.name) }
                XCTAssertEqual(try NCSudokuClassicDecoder(table: table).feed(wire), msg, "\(layout.name) \(lo)-\(hi)")
                if layout.name == "ascii" {
                    XCTAssertTrue(wire.allSatisfy { ($0 >= 0x20 && $0 < 0x7F) || $0 == 0x0A }, "ascii stays printable")
                }
            }
        }
    }

    func testEncoderVariesPuzzlesAndHintOrder() {
        let table = NCSudokuTable(core: NCSudokuTableCore(seed: NCSudokuKeys.tableSeed("sudoku")), layout: .entropy())
        let enc = NCSudokuEncoder(table: table, paddingMin: 0, paddingMax: 0)
        var seen = Set<Data>()
        for _ in 0..<64 { seen.insert(enc.encode(Data([0x41]))) }
        XCTAssertGreaterThan(seen.count, 16, "the same byte must not always look the same on the wire")
    }

    // MARK: Keys

    func testEd25519KeyNormalisationMatchesReference() {
        // Pairs from `sudoku -keygen` (official v0.5.2) and the loopback key pair.
        XCTAssertEqual(NCSudokuEd25519.recoverPublicKeyHex(Self.splitKey), Self.masterPub)
        XCTAssertEqual(NCSudokuEd25519.recoverPublicKeyHex(
            "c3e5c442140b0ff58ec491dfa567d3d047bb4af0a31c739f4ce426c6cb609c069ce58822c8ce485951716735c1926af71efefc7aef740ad3afeca569de61f206"),
            "f9633ba5070e016df5b283efa41862f957966b9b0ad1100155c37dd80423ae2f")
        XCTAssertEqual(NCSudokuEd25519.recoverPublicKeyHex("5fcb4d65dcd9574ee035f91467fa3dc866b9476b93917d72fcd0cc2faac28e0d"),
                       "f9633ba5070e016df5b283efa41862f957966b9b0ad1100155c37dd80423ae2f")
        // A public key is not a canonical scalar here, a passphrase is not hex: both are used as given.
        XCTAssertNil(NCSudokuEd25519.recoverPublicKeyHex(Self.masterPub))
        XCTAssertNil(NCSudokuEd25519.recoverPublicKeyHex("hunter2"))
        XCTAssertNil(NCSudokuEd25519.recoverPublicKeyHex(String(repeating: "f", count: 64)))
    }

    func testKeyScheduleVectors() {
        let norm = NCSudokuKeys.normalize(Self.splitKey)
        XCTAssertEqual(norm.psk, Self.masterPub)
        XCTAssertEqual(Self.hexString(norm.userHash), "5254fd3ed5acedc6") // the official server logs [User:5254fd3ed5acedc6]
        let pass = NCSudokuKeys.normalize("  hunter2 ")
        XCTAssertEqual(pass.psk, "  hunter2 ")
        XCTAssertEqual(Self.hexString(pass.userHash), "f52fbd32b2b3b86f") // SHA-256 of the trimmed key

        let psk = NCSudokuKeys.pskBases(Self.masterPub)
        XCTAssertEqual(Self.hexString(psk.c2s), "e74a53384286e6adaa428ba4aa7f5793828cff33caa4306bfb6508dd82858c92")
        XCTAssertEqual(Self.hexString(psk.s2c), "2f6058e7dea32d15c757d1e4544f3845980b5dc32f3b922f569bc4929d903575")
        let session = NCSudokuKeys.sessionBases(psk: Self.masterPub, shared: Data(0..<32), nonce: Data(0..<16))
        XCTAssertEqual(Self.hexString(session.c2s), "3602dd1147ddda05f98fda841e556a675267d8e33d5eaf20600a0b02ba34c834")
        XCTAssertEqual(Self.hexString(session.s2c), "064009d4b643523eb5e41b72a85a9a70499da07ab7628fa60856860d9ec2900f")
        XCTAssertEqual(Self.hexString(NCSudokuKeys.epochKey(base: psk.c2s, epoch: 7, method: "chacha20-poly1305")),
                       "dbc9f327e32ab8d9717649651510237c3662be8ca85ebb0ab77fa19425ecc848")
    }

    // MARK: Records

    func testRecordLayerOpensReferenceRecords() throws {
        let psk = NCSudokuKeys.pskBases(Self.masterPub)
        // epoch 1, seq 2, "hello sudoku", sealed with the c2s handshake base.
        let chacha = NCSudokuRecordLayer(method: .chacha20Poly1305, send: psk.s2c, recv: psk.c2s)
        chacha.append(Self.hex("0028000000010000000000000002388e79d9a92ade62bb4a64871c61693f63984ec8588421c27461edab"))
        XCTAssertEqual(try chacha.nextRecord(), Data("hello sudoku".utf8))
        XCTAssertNil(try chacha.nextRecord())
        let aes = NCSudokuRecordLayer(method: .aes128GCM, send: psk.s2c, recv: psk.c2s)
        aes.append(Self.hex("001f01020304112233445566778836837813547cea17ce6a9de82157f2aa37b0be"))
        XCTAssertEqual(try aes.nextRecord(), Data("aes".utf8))
    }

    func testRecordLayerRoundTripRekeyReplayAndTamper() throws {
        for method in [NCSudoku.AEADMethod.chacha20Poly1305, .aes128GCM] {
            let psk = NCSudokuKeys.pskBases("k")
            let client = NCSudokuRecordLayer(method: method, send: psk.c2s, recv: psk.s2c)
            let server = NCSudokuRecordLayer(method: method, send: psk.s2c, recv: psk.c2s)
            let big = Data((0..<150_000).map { UInt8($0 & 0xff) })
            let wire = try client.seal(big) // three records (64 KiB body limit)
            XCTAssertEqual(wire.count, big.count + 3 * (2 + 12 + 16))
            server.append(wire.prefix(1000))
            XCTAssertEqual(try server.drain(), Data())
            server.append(wire.dropFirst(1000))
            XCTAssertEqual(try server.drain(), big)

            // Rekey both sides; the old record replayed now fails, fresh ones pass.
            let s = NCSudokuKeys.sessionBases(psk: "k", shared: Data(count: 32), nonce: Data(count: 16))
            client.rekey(send: s.c2s, recv: s.s2c)
            server.rekey(send: s.s2c, recv: s.c2s)
            let r1 = try client.seal(Data("one".utf8))
            server.append(r1)
            XCTAssertEqual(try server.drain(), Data("one".utf8))
            server.append(r1) // same epoch + seq again
            XCTAssertThrowsError(try server.drain())

            let fresh = NCSudokuRecordLayer(method: method, send: s.s2c, recv: s.c2s)
            var tampered = try client.seal(Data("two".utf8))
            tampered[tampered.count - 1] ^= 1
            fresh.append(tampered)
            XCTAssertThrowsError(try fresh.drain())
        }
    }

    func testRecordLayerEpochRotation() throws {
        let saved = NCSudokuRecordLayer.keyUpdateAfterBytes
        NCSudokuRecordLayer.keyUpdateAfterBytes = 1000
        defer { NCSudokuRecordLayer.keyUpdateAfterBytes = saved }
        let psk = NCSudokuKeys.pskBases("rot")
        let a = NCSudokuRecordLayer(method: .chacha20Poly1305, send: psk.c2s, recv: psk.s2c)
        let b = NCSudokuRecordLayer(method: .chacha20Poly1305, send: psk.s2c, recv: psk.c2s)
        var epochs = Set<Data>()
        for i in 0..<12 {
            let w = try a.seal(Data(repeating: UInt8(i), count: 400))
            epochs.insert(w.subdata(in: 2..<6))
            b.append(w)
            XCTAssertEqual(try b.drain(), Data(repeating: UInt8(i), count: 400))
        }
        XCTAssertGreaterThanOrEqual(epochs.count, 4, "a new epoch (fresh key, random seq) every 1000 plaintext bytes")
    }

    func testRecordLayerNoneIsRawPassthrough() throws {
        let r = NCSudokuRecordLayer(method: .none, send: Data(), recv: Data())
        XCTAssertEqual(try r.seal(Data("abc".utf8)), Data("abc".utf8))
        r.append(Data("xyz".utf8))
        XCTAssertEqual(try r.nextRecord(), Data("xyz".utf8))
        XCTAssertNil(try r.nextRecord())
    }

    // MARK: KIP

    func testClientHelloServerHelloOpenTCPLayout() throws {
        let p = NCSudokuKIP.clientHelloPayload(timestamp: 0x0102030405060708, userHash: Self.hex("5254fd3ed5acedc6"),
                                               nonce: Data(repeating: 0xAA, count: 16), clientPub: Data(repeating: 0xBB, count: 32))
        XCTAssertEqual(p.count, 68)
        XCTAssertEqual(Self.hexString(p.prefix(16)), "01020304050607085254fd3ed5acedc6")
        XCTAssertEqual(Self.hexString(p.suffix(4)), "0000001f")
        let hinted = NCSudokuKIP.clientHelloPayload(timestamp: 1, userHash: Data(count: 8), nonce: Data(count: 16),
                                                    clientPub: Data(count: 32), tableHint: 0x3f9bdece)
        XCTAssertEqual(Self.hexString(hinted.suffix(8)), "0000001f3f9bdece")
        let msg = NCSudokuKIP.buildMessage(type: .clientHello, payload: p)
        XCTAssertEqual(Self.hexString(msg.prefix(6)), "6b6970010044")

        let nonce = Data(repeating: 0x11, count: 16)
        let sh = nonce + Data(repeating: 0x22, count: 32) + Data([0, 0, 0, 0x1f])
        let parsed = try NCSudokuKIP.parseServerHello(payload: sh, expectedNonce: nonce)
        XCTAssertEqual(parsed.serverPub, Data(repeating: 0x22, count: 32))
        XCTAssertEqual(parsed.features, 0x1f)
        XCTAssertThrowsError(try NCSudokuKIP.parseServerHello(payload: sh, expectedNonce: Data(count: 16)))
        XCTAssertThrowsError(try NCSudokuKIP.parseServerHello(payload: sh + Data([0]), expectedNonce: nonce))

        XCTAssertEqual(Self.hexString(try XCTUnwrap(NCSudokuKIP.openTCP(target: NCTarget(host: "127.0.0.1", port: 18080)))),
                       "6b6970100007017f00000146a0")
        XCTAssertEqual(Self.hexString(try XCTUnwrap(NCSudokuKIP.openTCP(target: NCTarget(host: "a.io", port: 443)))),
                       "6b6970100008030461" + "2e696f01bb")
        let un = try XCTUnwrap(try NCSudokuKIP.unwrapMessage(from: msg + Data([1, 2])))
        XCTAssertEqual(un.type, 0x01)
        XCTAssertEqual(un.consumed, msg.count)
        XCTAssertNil(try NCSudokuKIP.unwrapMessage(from: msg.prefix(10)))
        XCTAssertThrowsError(try NCSudokuKIP.unwrapMessage(from: Data("GET / HTTP".utf8)))
    }

    func testLegacyHTTPMaskHead() {
        let head = String(decoding: NCSudokuHTTPMask.legacyRequest(host: "1.2.3.4:443", pathRoot: "/aabb/"), as: UTF8.self)
        XCTAssertTrue(head.hasPrefix("POST /aabb/"))
        XCTAssertTrue(head.contains("\r\nHost: 1.2.3.4:443\r\n"))
        XCTAssertTrue(head.hasSuffix("\r\n\r\n"))
    }

    // MARK: Options (Clash field semantics)

    func testOptionsResolveClashFieldsAndDefaults() {
        let base: [String: NCJSONValue] = ["server": .string("1.2.3.4"), "port": .number(443), "key": .string("k")]
        var o = NCSudoku.Options(proxy: NCProxy(name: "a", type: "sudoku", fields: base))
        XCTAssertEqual(o.aead, .chacha20Poly1305)
        XCTAssertEqual(o.mode.canonical, "prefer_entropy")
        XCTAssertEqual([o.paddingMin, o.paddingMax], [10, 30])
        XCTAssertTrue(o.pureDownlink)
        XCTAssertTrue(o.httpMaskEnabled)
        XCTAssertEqual(o.httpMaskMode, "legacy")
        XCTAssertEqual(o.serverHostPort, "1.2.3.4:443")
        XCTAssertNil(o.dataPlaneUnsupported)

        var f = base
        f["aead-method"] = .string("none")
        f["padding-max"] = .number(5) // lone bound drags the other (Clash padding resolution)
        f["http-mask"] = .bool(false)
        f["table-type"] = .string("up_entropy_down_ascii")
        o = NCSudoku.Options(proxy: NCProxy(name: "b", type: "sudoku", fields: f))
        XCTAssertEqual(o.aead, NCSudoku.AEADMethod.none)
        XCTAssertEqual([o.paddingMin, o.paddingMax], [5, 5])
        XCTAssertFalse(o.httpMaskEnabled)
        XCTAssertFalse(o.mode.uplinkASCII)
        XCTAssertTrue(o.mode.downlinkASCII)

        // The official nested block overrides the flat keys.
        f["httpmask"] = .object(["disable": .bool(false), "mode": .string("ws"), "path-root": .string("p")])
        o = NCSudoku.Options(proxy: NCProxy(name: "c", type: "sudoku", fields: f))
        XCTAssertTrue(o.httpMaskEnabled)
        XCTAssertEqual(o.httpMaskMode, "ws")
        XCTAssertEqual(o.pathRoot, "p")
        XCTAssertNotNil(o.dataPlaneUnsupported, "HTTP tunnel modes are explicit markers, not a dial timeout")

        f = base
        f["multiplex"] = .string("on")
        XCTAssertNotNil(NCSudoku.Options(proxy: NCProxy(name: "d", type: "sudoku", fields: f)).dataPlaneUnsupported)
        f["multiplex"] = .string("auto")
        XCTAssertNil(NCSudoku.Options(proxy: NCProxy(name: "e", type: "sudoku", fields: f)).dataPlaneUnsupported)
    }

    func testASCIIModeParsing() {
        XCTAssertEqual(NCSudokuASCIIMode.parse(nil)?.canonical, "prefer_entropy")
        XCTAssertEqual(NCSudokuASCIIMode.parse("ascii")?.canonical, "prefer_ascii")
        XCTAssertEqual(NCSudokuASCIIMode.parse("UP_ASCII_DOWN_ENTROPY")?.canonical, "up_ascii_down_entropy")
        XCTAssertEqual(NCSudokuASCIIMode.parse("up_prefer_entropy_down_prefer_ascii")?.canonical, "up_entropy_down_ascii")
        XCTAssertEqual(NCSudokuASCIIMode.parse("up_ascii_down_ascii")?.canonical, "prefer_ascii")
        XCTAssertNil(NCSudokuASCIIMode.parse("gaussian"))
        XCTAssertNil(NCSudokuASCIIMode.parse("up_ascii"))
    }
}
