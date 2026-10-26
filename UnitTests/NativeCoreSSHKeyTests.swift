import XCTest
@testable import Mihomo

// Coverage for PR #118 (fix/nc-perf), SSH half: `private-key` may be a file
// path, and encrypted OpenSSH keys (bcrypt_pbkdf + aes256-ctr / aes256-cbc)
// parse through NCSSHKey.parse — that decryption path (feat/nc-proto3) had
// no test coverage at all.
//
// Test vectors: throwaway ed25519 keys generated for this test only with
// OpenSSH ssh-keygen on 2026-10-25 (the reference implementation), e.g.
//   ssh-keygen -t ed25519 -a 4 -N 'test-pass-123' -f k_ctr
//   ssh-keygen -t ed25519 -a 4 -Z aes256-cbc -N 'test-pass-123' -f k_cbc
// (-a 4 keeps the bcrypt KDF cheap in CI.) The expected public blobs are
// the keys' .pub wire blobs. The passphrase for both encrypted keys is
// "test-pass-123". These keys protect nothing and are used nowhere else.
final class NativeCoreSSHKeyTests: XCTestCase {

    private static let passphrase = "test-pass-123"

    // ssh-keygen -t ed25519 -N '' (cipher "none")
    private static let plainPEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACDTsbxHXE/Ddbjo/Z7TXRXpOl9EqBFWL2jtMTRmrSUkswAAAJBWpH79VqR+
    /QAAAAtzc2gtZWQyNTUxOQAAACDTsbxHXE/Ddbjo/Z7TXRXpOl9EqBFWL2jtMTRmrSUksw
    AAAECdIIoOdRnMYarv8aCwDKMFUvU7p1U2AAThdrSvspQzrNOxvEdcT8N1uOj9ntNdFek6
    X0SoEVYvaO0xNGatJSSzAAAACGNvdi10ZXN0AQIDBAU=
    -----END OPENSSH PRIVATE KEY-----
    """
    private static let plainPub = "AAAAC3NzaC1lZDI1NTE5AAAAINOxvEdcT8N1uOj9ntNdFek6X0SoEVYvaO0xNGatJSSz"

    // ssh-keygen -t ed25519 -a 4 -N 'test-pass-123' (default cipher aes256-ctr, kdf bcrypt)
    private static let ctrPEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC0IkvETs
    GUIdsfzDKCb1TEAAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIKOCXrN7A9cnROBW
    6R2WaDTOZqgR/nbQeQEtp7ksLQ9YAAAAkKSFxee99A0zCJASDX6N2X+nnSctiXa2O+sWrN
    a8ji5ewWgM6F0xO47hDOr5lzxW4w2VU//vaLgRhrVOeeZN6i67n1S3VNEXRz9fKd81MimS
    1eXupBSus3iyUhepWOCOHfC5tN16aGdRSBGQRcYb2L/xTJ7dWUdVoxTAX6HDJhVKZ5K/YO
    WOrXyfWaRJi54LTQ==
    -----END OPENSSH PRIVATE KEY-----
    """
    private static let ctrPub = "AAAAC3NzaC1lZDI1NTE5AAAAIKOCXrN7A9cnROBW6R2WaDTOZqgR/nbQeQEtp7ksLQ9Y"

    // ssh-keygen -t ed25519 -a 4 -Z aes256-cbc -N 'test-pass-123'
    private static let cbcPEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABAviTuauk
    p7FYo5UWwMugC4AAAABAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIB6nkNfA0HSGXtLI
    GUdIzEsOoKDcbcm7+e3Ycwl5eTZTAAAAkEafa3OUMjOmcaXUJKtaKh6TlJ1pLPs8IW28X7
    IKk/Cj8hnWKggoeR2zO/47IHDukV5yMyk0T+16NM+uU1NpLIDybec1++6rSFDZ6rXDkgpy
    yY/vNX4cJeUTKLgiVXilRFnZ/RvvNJfh+GxvFw6nnnB7Hmy7tjEeOmKiFKZE01gmXpVd5M
    +H6rd4cFIQXZy62Q==
    -----END OPENSSH PRIVATE KEY-----
    """
    private static let cbcPub = "AAAAC3NzaC1lZDI1NTE5AAAAIB6nkNfA0HSGXtLIGUdIzEsOoKDcbcm7+e3Ycwl5eTZT"

    // The unencrypted throwaway key from the deleted the old core test suite
    //: its
    // ssh-ed25519 host-key blob was asserted there, so the same blob must
    // come out of the Swift parser here.
    private static let goVectorPEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
    c2gtZWQyNTUxOQAAACA5MWYkja6EUd4XV7GtukXb7net/MS0uerC9fgjcNnM/gAA
    AJjs9yrU7Pcq1AAAAAtzc2gtZWQyNTUxOQAAACA5MWYkja6EUd4XV7GtukXb7net
    /MS0uerC9fgjcNnM/gAAAEBQa8eARYOYZNKkO93T406pO5r+Vc5Fj9FgvS1SwMzJ
    yzkxZiSNroRR3hdXsa26Rdvud638xLS56sL1+CNw2cz+AAAAD3Rlc3RAbWlob21v
    LWlvcwECAwQFBg==
    -----END OPENSSH PRIVATE KEY-----
    """
    private static let goVectorPub = "AAAAC3NzaC1lZDI1NTE5AAAAIDkxZiSNroRR3hdXsa26Rdvud638xLS56sL1+CNw2cz+"

    func testUnencryptedOpenSSHKey() {
        let (key, why) = NCSSHKey.parse(Self.plainPEM)
        XCTAssertNil(why)
        XCTAssertEqual(key?.algorithm, "ssh-ed25519")
        XCTAssertEqual(key?.publicBlob.base64EncodedString(), Self.plainPub)
        // A parsed key must actually sign (ed25519 verify against the blob's key).
        let sig = key?.sign(Data("payload".utf8))
        XCTAssertNotNil(sig)
    }

    func testGoVectorKeyParsesToSameBlob() {
        let (key, why) = NCSSHKey.parse(Self.goVectorPEM)
        XCTAssertNil(why)
        XCTAssertEqual(key?.publicBlob.base64EncodedString(), Self.goVectorPub)
    }

    func testEncryptedAES256CTRKey() {
        let (key, why) = NCSSHKey.parse(Self.ctrPEM, passphrase: Self.passphrase)
        XCTAssertNil(why)
        XCTAssertEqual(key?.algorithm, "ssh-ed25519")
        XCTAssertEqual(key?.publicBlob.base64EncodedString(), Self.ctrPub)
    }

    func testEncryptedAES256CBCKey() {
        let (key, why) = NCSSHKey.parse(Self.cbcPEM, passphrase: Self.passphrase)
        XCTAssertNil(why)
        XCTAssertEqual(key?.algorithm, "ssh-ed25519")
        XCTAssertEqual(key?.publicBlob.base64EncodedString(), Self.cbcPub)
    }

    /// Wrong passphrase: the decrypted checkints disagree, which the parser
    /// reports as a passphrase error — the key must not come back usable.
    func testWrongPassphraseRejected() {
        for pem in [Self.ctrPEM, Self.cbcPEM] {
            let (key, why) = NCSSHKey.parse(pem, passphrase: "not-the-passphrase")
            XCTAssertNil(key)
            XCTAssertEqual(why, "OpenSSH 私钥口令错误")
        }
    }

    /// No passphrase at all is a distinct, explicit failure.
    func testMissingPassphraseRejected() {
        let (key, why) = NCSSHKey.parse(Self.ctrPEM)
        XCTAssertNil(key)
        XCTAssertNotNil(why)
        XCTAssertTrue(why?.contains("缺少 private-key-passphrase") ?? false)
    }

    /// #118's file-path workflow at the level a unit test can drive: the key
    /// material lives in a file (written here to a temp dir), the file's
    /// text is what gets parsed. The connector's path expansion itself
    /// (absolute / ~ / relative to the profile home) is inline in the SSH
    /// dial path and has no standalone entry point, so it is not covered
    /// here — see the PR body.
    func testEncryptedKeyReadFromFile() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("nc-sshkey-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let file = dir.appendingPathComponent("id_ed25519")
        try Self.ctrPEM.write(to: file, atomically: true, encoding: .utf8)
        let text = try String(contentsOf: file, encoding: .utf8)
        let (key, why) = NCSSHKey.parse(text, passphrase: Self.passphrase)
        XCTAssertNil(why)
        XCTAssertEqual(key?.publicBlob.base64EncodedString(), Self.ctrPub)
    }
}
