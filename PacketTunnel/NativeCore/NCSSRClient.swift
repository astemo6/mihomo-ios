import Foundation
import Network

/// ShadowsocksR stream: protocol framing → stream cipher (per-connection
/// IV prefix) → optional obfs wrapping, over a raw NCStream. Mirrors
/// mihomo's composition obfs(cipher(protocol)) with the write order
/// app → protocol → cipher → obfs.
final class NCSSRRelayStream: NCRelayStream {
    var onData: ((Data) -> Void)?
    var onClose: ((Error?) -> Void)?

    private let raw: NCStream
    private let encryptor: NCSSStreamCipher
    private let decryptor: NCSSStreamCipher
    private let clientIV: Data
    private var ivSent = false
    private var ivReceived = false
    private var ivBuffer = Data()
    private let proto: NCSSRAuthSHA1V4?
    private let obfs: NCSSRHTTPSimple?
    private var closed = false

    init(raw: NCStream, method: String, key: Data, clientIV: Data,
         proto: NCSSRAuthSHA1V4?, obfs: NCSSRHTTPSimple?) {
        self.raw = raw
        self.clientIV = clientIV
        encryptor = NCSSStreamCipher(method: method, key: key)!
        encryptor.forEncryption = true
        encryptor.setIV(clientIV)
        decryptor = NCSSStreamCipher(method: method, key: key)!
        decryptor.forEncryption = false
        self.proto = proto
        self.obfs = obfs
        raw.onData = { [weak self] in self?.handle($0) }
        raw.onClose = { [weak self] error in
            guard let self, !closed else { return }
            closed = true
            onClose?(error)
        }
    }

    func send(_ data: Data) {
        let framed = proto?.encode(data) ?? data
        var out = Data()
        if !ivSent {
            out.append(clientIV)
            ivSent = true
        }
        out.append(encryptor.process(framed))
        raw.send(obfs?.encode(out) ?? out)
    }

    private func handle(_ data: Data) {
        var chunk = data
        if let obfs {
            guard let stripped = obfs.decode(chunk) else { return }
            chunk = stripped
        }
        if !ivReceived {
            ivBuffer.append(chunk)
            guard ivBuffer.count >= decryptor.ivSize else { return }
            let iv = Data(ivBuffer.prefix(decryptor.ivSize))
            chunk = Data(ivBuffer.dropFirst(decryptor.ivSize))
            ivBuffer = Data()
            decryptor.setIV(iv)
            ivReceived = true
        }
        let plain = decryptor.process(chunk)
        if let proto {
            do {
                let decoded = try proto.decode(plain)
                if !decoded.isEmpty { onData?(decoded) }
            } catch {
                cancel()
                onClose?(error)
            }
        } else if !plain.isEmpty {
            onData?(plain)
        }
    }

    func cancel() {
        closed = true
        raw.cancel()
    }
}
