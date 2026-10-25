import Foundation

/// ShadowsocksR stream: protocol framing → stream cipher (per-connection
/// IV prefix) → optional obfs wrapping, over the raw relay stream. Mirrors
/// mihomo's composition obfs(cipher(protocol)) with the write order
/// app → protocol → cipher → obfs. Same pull-receive shape as the other
/// relay wrappers (NCSSRelayStream).
final class NCSSRRelayStream: NCRelayStream {
    private let raw: NCRelayStream
    private let encryptor: NCSSStreamCipher
    private let decryptor: NCSSStreamCipher
    private let clientIV: Data
    private var ivSent = false
    private var ivReceived = false
    private var ivBuffer = Data()
    private let proto: NCSSRAuthSHA1V4?
    private let obfs: NCSSRHTTPSimple?

    init(raw: NCRelayStream, method: String, key: Data, clientIV: Data,
         proto: NCSSRAuthSHA1V4?, obfs: NCSSRHTTPSimple?, target: NCTarget) {
        self.raw = raw
        self.clientIV = clientIV
        encryptor = NCSSStreamCipher(method: method, key: key)!
        encryptor.forEncryption = true
        encryptor.setIV(clientIV)
        decryptor = NCSSStreamCipher(method: method, key: key)!
        decryptor.forEncryption = false
        self.proto = proto
        self.obfs = obfs
        // The target head is the first protocol chunk (auth framing picks
        // its auth piece from these bytes, like the reference).
        send(target.atypEncoded)
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

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        raw.receive { [weak self] data, error in
            guard let self else { handler(nil, error); return }
            guard let data else { handler(nil, error); return }
            var chunk = data
            if let obfs {
                guard let stripped = obfs.decode(chunk) else {
                    if obfs.overflowed {
                        self.cancel()
                        handler(nil, NCSSR.error("http_simple: response header too large"))
                        return
                    }
                    self.receive(handler) // header incomplete; pull more
                    return
                }
                chunk = stripped
            }
            if !ivReceived {
                ivBuffer.append(chunk)
                guard ivBuffer.count >= decryptor.ivSize else {
                    self.receive(handler)
                    return
                }
                let iv = Data(ivBuffer.prefix(decryptor.ivSize))
                chunk = Data(ivBuffer.dropFirst(decryptor.ivSize))
                ivBuffer = Data()
                decryptor.setIV(iv)
                ivReceived = true
                if chunk.isEmpty {
                    self.receive(handler)
                    return
                }
            }
            let plain = decryptor.process(chunk)
            if let proto {
                do {
                    let decoded = try proto.decode(plain)
                    if decoded.isEmpty {
                        self.receive(handler)
                    } else {
                        handler(decoded, nil)
                    }
                } catch {
                    self.cancel()
                    handler(nil, error)
                }
            } else if plain.isEmpty {
                self.receive(handler)
            } else {
                handler(plain, nil)
            }
        }
    }

    func cancel() { raw.cancel() }
}
