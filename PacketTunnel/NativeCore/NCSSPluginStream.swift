import Foundation

/// Shadowsocks stream-plugin transport (simple-obfs http/tls, v2ray-plugin
/// websocket). Wraps a connected stream to the SS server so the WHOLE SS
/// byte stream — request head included — rides inside the plugin, matching
/// mihomo's adapter/outbound/shadowsocks.go StreamConnContext, which wraps
/// the raw conn with the plugin before the SS codec sees it. TCP only; SS
/// UDP sessions never go through a plugin (mihomo parity).
///
/// Layering: the pure wire formats live in Shared/NativeCore/NCSSPlugin.swift;
/// this class only drives them over NCRelayStream (obfs rides the raw socket,
/// v2ray-plugin reuses NCWebSocketStream's RFC 6455 frame layer).
final class NCSSPluginStream: NCRelayStream {
    private let raw: NCRelayStream
    private let opts: NCSSPluginOptions
    private let serverPort: String
    private let ws: NCWebSocketStream?

    /// Flips after the first send (obfs disguise / mux create frame go out
    /// with it), like mihomo's firstRequest/firstResponse flags.
    private var started = false

    // Receive-side state, one per plugin shape.
    private var httpStripper = NCSSPlugin.HTTPResponseStripper()
    private var tlsParser = NCSSPlugin.TLSResponseParser()
    private var muxParser = NCSSPlugin.V2RayMux.Parser()

    init(raw: NCRelayStream, options: NCSSPluginOptions, serverPort: String) {
        self.raw = raw
        self.opts = options
        self.serverPort = serverPort
        if case .v2rayPlugin = options.kind {
            var headers = options.headers
            // mihomo v2ray NewV2rayObfs: a Host header overrides the Host
            // used for the upgrade request (and for the TLS server name).
            let hostHeader = headers.removeValue(forKey: "Host") ?? options.host
            self.ws = NCWebSocketStream(raw: raw, hostHeader: hostHeader, path: options.path, headers: headers)
        } else {
            self.ws = nil
        }
    }

    /// v2ray-plugin runs the WebSocket upgrade first; the obfs modes need no
    /// handshake — their disguise rides the first data packet.
    func start(completion: @escaping (Error?) -> Void) {
        if let ws {
            ws.startHandshake { err in completion(err) }
        } else {
            completion(nil)
        }
    }

    func send(_ data: Data) {
        let first = !started
        started = true
        switch opts.kind {
        case .obfs:
            if opts.mode == "http" {
                if first {
                    raw.send(NCSSPlugin.obfsHTTPRequest(host: opts.host, port: serverPort, payload: data))
                } else {
                    raw.send(data)
                }
            } else {
                if first {
                    raw.send(NCSSPlugin.obfsTLSClientHello(host: opts.host, payload: data))
                } else {
                    for record in NCSSPlugin.obfsTLSAppDataRecords(data) {
                        raw.send(record)
                    }
                }
            }
        case .v2rayPlugin:
            guard let ws else { return }
            if opts.mux {
                // mihomo mux.go NewMux pre-fills the create frame; the first
                // Write flushes create + data together.
                if first {
                    ws.send(NCSSPlugin.V2RayMux.createFrame() + NCSSPlugin.V2RayMux.dataFrame(payload: data))
                } else {
                    ws.send(NCSSPlugin.V2RayMux.dataFrame(payload: data))
                }
            } else {
                ws.send(data)
            }
        }
    }

    func receive(_ handler: @escaping (Data?, Error?) -> Void) {
        switch opts.kind {
        case .obfs:
            if opts.mode == "http" {
                raw.receive { [weak self] data, error in
                    guard let self else { handler(nil, error); return }
                    guard let data else { handler(nil, error); return }
                    guard let plain = self.httpStripper.feed(data) else {
                        handler(nil, self.pluginError("obfs http response header"))
                        return
                    }
                    if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
                }
            } else {
                raw.receive { [weak self] data, error in
                    guard let self else { handler(nil, error); return }
                    guard let data else { handler(nil, error); return }
                    guard let plain = self.tlsParser.feed(data) else {
                        handler(nil, self.pluginError("obfs tls response record"))
                        return
                    }
                    if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
                }
            }
        case .v2rayPlugin:
            ws?.receive { [weak self] data, error in
                guard let self else { handler(nil, error); return }
                guard let data else { handler(nil, error); return }
                if !self.opts.mux {
                    handler(data, nil)
                    return
                }
                guard let plain = self.muxParser.feed(data) else {
                    handler(nil, self.pluginError("v2ray-plugin mux frame"))
                    return
                }
                if plain.isEmpty { self.receive(handler) } else { handler(plain, nil) }
            }
        }
    }

    func cancel() {
        // Best-effort mux session end (mihomo Mux.Close), then tear the
        // transport down — NCWebSocketStream.cancel closes the raw stream.
        if case .v2rayPlugin = opts.kind, opts.mux {
            ws?.send(NCSSPlugin.V2RayMux.endFrame())
        }
        if let ws {
            ws.cancel()
        } else {
            raw.cancel()
        }
    }

    private func pluginError(_ what: String) -> Error {
        NSError(domain: "NativeCore", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "shadowsocks plugin decode failed: \(what)"])
    }
}
