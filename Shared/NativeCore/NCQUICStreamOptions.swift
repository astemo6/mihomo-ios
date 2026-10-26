import Foundation
import Network
import Security

// MARK: - Experimental System ECH Helper

/// Experimental Security framework C API binding for `sec_protocol_options_set_enable_encrypted_client_hello`.
///
/// In the public Apple SDK headers (SecProtocolOptions.h), this experimental function is annotated with
/// `API_UNAVAILABLE(macos, ios, watchos, tvos)`, which causes Swift compiler errors on iOS targets if referenced
/// statically. However, the symbol is implemented and exported by the Security / Network runtime on modern Darwin
/// systems (iOS 14+ / macOS 11+).
///
/// We resolve the symbol dynamically via `dlsym(RTLD_DEFAULT, ...)` so that:
/// 1. The Swift codebase compiles cleanly on all iOS target SDKs without compiler availability errors;
/// 2. If the runtime exports the symbol, system ECH is enabled on the given sec_protocol_options_t;
/// 3. If the runtime lacks the symbol, it safely no-ops ("能开则开、开不了就标注").
private let secProtocolOptionsSetEnableECHSymbol: (@convention(c) (sec_protocol_options_t, Bool) -> Void)? = {
    guard let sym = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "sec_protocol_options_set_enable_encrypted_client_hello") else {
        return nil
    }
    return unsafeBitCast(sym, to: (@convention(c) (sec_protocol_options_t, Bool) -> Void).self)
}()

func sec_protocol_options_set_enable_encrypted_client_hello(_ options: sec_protocol_options_t, _ enable: Bool) {
    if let fn = secProtocolOptionsSetEnableECHSymbol {
        fn(options, enable)
    }
}

/// Per-stream QUIC options for `NWConnectionGroup.extract(connectionTo:using:)` on a
/// multiplex (QUIC) group.
///
/// A stream extracted from the group is a *cloned* flow: Network.framework joins each
/// protocol in the new flow's stack to the matching protocol instance of the group's
/// established QUIC connection. A freshly built `NWProtocolQUIC.Options` — even one with
/// the same ALPN / SNI / TLS min version / verify block as the group's — does not match
/// that instance, so the clone fails before any packet is sent:
///
///     nw_endpoint_flow_setup_cloned_protocols [C3 127.0.0.1:18006 …] could not find
///         protocol to join in existing protocol stack
///     nw_endpoint_flow_failed_with_error … failed to clone from flow, moving directly
///         to failed state
///
/// and the stream reports `.failed(POSIXErrorCode.ENETDOWN)` ("Network is down"). That
/// was the proto-loopback failure of testHysteria2TCPEcho / testTUICTCPEcho (run
/// 40187510708): the group handshake to sing-box had succeeded, only the first
/// per-stream-options extract (hy2's unidirectional H3 control stream, TUIC's
/// unidirectional auth stream) died. Bidi streams extracted with `using: nil` inherit the
/// group's own options and always worked.
///
/// Fix: derive per-stream options from the group's OWN QUIC options (the group
/// parameters' transport protocol) and flip only the per-stream knobs (direction,
/// datagram). The parameters are deep-copied first so the flip never touches the group's
/// live options — a later `extract(using: nil)` must still get a bidirectional stream.
///
/// In addition, because the group parameters already carry the securityProtocolOptions
/// configured by the dialer (e.g. ALPN, TLS 1.3 min version, and the experimental system
/// ECH switch `sec_protocol_options_set_enable_encrypted_client_hello`), both `derived`
/// and the callers' `fallback` closures retain the exact same security/ECH options.
enum NCQUICStreamOptions {

    /// The group's QUIC options, deep-copied, with `configure` applied (direction /
    /// isDatagram). nil only if the group's stack has no QUIC transport, which cannot
    /// happen for a group built with `NWParameters(quic:)`; callers fall back to their
    /// freshly built options then.
    static func derived(from group: NWConnectionGroup,
                        _ configure: (NWProtocolQUIC.Options) -> Void) -> NWProtocolQUIC.Options? {
        let params = group.parameters.copy()
        guard let quic = params.defaultProtocolStack.transportProtocol as? NWProtocolQUIC.Options else {
            return nil
        }
        configure(quic)
        return quic
    }

    /// A client-initiated unidirectional stream on `group`.
    static func unidirectional(from group: NWConnectionGroup,
                               fallback: () -> NWProtocolQUIC.Options) -> NWProtocolQUIC.Options {
        if let o = derived(from: group, { $0.direction = .unidirectional }) { return o }
        let o = fallback()
        o.direction = .unidirectional
        return o
    }

    /// The RFC 9221 datagram flow of `group`.
    static func datagram(from group: NWConnectionGroup,
                         fallback: () -> NWProtocolQUIC.Options) -> NWProtocolQUIC.Options {
        if let o = derived(from: group, { $0.isDatagram = true }) { return o }
        let o = fallback()
        o.isDatagram = true
        return o
    }
}
