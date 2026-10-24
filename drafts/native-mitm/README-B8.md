# B8 draft — HTTP/1.1 parsing & upstream (Swift, native MitM lane)

Status: draft written by Muse (astemo6's agent) in parallel with B4, before
`feat/native-mitm` lands. Files live here until the branch + B6 interfaces
exist; then they move to `PacketTunnel/NativeMitM/HTTP*.swift` /
`Upstream*.swift` per TODO.md's file ownership.

## What's here

| File | Contents |
|---|---|
| `HTTPMessage.swift` | `HTTPHeaders` (ordered, case-insensitive), request/response head types + serializers, incremental head parser (64 KB cap, obs-fold rejected), body framing decision (`HTTPBodyFraming`), incremental chunked decoder + encoder |
| `HeaderRewrite.swift` | The op vocabulary Go hands down (`set` / `add` / `remove`), CR/LF validation, hop-by-hop stripping incl. `Connection`-nominated fields |
| `Upstream.swift` | `UpstreamConnection` seam + `NWConnection` implementation that streams bytes to/from the Go relay |

Design rules kept from the Go path: fail closed on malformed input (typed
errors, no repair attempts), never fold duplicate headers, re-frame bodies
instead of trusting relayed `Content-Length` / `Transfer-Encoding`.

## How a connection flows (intended)

1. B7 terminates client TLS, yielding a clear byte stream + the ALPN result.
2. This layer parses the request head, asks Go (B6 flow API) for the verdict:
   passthrough-relay, script via body channel, or reject.
3. Head (+ header ops) is serialized to the relay in absolute-form; the body
   streams through the body channel (B1 store) so scripts see the same bytes
   on the native and Go paths.
4. Response head is parsed (interim 1xx emitted and skipped), framing
   decided against the request method, body streamed back; the client side
   is re-framed (chunked or content-length) at serialization time.

## OPEN — must align with B6 before integration

1. **Relay protocol**: draft assumes one NWConnection per intercepted
   connection and HTTP/1.1 absolute-form into `bridge/mitm/relay.go`.
   Confirm: keep-alive/pooling semantics, and whether the relay wants a
   preamble (host/flow id) instead of absolute-form.
2. **Verdict channel**: how Go returns per-flow decisions + header ops +
   body-channel blob ids to Swift (the `__tern`-style host bridge used by
   JSCScriptEngine is the obvious precedent).
3. **Body handoff**: at which byte threshold a body stops streaming through
   and is fully materialized in the NativeBodyStore for scripts — the 0.19.22
   Go semantics (admission queue, dynamic budget, big-body serialization)
   are the reference; the Swift side must match outcomes, not internals.
4. **Failure reporting**: parse/framing failures and upstream errors must
   reach Go's circuit breaker (per-host fallback to the Go path). Channel
   TBD with B6/B3.
5. **Obs-text header values**: the draft head parser decodes lossily, so a
   header value with non-UTF-8 bytes is not byte-faithful across a
   parse → serialize round trip (Go keeps raw bytes). Decide with B6:
   byte-level parser (values as `Data`) before launch, or a documented
   per-host fallback list. Not a silent difference — flagged in
   `HTTPMessage.swift` at the `lines` helper.

## B9 boundary notes (for the B9 pass)

- **WebSocket / protocol upgrades**: a `101` response ends HTTP semantics.
  After the upgrade the connection is an opaque byte relay — no body
  channel, no further parsing. `Upgrade` on a request whose response is not
  101 is stripped per hop-by-hop rules.
- **h2-only clients (gRPC etc.)**: decided at ALPN in B7 — if the client
  offers only `h2`, the flow stays on the Go path untouched; this layer
  never sees it. `h2c` upgrade attempts over cleartext are not a tunnel
  case (origins are reached via the core) and are treated as malformed.
- **CONNECT**: the tunnel's clients speak proxy-style CONNECT to the core,
  not to this layer; a CONNECT reaching this parser is a configuration
  error → fail closed.
- **Expect: 100-continue**: relay the interim response promptly; do not
  wait for the body before forwarding the request head upstream.
- **Network switch mid-body**: NWConnection fails → report upstream error,
  drop the flow (fail closed, no resume); Go's breaker hears about it via
  the failure channel (OPEN #4). This matches the Go path's behavior —
  a switched network restarts connections, it never migrates them.
- **No-body responses**: HEAD / 204 / 304 / 1xx framing is handled in
  `HTTPBodyFraming.forResponse`; a `Content-Length` on a 304 is metadata,
  not a body — do not wait for bytes that will never come.

## Not verifiable in this environment

No Xcode here: the Swift is written against public Foundation/Network API
surface only, but it has not been compiled. First compile happens when the
files move into the project on `feat/native-mitm`; expect small type fixes,
not design changes.
