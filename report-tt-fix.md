# TrustTunnel loopback fix report (PR #161 follow-up, 2026-11-03)

Failing run: proto-loopback 40397791692 — H2 echo stalled at exactly
1000/8192 bytes; H3 connect never completed (30 s timeout, no error).
iOS build was green; the auth-failure test passed (CONNECT + Basic auth +
200 all work on H2).

## Ground truth established locally (endpoint is NOT the problem)
Ran the official trusttunnel_endpoint v1.1.0 (linux x86_64) locally with
the loopback config (127.0.0.1:18013, same credentials) plus the repo's
echo server, and drove it with two independent clients:
- python-h2: CONNECT + 8192 bytes → **8192 echoed in one DATA frame**.
- A hand-rolled raw-frame client mimicking NCH2MuxCore exactly (preface +
  **empty SETTINGS**, literal HPACK CONNECT, one 8192 DATA frame,
  connection WINDOW_UPDATE on receipt): **8192 echoed in one DATA frame**.
Endpoint SETTINGS measured: MAX_CONCURRENT_STREAMS=1000,
INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384,
MAX_HEADER_LIST_SIZE=65536.

## H3 root causes (three, all in NCTrustTunnelSession.swift)
1. **No H3 control stream / SETTINGS.** The session reported ready as
   soon as the QUIC group was up and streams sent HEADERS immediately.
   RFC 9114 §6.2 requires the client's control stream (type 0x00) with
   its SETTINGS first; h3 servers wait for it before processing
   requests — the connect hung with no error. Fix (mirroring the proven
   NCMASQUESession pattern): on group .ready, extract a unidirectional
   stream via NCQUICStreamOptions.unidirectional (group-derived options),
   send stream-type 0x00 + SETTINGS (QPACK_MAX_TABLE_CAPACITY=0,
   QPACK_BLOCKED_STREAMS=0, ENABLE_CONNECT_PROTOCOL=1), and only then
   complete start. Server-initiated uni streams are accepted and drained
   via group.newConnectionHandler. A 15 s start deadline now converts
   any future stall into an explicit error.
2. **Data plane had no H3 framing.** Stream `send` wrote raw bytes and
   the receive path delivered raw bytes; H3 requires DATA frames both
   ways. Outbound payloads (including the pre-open outbox flush) are now
   wrapped in DATA frames (type 0x00 + varint length); inbound bytes run
   through a frame parser that delivers DATA payloads and skips other
   frames, buffering partial frames across receives.
3. Group teardown now also cancels the control connection and drained
   server streams.

## H2 status
Frame-level, the client design is proven correct against the real
endpoint (raw-frame replica above); the mux core also audits clean
(SETTINGS ACK, connection window returned on receipt, stream window on
consumption). The remaining suspect is the session pump: it read via
`NWConnection.receive` directly and re-armed only while `isAlive`,
whereas every working mux session in this codebase (NCMuxSession) pumps
through `NCStream.receive` and re-arms after every batch until teardown.
The pump now mirrors NCMuxSession exactly. A new unit test
(testMuxCoreResponseWholeAndFragmented) feeds the measured endpoint
response stream (SETTINGS/WINDOW_UPDATE/HEADERS/DATA 8192) whole,
in 1000-byte fragments, and byte-by-byte, asserting the core delivers
all 8192 bytes — so a red loopback after this change isolates the glue,
and a green one closes the issue.

## Verification
CI: ios.yml full (unit tests) + proto-loopback on the pushed head —
links appended to PR #161.
