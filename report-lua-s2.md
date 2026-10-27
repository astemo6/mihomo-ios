# Lua S2 Report — Custom Backend Engine (feat/nc-lua)

Date: 2026-10-27. Baseline: feat/nc-integrate @ 6fd4bab. S1 verdict: ACCEPTABLE
(docs/nc-proto-lua.md §1–§7). S2 stage 1 (44c4533) vendored the trimmed Lua
5.4.6 core + C bridge. This report covers S2 stage 2: the execution layer.

## Delivered

1. **C bridge completion** (`PacketTunnel/NativeCore/Lua/nc_lua_bridge.{h,c}`):
   closure/upvalue helpers, registry-held per-connection ctx table,
   nested-table registration and typed field setters; `nc_lua_push_bytes`
   now pushes "" for zero-length data instead of nil.
2. **Target wiring**: `NCBridge.h` (tunnel) includes the Lua bridge +
   <arpa/inet.h>; new `App/NCLuaBridge.h` + project.yml App-target
   `SWIFT_OBJC_BRIDGING_HEADER` / `HEADER_SEARCH_PATHS` so App Swift and
   UnitTests can call the bridge (the S2-permitted project.yml exception).
3. **Engine** (`Shared/NativeCore/NCLuaEngine.swift`): per-connection
   `lua_State`, tracked allocator (2 MB hard cap), execution deadline per
   callback; host modules `backend`, `crypto`, `network`, `http`; global
   `settings` table from node fields.
4. **Ciphers** (`Shared/NativeCore/NCLuaCipher.swift`): AES-CFB/CFB8
   (one-shot ECB blocks, chunk-safe state), RC4, RC4-MD5, ChaCha20
   (pure Swift, both nonce layouts), AES-GCM and ChaCha20-Poly1305
   (CryptoKit AEAD; update buffers, final seals/opens; wire = ct‖tag).
5. **Session** (`Shared/NativeCore/NCLuaSession.swift`): the wa_lua_on_*
   state machine over the raw stream (flags → handshake rounds fed by
   on_read, 64-round + 15 s caps → data transforms → close). Script source:
   inline `script` field, else basename-only lookup in the app-group
   container's `LuaScripts/`; missing source is an explicit dial failure.
6. **Live status flip**: `NCConnector` case `lua`; `NCSupport.types` gains
   `lua` (source-less nodes report "Lua 后端缺少脚本 (file/script)");
   Clash/Shadowrocket/QuanX importers no longer stamp nodes
   `lua-status: pending_s2`. HTTP-layer Lua script rules are stamped
   `unsupported` — that layer is JSC's (docs §8.4).
7. **Tests**: `NativeCoreLuaTests` — S1 import tests updated to the live
   status; engine tests for callbacks/host modules, error isolation,
   deadline kill of an infinite loop, 2 MB allocation-bomb cap,
   AES-256-CFB and AEAD behavior driven through Lua itself, unsupported
   cipher → nil, network module, RC4 RFC 6229 vector, ChaCha20 chunking,
   AES-GCM round trip; plus an end-to-end `NCLuaSession` test over an
   in-memory transport (XOR backend: HE/HO handshake + transform echo).
   Loopback: `tools/loopback/lua-mock-server.py` (:18016, XOR decoding
   relay to the echo backend) wired into `start-servers.sh`, and
   `NativeCoreLoopbackTests.testLuaCustomBackendEcho` (8192-byte payload).

## Measured (local, 2026-10-27)
- Vendored C core compiles clean with gcc (default std, -Os): 30/30 TUs.
- Source: 776,544 bytes (excl. LICENSE/README), 58 files, 26,429 lines.
- Static archive .text: 162,362 bytes on **x86_64** (reference only;
  arm64 figure = CI IPA size report).

## Known risks / notes
- The Swift code was written against the Lua 5.4.6 headers as vendored;
  macro-only API (`lua_tostring`, `lua_pop`, `lua_pushcfunction`, …) is
  deliberately avoided or wrapped in the C bridge. CI is the first full
  Xcode compile of this code.
- `backend.write` during the data phase sends immediately (DIRECT_WRITE);
  scripts that need store-and-forward should return data from on_write.
- AEAD ciphers are single-message per object (nonce = construction IV);
  multi-message AEAD protocols need one cipher object per message, which
  the script controls.

## CI (final head, 2026-10-27)
- ios.yml build_only: **SUCCESS** —
  https://github.com/astemo6/mihomo-ios/actions/runs/40433908129
- ios.yml full (build + all unit tests, incl. NativeCoreLuaTests and the
  in-memory NCLuaSession end-to-end test): **SUCCESS** —
  https://github.com/astemo6/mihomo-ios/actions/runs/40428220950
- proto-loopback (13 tests, incl. testLuaCustomBackendEcho over real TCP
  against the XOR mock peer): **SUCCESS** —
  https://github.com/astemo6/mihomo-ios/actions/runs/40432893089

### Failure history during bring-up (all fixed on this branch)
1. `NCQXImport.quantumultX` typo in the S1-era QX test (the real entry
   point is `quantumultx`); S1 never compiled its tests under CI, so it
   surfaced only at S2's first build-for-testing.
2. `testLuaCustomBackendEcho` connect hang: `NCLuaSession` was retained
   by nothing during its async handshake (receive handler and timeout
   capture it weakly), so it deallocated mid-handshake over real
   transports — no stream, no error, not even the 15 s timeout. The
   session now retains itself until the connect outcome is delivered.
   The in-memory unit test could not see this (synchronous delivery
   completed the handshake before the session could deallocate).
