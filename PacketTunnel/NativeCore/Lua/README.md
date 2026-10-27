# Vendored Lua 5.4.6 C Core for NativeCore (iOS NetworkExtension)

- **Upstream Version**: Lua 5.4.6 (`https://www.lua.org/ftp/lua-5.4.6.tar.gz`)
- **License**: MIT License (see `LICENSE`)
- **Trimmed Configuration**:
  - Excluded CLI tools: `lua.c`, `luac.c`
  - Excluded unneeded/sandbox-violating standard libraries:
    - `liolib.c` (stdio/file handles)
    - `loadlib.c` (dynamic library loading `package.loadlib` / dlopen)
    - `ldblib.c` (debug library)
    - `loslib.c` (replaced by sandboxed `lnc_oslib.c` providing only `os.clock()`, `os.time()`, `os.difftime()`)
  - Included Core Interpreter & VM:
    `lapi.c`, `lcode.c`, `lctype.c`, `ldebug.c`, `ldo.c`, `ldump.c`, `lfunc.c`, `lgc.c`, `llex.c`, `lmem.c`, `lobject.c`, `lopcodes.c`, `lparser.c`, `lstate.c`, `lstring.c`, `ltable.c`, `ltm.c`, `lundump.c`, `lvm.c`, `lzio.c`, `lauxlib.c`
  - Included Sandbox-Safe Libraries:
    `lbaselib.c`, `lcorolib.c`, `lmathlib.c`, `lstrlib.c`, `ltablib.c`, `lutf8lib.c`
  - Tailored init & os stubs:
    `linit.c` (loads only safe libraries), `lnc_oslib.c`
  - Bridge & Memory Governor:
    `nc_lua_bridge.h`, `nc_lua_bridge.c` (custom tracked allocator `nc_lua_alloc` with a 2 MB hard ceiling,
    execution-deadline hook checked every 65536 instructions — the Lua counterpart of the JSC engine's
    `JSContextGroupSetExecutionTimeLimit` — and helper functions).
