/* Bridging header for the App target: exposes the vendored Lua 5.4 bridge
   (PacketTunnel/NativeCore/Lua, compiled into the app so the unit tests can
   drive NCLuaEngine in-process) to the shared NativeCore Swift glue. The
   tunnel target reaches the same header through NCBridge.h. */
#ifndef NC_LUA_APP_BRIDGE_H
#define NC_LUA_APP_BRIDGE_H
#include <arpa/inet.h>
#include "nc_lua_bridge.h"
#endif
