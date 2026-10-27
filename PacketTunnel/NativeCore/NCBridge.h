/* Bridging header for the PacketTunnel target: exposes the vendored lwIP
   bridge (lwip/nc_stack.h) to the native core's Swift glue. */
#ifndef NC_BRIDGE_H
#define NC_BRIDGE_H
#include "nc_stack.h"
#include "nc_wg.h" /* feat/nc-wg: WireGuard netifs */
#include <arpa/inet.h> /* feat/nc-lua: inet_pton/inet_ntop for the Lua network module */
#include "Lua/nc_lua_bridge.h" /* feat/nc-lua: vendored Lua 5.4 bridge (NCLuaEngine) */
#endif
